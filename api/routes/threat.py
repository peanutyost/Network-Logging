"""Threat hunting and analytics API routes."""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Response, Body
from typing import List, Optional, Any, Dict
from datetime import datetime
import logging
import csv
import io

from api.models import (
    OrphanedIPResponse, 
    DateRangeRequest,
    ThreatFeedResponse,
    ThreatAlertResponse,
    ThreatFeedUpdateRequest,
    ThreatFeedUpdateResponse,
    ThreatWhitelistEntry,
    ThreatWhitelistAddRequest,
    ThreatScanResponse,
    ThreatConfigResponse,
    ThreatConfigUpdateRequest
)
from api.dependencies import get_db
from api.auth import get_current_active_user, require_admin
from database.base import DatabaseBase
from threat_intel import ThreatIntelligenceManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threat", tags=["Threat Hunting"])

@router.get("/orphaned-ips", response_model=List[OrphanedIPResponse])
async def get_orphaned_ips(
    days: int = 7,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Get IPs that have traffic but no DNS entry in the last N days."""
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Days must be between 1 and 365")
    
    results = db.get_orphaned_ips(days=days, start_time=start_time, end_time=end_time)
    return results


@router.get("/feeds", response_model=List[ThreatFeedResponse])
async def get_threat_feeds(
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Get list of threat intelligence feeds."""
    feeds = db.get_threat_feeds()
    return feeds


@router.post("/feeds/{feed_name}/update", response_model=ThreatFeedUpdateResponse)
async def update_threat_feed(
    feed_name: str,
    force: bool = False,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Manually trigger update of a threat intelligence feed.
    
    Args:
        feed_name: Name of the feed to update
        force: If True, bypass the 3-hour minimum update interval (admin only)
    """
    try:
        manager = ThreatIntelligenceManager(db)
        result = manager.update_feed(feed_name, force=force)
        
        # If throttled, return 429 Too Many Requests
        if result.get('throttled'):
            raise HTTPException(
                status_code=429,
                detail=result.get('error', 'Feed update throttled. Minimum 3 hours required between updates.')
            )
        
        return ThreatFeedUpdateResponse(**result)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating threat feed {feed_name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating feed: {str(e)}")


@router.get("/alerts", response_model=List[ThreatAlertResponse])
async def get_threat_alerts(
    limit: int = 100,
    since: Optional[datetime] = None,
    resolved: Optional[bool] = None,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Get threat alerts."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
    
    alerts = db.get_threat_alerts(limit=limit, since=since, resolved=resolved)
    return alerts


@router.get("/alerts/count")
async def get_threat_alerts_count(
    since: Optional[datetime] = None,
    resolved: Optional[bool] = None,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Get total count of threat alerts."""
    count = db.get_threat_alerts_count(since=since, resolved=resolved)
    return {"count": count}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_threat_alert(
    alert_id: int,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Mark a threat alert as resolved."""
    success = db.resolve_threat_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "message": "Alert resolved"}


@router.post("/alerts/resolve-batch")
async def resolve_threat_alerts_batch(
    alert_ids: List[int] = Body(...),
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Resolve multiple threat alerts by their IDs."""
    if not alert_ids:
        raise HTTPException(status_code=400, detail="alert_ids list cannot be empty")
    
    if len(alert_ids) > 1000:
        raise HTTPException(status_code=400, detail="Cannot resolve more than 1000 alerts at once")
    
    resolved_count = db.resolve_threat_alerts_by_ids(alert_ids)
    return {
        "success": True,
        "message": f"Resolved {resolved_count} alert(s)",
        "resolved_count": resolved_count
    }


@router.put("/feeds/{feed_name}/toggle")
async def toggle_threat_feed(
    feed_name: str,
    enabled: bool,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Enable or disable a threat feed."""
    try:
        # Get current feed info
        feeds = db.get_threat_feeds()
        feed_info = next((f for f in feeds if f['feed_name'] == feed_name), None)
        
        if not feed_info:
            raise HTTPException(status_code=404, detail=f"Feed '{feed_name}' not found")
        
        # Update enabled status
        db.update_threat_feed_enabled(feed_name, enabled)
        
        # Also update the in-memory feed object if manager exists
        try:
            manager = ThreatIntelligenceManager(db)
            if feed_name in manager.feeds:
                manager.feeds[feed_name].enabled = enabled
        except:
            pass  # Ignore if manager can't be created
        
        return {"success": True, "feed": feed_name, "enabled": enabled}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling threat feed {feed_name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error toggling feed: {str(e)}")


@router.put("/feeds/{feed_name}/config")
async def update_feed_config(
    feed_name: str,
    config: Dict[str, Any],
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Update feed configuration (e.g., level for ipsum feed)."""
    try:
        # Get current feed info
        feeds = db.get_threat_feeds()
        feed_info = next((f for f in feeds if f['feed_name'] == feed_name), None)
        if not feed_info:
            raise HTTPException(status_code=404, detail=f"Feed '{feed_name}' not found")
        
        # Validate and update config for ipsum feed
        if feed_name.startswith('IPsum-L') and 'level' in config:
            level = config['level']
            if level < 1 or level > 8:
                raise HTTPException(status_code=400, detail="IPsum level must be between 1 and 8")
            
            # Find all existing IPsum feeds (there should only be one, but handle duplicates)
            all_feeds = db.get_threat_feeds()
            ipsum_feeds = [f for f in all_feeds if f['feed_name'].startswith('IPsum-L')]
            
            # Update the feed instance and re-register with new level
            manager = ThreatIntelligenceManager(db)
            
            # Remove all IPsum feed instances from manager
            for ipsum_feed in ipsum_feeds:
                old_name = ipsum_feed['feed_name']
                if old_name in manager.feeds:
                    del manager.feeds[old_name]
            
            # Create new feed instance with updated level
            from threat_intel import IpsumFeed
            new_feed = IpsumFeed(level=level)
            manager.register_feed(new_feed)
            
            # Delete all old IPsum feeds from database (including indicators)
            # This ensures we don't have duplicates when level changes
            for ipsum_feed in ipsum_feeds:
                old_feed_name = ipsum_feed['feed_name']
                # Delete indicators and feed entry
                try:
                    # Try PostgreSQL-style first
                    if hasattr(db, '_get_connection'):
                        conn = db._get_connection()
                        try:
                            with conn.cursor() as cur:
                                cur.execute("DELETE FROM threat_indicators WHERE feed_name = %s", (old_feed_name,))
                                cur.execute("DELETE FROM threat_feeds WHERE feed_name = %s", (old_feed_name,))
                                conn.commit()
                        except Exception as e:
                            conn.rollback()
                            logger.error(f"Error deleting old IPsum feed {old_feed_name}: {e}")
                        finally:
                            db._return_connection(conn)
                    # Try SQLite-style
                    elif hasattr(db, 'conn'):
                        if not db.conn:
                            db.connect()
                        try:
                            cursor = db.conn.cursor()
                            cursor.execute("DELETE FROM threat_indicators WHERE feed_name = ?", (old_feed_name,))
                            cursor.execute("DELETE FROM threat_feeds WHERE feed_name = ?", (old_feed_name,))
                            db.conn.commit()
                        except Exception as e:
                            logger.error(f"Error deleting old IPsum feed {old_feed_name}: {e}")
                    else:
                        logger.warning(f"Unable to delete old IPsum feed {old_feed_name}: unknown database type")
                except Exception as e:
                    logger.error(f"Error deleting old IPsum feed {old_feed_name}: {e}")
            
            # Create the new feed entry with preserved settings from the current feed
            db.update_threat_feed_metadata(
                feed_name=new_feed.name,
                last_update=None,  # Reset update time since level changed
                indicator_count=0,  # Reset count - needs new update
                source_url=new_feed.url,
                enabled=feed_info.get('enabled', True),
                error=None,  # Clear any errors
                homepage=new_feed.homepage,
                config={'level': level}
            )
            
            return {"success": True, "feed_name": new_feed.name, "message": f"IPsum feed updated to level {level}. Please update the feed to download new indicators."}
        
        return {"success": True, "feed_name": feed_name, "message": "Configuration updated"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating feed config: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating feed config: {str(e)}")


@router.get("/whitelist", response_model=List[ThreatWhitelistEntry])
async def get_threat_whitelist(
    limit: int = 100,
    indicator_type: Optional[str] = None,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Get threat whitelist entries."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
    
    if indicator_type and indicator_type not in ['domain', 'ip']:
        raise HTTPException(status_code=400, detail="indicator_type must be 'domain' or 'ip'")

    entries = db.get_threat_whitelist(limit=limit, indicator_type=indicator_type)
    # Convert dict entries to Pydantic models to ensure proper datetime handling
    return [ThreatWhitelistEntry(**entry) for entry in entries]


@router.post("/whitelist", response_model=ThreatWhitelistEntry, status_code=status.HTTP_201_CREATED)
async def add_threat_whitelist(
    request: ThreatWhitelistAddRequest,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Add an indicator to the threat whitelist."""
    if request.indicator_type not in ['domain', 'ip']:
        raise HTTPException(status_code=400, detail="indicator_type must be 'domain' or 'ip'")
    
    if request.indicator_type == 'domain' and not request.domain:
        raise HTTPException(status_code=400, detail="domain is required when indicator_type is 'domain'")
    
    if request.indicator_type == 'ip' and not request.ip:
        raise HTTPException(status_code=400, detail="ip is required when indicator_type is 'ip'")
    
    try:
        whitelist_id = db.add_threat_whitelist(
            indicator_type=request.indicator_type,
            domain=request.domain,
            ip=request.ip,
            reason=request.reason
        )
        
        # Resolve all alerts matching this indicator
        resolved_count = db.resolve_threat_alerts_by_indicator(
            domain=request.domain,
            ip=request.ip
        )
        
        # Get the created entry by querying all entries and finding the one with matching ID
        # We query a reasonable limit to ensure we get the newly created entry
        entries = db.get_threat_whitelist(limit=100)
        entry = next((e for e in entries if e['id'] == whitelist_id), None)
        if entry:
            result = ThreatWhitelistEntry(**entry)
            # Add resolved count to response metadata (if we need to return it)
            # For now, we'll just log it
            if resolved_count > 0:
                logger.info(f"Resolved {resolved_count} threat alerts when adding {request.domain or request.ip} to whitelist")
            return result
        raise HTTPException(status_code=500, detail="Failed to retrieve created whitelist entry")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding threat whitelist entry: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error adding whitelist entry: {str(e)}")


@router.delete("/whitelist/{whitelist_id}")
async def remove_threat_whitelist(
    whitelist_id: int,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Remove an indicator from the threat whitelist."""
    success = db.remove_threat_whitelist(whitelist_id)
    if not success:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")
    return {"success": True, "message": "Whitelist entry removed"}


@router.post("/whitelist/rfc1918")
async def add_rfc1918_whitelist(
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Add RFC 1918 private IP ranges to the threat whitelist.
    
    This adds the following ranges:
    - 10.0.0.0/8 (10.0.0.0 to 10.255.255.255)
    - 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
    - 192.168.0.0/16 (192.168.0.0 to 192.168.255.255)
    - 127.0.0.0/8 (loopback)
    - 169.254.0.0/16 (link-local)
    
    Note: The whitelist check automatically excludes RFC 1918 IPs,
    but this endpoint allows adding them explicitly for management purposes.
    """
    import ipaddress
    
    rfc1918_ranges = [
        ("10.0.0.0/8", "RFC 1918 - Private Class A (10.0.0.0/8)"),
        ("172.16.0.0/12", "RFC 1918 - Private Class B (172.16.0.0/12)"),
        ("192.168.0.0/16", "RFC 1918 - Private Class C (192.168.0.0/16)"),
        ("127.0.0.0/8", "Loopback (127.0.0.0/8)"),
        ("169.254.0.0/16", "Link-local (169.254.0.0/16)"),
    ]
    
    added_count = 0
    skipped_count = 0
    
    for cidr, reason in rfc1918_ranges:
        try:
            # Try to add as a CIDR notation entry
            # For now, we'll add representative entries since exact CIDR matching isn't implemented
            # The automatic check will handle the ranges anyway
            network = ipaddress.ip_network(cidr, strict=False)
            # Add the network address as a marker
            # The automatic is_private check will handle the actual range matching
            try:
                db.add_threat_whitelist(
                    indicator_type='ip',
                    domain=None,
                    ip=str(network.network_address),
                    reason=reason
                )
                added_count += 1
            except ValueError:
                # Entry might already exist
                skipped_count += 1
        except Exception as e:
            logger.warning(f"Error adding RFC 1918 range {cidr}: {e}")
            skipped_count += 1
    
    return {
        "success": True,
        "message": f"RFC 1918 exclusion enabled. Added {added_count} entries, skipped {skipped_count} duplicates.",
        "added": added_count,
        "skipped": skipped_count,
        "note": "Note: RFC 1918 private IPs are automatically excluded from threat alerts regardless of whitelist entries."
    }


@router.get("/whitelist/export")
async def export_whitelist_csv(
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Export threat whitelist entries as CSV."""
    try:
        # Get all whitelist entries (use a large limit to get all)
        entries = db.get_threat_whitelist(limit=10000)
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['id', 'indicator_type', 'domain', 'ip', 'reason', 'created_at'])
        
        # Write rows
        for entry in entries:
            writer.writerow([
                entry.get('id', ''),
                entry.get('indicator_type', ''),
                entry.get('domain', ''),
                entry.get('ip', ''),
                entry.get('reason', ''),
                entry.get('created_at', '')
            ])
        
        # Get CSV content
        csv_content = output.getvalue()
        output.close()
        
        # Return CSV file
        return Response(
            content=csv_content,
            media_type='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename="threat_whitelist_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
            }
        )
    except Exception as e:
        logger.error(f"Error exporting whitelist CSV: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error exporting whitelist: {str(e)}")


@router.post("/whitelist/import")
async def import_whitelist_csv(
    file: UploadFile = File(...),
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Import threat whitelist entries from CSV file.
    
    CSV format should be:
    - Header row: id, indicator_type, domain, ip, reason, created_at
    - Data rows: values for each column
    - The 'id' and 'created_at' columns are optional and will be ignored
    - Required: indicator_type (must be 'domain' or 'ip')
    - Required: either 'domain' or 'ip' based on indicator_type
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV file")
    
    try:
        # Read CSV content
        content = await file.read()
        csv_content = content.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_content))
        
        added_count = 0
        skipped_count = 0
        error_count = 0
        errors = []
        
        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 (header is row 1)
            try:
                indicator_type = row.get('indicator_type', '').strip().lower()
                domain = row.get('domain', '').strip() if row.get('domain') else None
                ip = row.get('ip', '').strip() if row.get('ip') else None
                reason = row.get('reason', '').strip() if row.get('reason') else None
                
                # Validate indicator_type
                if indicator_type not in ['domain', 'ip']:
                    errors.append(f"Row {row_num}: Invalid indicator_type '{indicator_type}' (must be 'domain' or 'ip')")
                    error_count += 1
                    continue
                
                # Validate required fields
                if indicator_type == 'domain' and not domain:
                    errors.append(f"Row {row_num}: domain is required when indicator_type is 'domain'")
                    error_count += 1
                    continue
                
                if indicator_type == 'ip' and not ip:
                    errors.append(f"Row {row_num}: ip is required when indicator_type is 'ip'")
                    error_count += 1
                    continue
                
                # Try to add entry
                try:
                    db.add_threat_whitelist(
                        indicator_type=indicator_type,
                        domain=domain,
                        ip=ip,
                        reason=reason
                    )
                    added_count += 1
                except ValueError:
                    # Entry already exists
                    skipped_count += 1
                except Exception as e:
                    errors.append(f"Row {row_num}: Error adding entry - {str(e)}")
                    error_count += 1
                    
            except Exception as e:
                errors.append(f"Row {row_num}: Error processing row - {str(e)}")
                error_count += 1
        
        return {
            "success": True,
            "message": f"Import completed. Added {added_count} entries, skipped {skipped_count} duplicates, {error_count} errors.",
            "added": added_count,
            "skipped": skipped_count,
            "errors": error_count,
            "error_details": errors[:10]  # Return first 10 errors
        }
        
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")
    except Exception as e:
        logger.error(f"Error importing whitelist CSV: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error importing whitelist: {str(e)}")


@router.post("/scan-historical", response_model=ThreatScanResponse)
async def scan_historical_threats(
    days: int = 30,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Manually trigger a historical threat scan.
    
    Args:
        days: Number of days to look back (default: 30, max: 365)
    """
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Days must be between 1 and 365")
    
    try:
        manager = ThreatIntelligenceManager(db)
        result = manager.scan_historical_dns(days=days)
        
        # Check if the scan itself returned a failure
        if not result.get('success', False):
            error_msg = result.get('error', 'Unknown error during scan')
            logger.error(f"Historical threat scan failed: {error_msg}")
            raise HTTPException(status_code=500, detail=error_msg)
        
        return ThreatScanResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning historical threats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error scanning historical threats: {str(e)}")


@router.get("/config", response_model=ThreatConfigResponse)
async def get_threat_config(
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Get threat detection configuration."""
    from config import config
    lookback_days = db.get_setting('threat_lookback_days', config.threat_lookback_days)
    if lookback_days is None:
        lookback_days = config.threat_lookback_days
    return ThreatConfigResponse(lookback_days=int(lookback_days))


@router.put("/config", response_model=ThreatConfigResponse)
async def update_threat_config(
    request: ThreatConfigUpdateRequest,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Update threat detection configuration."""
    db.set_setting('threat_lookback_days', request.lookback_days)
    return ThreatConfigResponse(lookback_days=request.lookback_days)


@router.post("/feeds/custom/add")
async def add_custom_indicator(
    feed_name: str = Body(...),
    indicator_type: str = Body(...),
    domain: Optional[str] = Body(None),
    ip: Optional[str] = Body(None),
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Add a domain or IP to a custom threat feed."""
    if indicator_type not in ['domain', 'ip']:
        raise HTTPException(status_code=400, detail="indicator_type must be 'domain' or 'ip'")
    
    if indicator_type == 'domain' and not domain:
        raise HTTPException(status_code=400, detail="domain is required when indicator_type is 'domain'")
    
    if indicator_type == 'ip' and not ip:
        raise HTTPException(status_code=400, detail="ip is required when indicator_type is 'ip'")
    
    # Ensure custom feed exists
    feeds = db.get_threat_feeds()
    feed_exists = any(f['feed_name'] == feed_name for f in feeds)
    
    if not feed_exists:
        # Create the custom feed if it doesn't exist
        db.update_threat_feed_metadata(
            feed_name=feed_name,
            last_update=datetime.utcnow(),
            indicator_count=0,
            source_url='custom',
            enabled=True,
            error=None,
            homepage=None,
            config=None
        )
    
    try:
        indicator_id = db.add_custom_threat_indicator(
            feed_name=feed_name,
            indicator_type=indicator_type,
            domain=domain,
            ip=ip
        )
        return {
            "success": True,
            "indicator_id": indicator_id,
            "message": f"Added {indicator_type} '{domain or ip}' to custom feed '{feed_name}'"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding custom indicator: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error adding indicator: {str(e)}")


@router.delete("/feeds/custom/remove")
async def remove_custom_indicator(
    feed_name: str,
    indicator_type: str,
    domain: Optional[str] = None,
    ip: Optional[str] = None,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Remove a domain or IP from a custom threat feed."""
    if indicator_type not in ['domain', 'ip']:
        raise HTTPException(status_code=400, detail="indicator_type must be 'domain' or 'ip'")
    
    if indicator_type == 'domain' and not domain:
        raise HTTPException(status_code=400, detail="domain is required when indicator_type is 'domain'")
    
    if indicator_type == 'ip' and not ip:
        raise HTTPException(status_code=400, detail="ip is required when indicator_type is 'ip'")
    
    try:
        removed = db.remove_custom_threat_indicator(
            feed_name=feed_name,
            indicator_type=indicator_type,
            domain=domain,
            ip=ip
        )
        if not removed:
            raise HTTPException(status_code=404, detail="Indicator not found")
        return {
            "success": True,
            "message": f"Removed {indicator_type} '{domain or ip}' from custom feed '{feed_name}'"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error removing custom indicator: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error removing indicator: {str(e)}")


@router.get("/feeds/custom/{feed_name}/indicators")
async def get_custom_feed_indicators(
    feed_name: str,
    limit: int = 1000,
    offset: int = 0,
    db: DatabaseBase = Depends(get_db),
    current_user: dict = Depends(get_current_active_user)
):
    """Get indicators from a custom feed."""
    if limit < 1 or limit > 10000:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 10000")
    if offset < 0:
        raise HTTPException(status_code=400, detail="Offset must be >= 0")
    
    try:
        indicators = db.get_custom_feed_indicators(feed_name, limit=limit, offset=offset)
        return {"indicators": indicators, "count": len(indicators)}
    except Exception as e:
        logger.error(f"Error getting custom feed indicators for {feed_name}: {e}", exc_info=True)
        # Return empty list if feed doesn't exist or has no indicators
        return {"indicators": [], "count": 0}