"""Threat hunting and analytics API routes."""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional, Any, Dict
from datetime import datetime
import logging

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
            
            # Update the feed instance and re-register with new level
            manager = ThreatIntelligenceManager(db)
            # Remove old feed instance if it exists
            old_feed_name = feed_name
            if old_feed_name in manager.feeds:
                del manager.feeds[old_feed_name]
            
            # Create new feed instance with updated level
            from threat_intel import IpsumFeed
            new_feed = IpsumFeed(level=level)
            manager.register_feed(new_feed)
            
            # Update database metadata with new feed name
            db.update_threat_feed_metadata(
                feed_name=new_feed.name,
                last_update=feed_info.get('last_update'),
                indicator_count=feed_info.get('indicator_count', 0),
                source_url=new_feed.url,
                enabled=feed_info.get('enabled', True),
                error=feed_info.get('last_error'),
                homepage=new_feed.homepage,
                config={'level': level}
            )
            
            # Note: When level changes, feed name changes (IPsum-L1 -> IPsum-L2)
            # Old indicators and alerts remain associated with old feed name
        
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
    return entries


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
        # Get the created entry
        entries = db.get_threat_whitelist(limit=1)
        entry = next((e for e in entries if e['id'] == whitelist_id), None)
        if entry:
            return ThreatWhitelistEntry(**entry)
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

