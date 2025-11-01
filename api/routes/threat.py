"""Threat hunting and analytics API routes."""
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime
import logging

from api.models import (
    OrphanedIPResponse, 
    DateRangeRequest,
    ThreatFeedResponse,
    ThreatAlertResponse,
    ThreatFeedUpdateRequest,
    ThreatFeedUpdateResponse
)
from api.dependencies import get_db, get_current_user, require_admin
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
    current_user = Depends(get_current_user)
):
    """Get IPs that have traffic but no DNS entry in the last N days."""
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Days must be between 1 and 365")
    
    results = db.get_orphaned_ips(days=days, start_time=start_time, end_time=end_time)
    return results


@router.get("/feeds", response_model=List[ThreatFeedResponse])
async def get_threat_feeds(
    db: DatabaseBase = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get list of threat intelligence feeds."""
    feeds = db.get_threat_feeds()
    return feeds


@router.post("/feeds/{feed_name}/update", response_model=ThreatFeedUpdateResponse)
async def update_threat_feed(
    feed_name: str,
    db: DatabaseBase = Depends(get_db),
    current_user = Depends(require_admin)
):
    """Manually trigger update of a threat intelligence feed."""
    try:
        manager = ThreatIntelligenceManager(db)
        result = manager.update_feed(feed_name)
        return ThreatFeedUpdateResponse(**result)
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
    current_user = Depends(get_current_user)
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
    current_user = Depends(get_current_user)
):
    """Mark a threat alert as resolved."""
    success = db.resolve_threat_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "message": "Alert resolved"}

