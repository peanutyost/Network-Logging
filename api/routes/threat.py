"""Threat hunting and analytics API routes."""
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime

from api.models import OrphanedIPResponse, DateRangeRequest
from api.dependencies import get_db
from database.base import DatabaseBase

router = APIRouter(prefix="/api/threat", tags=["Threat Hunting"])


@router.get("/orphaned-ips", response_model=List[OrphanedIPResponse])
async def get_orphaned_ips(
    days: int = 7,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: DatabaseBase = Depends(get_db)
):
    """Get IPs that have traffic but no DNS entry in the last N days."""
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Days must be between 1 and 365")
    
    results = db.get_orphaned_ips(days=days, start_time=start_time, end_time=end_time)
    return results

