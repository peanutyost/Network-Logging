"""Traffic-related API routes."""
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime

from api.models import (
    TrafficFlowResponse,
    DateRangeRequest,
    TrafficVolumeDataPoint
)
from api.dependencies import get_db
from database.base import DatabaseBase

router = APIRouter(prefix="/api/traffic", tags=["Traffic"])


@router.get("/domain/{domain}", response_model=List[TrafficFlowResponse])
async def get_traffic_by_domain(
    domain: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: DatabaseBase = Depends(get_db)
):
    """Get all traffic flows for a specific domain."""
    results = db.get_traffic_by_domain(domain, start_time, end_time)
    return results


@router.get("/domain/{domain}/volume", response_model=List[TrafficVolumeDataPoint])
async def get_traffic_volume_by_domain(
    domain: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: DatabaseBase = Depends(get_db)
):
    """Get traffic volume over time for a domain."""
    # This would aggregate traffic by time intervals
    # For now, return individual flow data
    flows = db.get_traffic_by_domain(domain, start_time, end_time)
    
    # Group by timestamp intervals (e.g., hourly)
    # Simplified version - in production, use proper time series aggregation
    result = []
    for flow in flows:
        result.append({
            "timestamp": flow.get("last_update"),
            "bytes_sent": flow.get("bytes_sent", 0),
            "bytes_received": flow.get("bytes_received", 0),
            "total_bytes": flow.get("bytes_sent", 0) + flow.get("bytes_received", 0)
        })
    
    return result


@router.get("/top-domains", response_model=List[dict])
async def get_top_domains(
    limit: int = 10,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: DatabaseBase = Depends(get_db)
):
    """Get top domains by traffic volume."""
    results = db.get_top_domains(limit=limit, start_time=start_time, end_time=end_time)
    return results

