"""Dashboard API routes."""
from fastapi import APIRouter, Depends
from api.models import DashboardStatsResponse
from api.dependencies import get_db
from database.base import DatabaseBase

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    hours: int = 24,
    db: DatabaseBase = Depends(get_db)
):
    """Get dashboard statistics for the last N hours."""
    if hours < 1 or hours > 168:  # Max 1 week
        hours = 24
    
    stats = db.get_dashboard_stats(hours=hours)
    return stats

