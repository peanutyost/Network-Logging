"""DNS-related API routes."""
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime
import logging

from api.models import DNSLookupResponse, DomainSearchRequest, WhoisResponse, DNSEventResponse
from api.dependencies import get_db
from database.base import DatabaseBase
from whois_service import WhoisService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dns", tags=["DNS"])
whois_service = WhoisService()


@router.get("/search", response_model=List[DNSLookupResponse])
async def search_domains(
    query: str,
    limit: int = 100,
    db: DatabaseBase = Depends(get_db)
):
    """Search for domains by query string."""
    if len(query) < 1:
        raise HTTPException(status_code=400, detail="Query string must be at least 1 character")
    
    results = db.search_domains(query, limit=limit)
    return results


@router.get("/recent", response_model=List[DNSLookupResponse])
async def get_recent_dns(
    limit: int = 100,
    since: Optional[datetime] = None,
    db: DatabaseBase = Depends(get_db)
):
    """Get recent DNS queries in descending order of last_seen."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    return db.get_recent_dns_queries(limit=limit, since=since)


@router.get("/events", response_model=List[DNSEventResponse])
async def get_dns_events(
    limit: int = 500,
    since: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    domain: Optional[str] = None,
    event_type: Optional[str] = None,
    db: DatabaseBase = Depends(get_db)
):
    """Get DNS events with optional filters."""
    if limit < 1 or limit > 5000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 5000")
    return db.get_dns_events(limit=limit, since=since, source_ip=source_ip, domain=domain, event_type=event_type)


@router.get("/domain/{domain}", response_model=DNSLookupResponse)
async def get_domain_info(
    domain: str,
    db: DatabaseBase = Depends(get_db)
):
    """Get DNS information for a specific domain."""
    result = db.get_dns_lookup_by_domain(domain)
    if not result:
        raise HTTPException(status_code=404, detail="Domain not found")
    return result


@router.get("/domain/{domain}/whois", response_model=WhoisResponse)
async def get_domain_whois(
    domain: str,
    force_refresh: bool = False,
    db: DatabaseBase = Depends(get_db)
):
    """Get WHOIS information for a domain."""
    whois_data = whois_service.get_whois(domain, force_refresh=force_refresh)
    if not whois_data:
        raise HTTPException(status_code=404, detail="WHOIS data not available for this domain")
    
    cached = db.get_whois_by_domain(domain)
    if cached:
        return cached
    raise HTTPException(status_code=404, detail="WHOIS data not found")


@router.get("/ip/{ip}")
async def get_dns_lookups_by_ip(
    ip: str,
    limit: int = 1000,
    offset: int = 0,
    days: int = 30,
    db: DatabaseBase = Depends(get_db)
):
    """Get all DNS lookups that resolved to a specific IP address with pagination.
    
    Args:
        ip: IP address to search for
        limit: Maximum number of results per page (default: 1000, max: 1000)
        offset: Number of results to skip for pagination (default: 0)
        days: Number of days to look back (default: 30, max: 365)
    """
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="days must be between 1 and 365")
    
    # Basic IP validation
    if not ip or not ip.strip():
        raise HTTPException(status_code=400, detail="IP address is required")
    
    try:
        results = db.get_dns_lookups_by_ip(ip=ip.strip(), limit=limit, offset=offset, days=days)
        total_count = db.get_dns_lookups_by_ip_count(ip=ip.strip(), days=days)
        
        # Convert dict entries to Pydantic models
        return {
            "results": [DNSLookupResponse(**entry) for entry in results],
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + len(results)) < total_count
        }
    except Exception as e:
        logger.error(f"Error getting DNS lookups by IP: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error searching DNS lookups: {str(e)}")
