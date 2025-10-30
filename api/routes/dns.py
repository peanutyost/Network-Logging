"""DNS-related API routes."""
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from datetime import datetime

from api.models import DNSLookupResponse, DomainSearchRequest, WhoisResponse
from api.dependencies import get_db
from database.base import DatabaseBase
from whois_service import WhoisService

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

