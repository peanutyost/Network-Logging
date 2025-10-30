"""DNS-related API routes."""
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from datetime import datetime

from api.models import DNSLookupResponse, DomainSearchRequest
from api.dependencies import get_db
from database.base import DatabaseBase

router = APIRouter(prefix="/api/dns", tags=["DNS"])


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

