"""Pydantic models for API responses and requests."""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class DNSLookupResponse(BaseModel):
    """DNS lookup response model."""
    id: int
    domain: str
    query_type: str
    resolved_ips: List[str]
    query_timestamp: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class TrafficFlowResponse(BaseModel):
    """Traffic flow response model."""
    id: int
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    domain: Optional[str]
    bytes_sent: int
    bytes_received: int
    packet_count: int
    first_seen: datetime
    last_update: datetime
    is_orphaned: bool

    class Config:
        from_attributes = True


class OrphanedIPResponse(BaseModel):
    """Orphaned IP response model."""
    destination_ip: str
    total_bytes_sent: int
    total_bytes_received: int
    total_bytes: int
    total_packets: int
    connection_count: int
    first_seen: datetime
    last_seen: datetime


class DomainSearchRequest(BaseModel):
    """Domain search request model."""
    query: str = Field(..., min_length=1)
    limit: int = Field(default=100, ge=1, le=1000)


class DateRangeRequest(BaseModel):
    """Date range request model."""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    days: int = Field(default=7, ge=1, le=365)


class DashboardStatsResponse(BaseModel):
    """Dashboard statistics response model."""
    dns_queries: int
    total_bytes: int
    flow_count: int
    active_connections: int
    period_hours: int


class TopDomainResponse(BaseModel):
    """Top domain response model."""
    domain: str
    query_count: int
    total_bytes: int
    bytes_sent: int
    bytes_received: int
    total_packets: int
    last_seen: datetime


class TrafficVolumeDataPoint(BaseModel):
    """Traffic volume data point for time series."""
    timestamp: datetime
    bytes_sent: int
    bytes_received: int
    total_bytes: int

