"""Pydantic models for API responses and requests."""
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime


class DNSLookupResponse(BaseModel):
    """DNS lookup response model."""
    id: int
    domain: str
    query_type: str
    resolved_ips: List[str]
    query_timestamp: datetime
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class WhoisResponse(BaseModel):
    """WHOIS data response model."""
    domain: str
    whois_data: Dict[str, Any]
    whois_updated_at: datetime
    created_at: datetime


class DNSEventResponse(BaseModel):
    """DNS per-event model."""
    id: int
    event_type: str
    domain: str
    query_type: str
    source_ip: str
    destination_ip: str
    resolved_ips: Optional[List[str]] = None
    event_timestamp: datetime


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


# Authentication models
class Token(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Token data model."""
    username: Optional[str] = None


class UserLogin(BaseModel):
    """User login request model."""
    username: str
    password: str


class UserCreate(BaseModel):
    """User creation request model."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)
    is_admin: bool = False


class UserUpdate(BaseModel):
    """User update request model."""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=6)
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    """Password change request model."""
    current_password: str
    new_password: str = Field(..., min_length=6)


class UserResponse(BaseModel):
    """User response model."""
    id: int
    username: str
    email: str
    is_admin: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ThreatFeedResponse(BaseModel):
    """Threat feed metadata response model."""
    id: int
    feed_name: str
    source_url: str
    enabled: bool
    last_update: Optional[datetime] = None
    indicator_count: int
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ThreatAlertResponse(BaseModel):
    """Threat alert response model."""
    id: int
    feed_name: str
    indicator_type: str
    domain: Optional[str] = None
    ip: Optional[str] = None
    query_type: str
    source_ip: str
    resolved: bool
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[int] = None
    created_at: datetime


class ThreatFeedUpdateRequest(BaseModel):
    """Request to update a threat feed."""
    feed_name: str


class ThreatFeedUpdateResponse(BaseModel):
    """Response from threat feed update."""
    success: bool
    feed: str
    domains: Optional[int] = None
    ips: Optional[int] = None
    indicator_count: Optional[int] = None
    last_update: Optional[str] = None
    error: Optional[str] = None