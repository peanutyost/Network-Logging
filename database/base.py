"""Base database abstraction class."""
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime


class DatabaseBase(ABC):
    """Abstract base class for database operations."""
    
    @abstractmethod
    def connect(self) -> None:
        """Establish database connection."""
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Close database connection."""
        pass
    
    @abstractmethod
    def create_tables(self) -> None:
        """Create all required database tables."""
        pass
    
    # DNS Lookup operations
    @abstractmethod
    def insert_dns_lookup(
        self,
        domain: str,
        query_type: str,
        resolved_ips: List[str],
        timestamp: Optional[datetime] = None,
        first_seen: Optional[datetime] = None
    ) -> int:
        """Insert or update a DNS lookup entry."""
        pass
    
    @abstractmethod
    def get_dns_lookup_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS lookup information by domain."""
        pass
    
    @abstractmethod
    def get_domain_by_ip(self, ip: str, days: int = 7) -> Optional[str]:
        """Get domain name for an IP address if it was resolved in the last N days."""
        pass
    
    @abstractmethod
    def search_domains(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for domains matching a query string."""
        pass
    
    # Traffic Flow operations
    @abstractmethod
    def upsert_traffic_flow(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int,
        protocol: str,
        bytes_sent: int,
        bytes_received: int,
        packet_count: int,
        domain: Optional[str] = None
    ) -> int:
        """Insert or update a traffic flow entry."""
        pass
    
    @abstractmethod
    def get_traffic_by_domain(
        self,
        domain: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get all traffic flows for a specific domain."""
        pass
    
    @abstractmethod
    def get_orphaned_ips(
        self,
        days: int = 7,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get IPs that have traffic but no DNS entry in the last N days."""
        pass
    
    @abstractmethod
    def get_top_domains(
        self,
        limit: int = 10,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get top domains by query count or traffic volume."""
        pass
    
    @abstractmethod
    def get_dashboard_stats(
        self,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get dashboard statistics for the last N hours."""
        pass
    
    # WHOIS operations
    @abstractmethod
    def save_whois_data(self, domain: str, whois_data: Dict[str, Any]) -> None:
        """Save WHOIS data for a domain."""
        pass
    
    @abstractmethod
    def get_whois_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS data for a domain."""
        pass

