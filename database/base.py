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

    @abstractmethod
    def get_recent_dns_queries(
        self,
        limit: int = 100,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get recent DNS queries ordered by last_seen desc."""
        pass

    # DNS Events (per-packet/query/response)
    @abstractmethod
    def insert_dns_event(
        self,
        event_type: str,  # 'query' | 'response'
        domain: str,
        query_type: str,
        source_ip: str,
        destination_ip: str,
        resolved_ips: Optional[List[str]] = None,
        timestamp: Optional[datetime] = None
    ) -> int:
        """Insert a DNS event row."""
        pass

    @abstractmethod
    def get_dns_events(
        self,
        limit: int = 500,
        since: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        domain: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query DNS events with optional filters."""
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
    
    # User management operations
    @abstractmethod
    def create_user(
        self,
        username: str,
        email: str,
        hashed_password: str,
        is_admin: bool = False,
        is_active: bool = True
    ) -> int:
        """Create a new user."""
        pass
    
    @abstractmethod
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        pass
    
    @abstractmethod
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        pass
    
    @abstractmethod
    def get_all_users(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all users with pagination."""
        pass
    
    @abstractmethod
    def update_user(
        self,
        user_id: int,
        username: Optional[str] = None,
        email: Optional[str] = None,
        hashed_password: Optional[str] = None,
        is_admin: Optional[bool] = None,
        is_active: Optional[bool] = None
    ) -> bool:
        """Update user information."""
        pass
    
    @abstractmethod
    def delete_user(self, user_id: int) -> bool:
        """Delete a user."""
        pass
    
    # Threat intelligence operations
    @abstractmethod
    def update_threat_indicators(
        self,
        feed_name: str,
        domains: List[str],
        ips: List[str],
        source_url: str
    ) -> int:
        """Update threat indicators for a feed (replace existing).
        
        Args:
            feed_name: Name of the threat feed
            domains: List of domain indicators
            ips: List of IP indicators
            source_url: URL where the feed was downloaded from
            
        Returns:
            Total number of indicators stored
        """
        pass
    
    @abstractmethod
    def check_threat_indicator(
        self,
        domain: Optional[str] = None,
        ip: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Check if a domain or IP matches a threat indicator.
        
        Args:
            domain: Domain name to check
            ip: IP address to check
            
        Returns:
            Threat indicator match information or None
        """
        pass
    
    @abstractmethod
    def create_threat_alert(
        self,
        domain: Optional[str],
        ip: Optional[str],
        query_type: str,
        source_ip: str,
        threat_feed: str,
        indicator_type: str
    ) -> int:
        """Create a threat alert.
        
        Args:
            domain: Matched domain (if applicable)
            ip: Matched IP (if applicable)
            query_type: DNS query type
            source_ip: Source IP that triggered the alert
            threat_feed: Name of the threat feed
            indicator_type: Type of indicator ('domain' or 'ip')
            
        Returns:
            Alert ID
        """
        pass
    
    @abstractmethod
    def get_threat_alerts(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        resolved: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Get threat alerts.
        
        Args:
            limit: Maximum number of alerts to return
            since: Only return alerts since this timestamp
            resolved: Filter by resolved status (True/False/None for all)
            
        Returns:
            List of threat alerts
        """
        pass
    
    @abstractmethod
    def get_threat_feeds(self) -> List[Dict[str, Any]]:
        """Get list of threat feeds.
        
        Returns:
            List of threat feed information
        """
        pass
    
    @abstractmethod
    def update_threat_feed_metadata(
        self,
        feed_name: str,
        last_update: datetime,
        indicator_count: int,
        source_url: str,
        enabled: bool = True,
        error: Optional[str] = None
    ) -> None:
        """Update threat feed metadata.
        
        Args:
            feed_name: Name of the threat feed
            last_update: Last update timestamp
            indicator_count: Number of indicators in feed
            source_url: URL where feed is downloaded from
            enabled: Whether feed is enabled
            error: Last error message (if any)
        """
        pass
    
    @abstractmethod
    def resolve_threat_alert(self, alert_id: int) -> bool:
        """Mark a threat alert as resolved.
        
        Args:
            alert_id: ID of alert to resolve
            
        Returns:
            True if alert was resolved, False if not found
        """
        pass
    
    @abstractmethod
    def update_threat_feed_enabled(self, feed_name: str, enabled: bool) -> bool:
        """Update the enabled status of a threat feed.
        
        Args:
            feed_name: Name of the threat feed
            enabled: Whether the feed should be enabled
            
        Returns:
            True if feed was updated, False if not found
        """
        pass

