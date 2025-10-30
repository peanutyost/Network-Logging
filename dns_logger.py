"""DNS logging module."""
import logging
from datetime import datetime
from typing import Dict, Any
from database import get_database
from config import config

logger = logging.getLogger(__name__)


class DNSLogger:
    """Handles DNS query/response logging to database."""
    
    def __init__(self):
        """Initialize DNS logger."""
        self.db = get_database()
        self.db.connect()
        self.db.create_tables()
    
    def log_dns(self, dns_data: Dict[str, Any]):
        """Log DNS query or response to database.
        
        Args:
            dns_data: Dictionary containing DNS information
                - type: 'query' or 'response'
                - domain: Domain name
                - query_type: DNS query type (A, AAAA, etc.)
                - resolved_ips: List of IP addresses (for responses)
                - timestamp: Packet timestamp
        """
        try:
            dns_type = dns_data.get('type')
            domain = dns_data.get('domain')
            query_type = dns_data.get('query_type', 'A')
            
            if not domain:
                return
            
            # For queries, we log them but wait for the response to get IPs
            if dns_type == 'query':
                # Only log if we don't have a recent entry
                existing = self.db.get_dns_lookup_by_domain(domain)
                if existing and existing.get('query_type') == query_type:
                    # Update last_seen
                    timestamp = datetime.fromtimestamp(dns_data.get('timestamp', datetime.utcnow().timestamp()))
                    self.db.insert_dns_lookup(domain, query_type, existing.get('resolved_ips', []), timestamp)
                else:
                    # New query, log it with empty IPs
                    timestamp = datetime.fromtimestamp(dns_data.get('timestamp', datetime.utcnow().timestamp()))
                    self.db.insert_dns_lookup(domain, query_type, [], timestamp)
            
            # For responses, we log the resolved IPs
            elif dns_type == 'response':
                resolved_ips = dns_data.get('resolved_ips', [])
                if not resolved_ips:
                    return
                
                timestamp = datetime.fromtimestamp(dns_data.get('timestamp', datetime.utcnow().timestamp()))
                self.db.insert_dns_lookup(domain, query_type, resolved_ips, timestamp)
                logger.debug(f"Logged DNS response: {domain} -> {resolved_ips}")
        
        except Exception as e:
            logger.error(f"Error logging DNS data: {e}")
