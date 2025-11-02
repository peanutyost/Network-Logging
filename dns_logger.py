"""DNS logging module."""
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from database import get_database
from config import config
from whois_service import WhoisService

logger = logging.getLogger(__name__)


class DNSLogger:
    """Handles DNS query/response logging to database."""
    
    def __init__(self, threat_intel_manager=None):
        """Initialize DNS logger.
        
        Args:
            threat_intel_manager: Optional threat intelligence manager instance
        """
        self.db = get_database()
        self.db.connect()
        self.db.create_tables()
        self.whois_service = WhoisService()
        self.threat_intel_manager = threat_intel_manager
    
    def log_dns(self, dns_data: Dict[str, Any]):
        """Log DNS query or response to database.
        
        Args:
            dns_data: Dictionary containing DNS information
                - type: 'query' or 'response'
                - domain: Domain name
                - query_type: DNS query type (A, AAAA, etc.)
                - resolved_ips: List of IP addresses (for responses)
                - source_ip: Source IP
                - destination_ip: Destination IP
                - timestamp: Packet timestamp
        """
        try:
            dns_type = dns_data.get('type')
            domain = dns_data.get('domain')
            query_type = dns_data.get('query_type', 'A')
            source_ip = dns_data.get('source_ip')
            destination_ip = dns_data.get('destination_ip')
            
            if not domain:
                return
            
            # Check for threat indicators before logging
            if self.threat_intel_manager:
                try:
                    # Normalize domain for whitelist check
                    domain_normalized = domain.lower().strip() if domain else None
                    
                    # Check if domain is whitelisted first
                    if domain_normalized and self.db.is_threat_whitelisted(domain=domain_normalized):
                        logger.debug(f"Skipping threat check for whitelisted domain: {domain_normalized}")
                    else:
                        # Check domain for threat match
                        threat_match = self.threat_intel_manager.check_domain(domain)
                        if threat_match:
                            # Double-check whitelist before creating alert (defensive)
                            if domain_normalized and self.db.is_threat_whitelisted(domain=domain_normalized):
                                logger.debug(f"Skipping alert creation for whitelisted domain: {domain_normalized}")
                            else:
                                # Create alert
                                self.threat_intel_manager.create_alert(
                                    domain=domain,
                                    ip=None,
                                    query_type=query_type,
                                    source_ip=source_ip or '',
                                    threat_feed=threat_match.get('feed_name', 'Unknown'),
                                    indicator_type='domain'
                                )
                except Exception as e:
                    logger.error(f"Error checking domain threat: {e}", exc_info=True)
            
            # Record per-event row
            try:
                self.db.insert_dns_event(
                    event_type=dns_type or 'query',
                    domain=domain,
                    query_type=query_type,
                    source_ip=source_ip or '',
                    destination_ip=destination_ip or '',
                    resolved_ips=dns_data.get('resolved_ips') if dns_type == 'response' else None,
                    timestamp=datetime.fromtimestamp(dns_data.get('timestamp', datetime.utcnow().timestamp()))
                )
            except Exception as e:
                logger.debug(f"Error inserting dns_event: {e}")
            
            # Log lookups for summary table
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
            
            elif dns_type == 'response':
                resolved_data = dns_data.get('resolved_ips', [])
                timestamp = datetime.fromtimestamp(dns_data.get('timestamp', datetime.utcnow().timestamp()))
                
                # Extract only IP addresses (A and AAAA records) for lookup table
                resolved_ips = []
                if resolved_data:
                    for item in resolved_data:
                        if isinstance(item, str):
                            # A and AAAA records are stored as plain IP strings
                            # Other record types are stored as "TYPE:data"
                            # Check if it starts with a known record type prefix
                            if not any(item.startswith(prefix + ':') for prefix in ['CNAME', 'NS', 'MX', 'TXT', 'SRV', 'SOA', 'PTR']):
                                # Could be an IP address (IPv4 has no colons, IPv6 has colons)
                                if self._is_ip_address(item):
                                    resolved_ips.append(item)
                
                # Only update lookup table for A and AAAA records that have IP addresses
                # Other record types (MX, TXT, SRV, etc.) are logged in events but not in lookup table
                is_new_domain = False
                if query_type in ['A', 'AAAA'] and resolved_ips:
                    # Check if this is a new domain (first time seeing it)
                    existing = self.db.get_dns_lookup_by_domain(domain)
                    # Check if existing entry matches this query type
                    is_new_domain = existing is None
                    is_new_type = existing is None or (existing.get('query_type') != query_type)
                    first_seen = timestamp if is_new_domain or is_new_type else None
                    
                    self.db.insert_dns_lookup(domain, query_type, resolved_ips, timestamp, first_seen)
                    logger.debug(f"Logged DNS response: {domain} ({query_type}) -> {resolved_ips}")
                elif resolved_data:
                    # Log non-A/AAAA responses in events but not in lookup table
                    logger.debug(f"Logged DNS response: {domain} ({query_type}) -> {resolved_data}")
                else:
                    # Log responses with no data (NXDOMAIN, etc.)
                    logger.debug(f"Logged DNS response: {domain} ({query_type}) -> no data")
                
                # Trigger WHOIS lookup for new A/AAAA domains with IPs
                # Only lookup if domain is not local/private and has valid public IPs
                if query_type in ['A', 'AAAA'] and resolved_ips and is_new_domain:
                    # Check if any resolved IPs are private/internal
                    has_public_ip = False
                    for ip in resolved_ips:
                        try:
                            import ipaddress
                            ip_obj = ipaddress.ip_address(ip)
                            # Skip private/internal IP ranges
                            if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local and not ip_obj.is_multicast:
                                has_public_ip = True
                                break
                        except ValueError:
                            pass
                    
                    # Only trigger WHOIS if domain has public IPs
                    # The whois_service will also check if domain is local
                    if has_public_ip:
                        try:
                            import threading
                            threading.Thread(target=self.whois_service.get_whois, args=(domain,), daemon=True).start()
                        except Exception as e:
                            logger.debug(f"Error triggering WHOIS lookup for {domain}: {e}")
                    else:
                        logger.debug(f"Skipping WHOIS lookup for {domain} (only private/internal IPs)")
                
                # Check resolved IPs for threat indicators
                if self.threat_intel_manager and resolved_ips:
                    for ip in resolved_ips:
                        try:
                            # Normalize IP (ensure it's a string)
                            ip_str = str(ip).strip() if ip else None
                            
                            # Check if IP is whitelisted first
                            if ip_str and self.db.is_threat_whitelisted(ip=ip_str):
                                logger.debug(f"Skipping threat check for whitelisted IP: {ip_str}")
                            else:
                                threat_match = self.threat_intel_manager.check_ip(ip_str)
                                if threat_match:
                                    # Double-check whitelist before creating alert (defensive)
                                    if ip_str and self.db.is_threat_whitelisted(ip=ip_str):
                                        logger.debug(f"Skipping alert creation for whitelisted IP: {ip_str}")
                                    else:
                                        # Create alert for IP match
                                        self.threat_intel_manager.create_alert(
                                            domain=domain,
                                            ip=ip_str,
                                            query_type=query_type,
                                            source_ip=source_ip or '',
                                            threat_feed=threat_match.get('feed_name', 'Unknown'),
                                            indicator_type='ip'
                                        )
                        except Exception as e:
                            logger.error(f"Error checking IP threat {ip}: {e}", exc_info=True)
        
        except Exception as e:
            logger.error(f"Error logging DNS data: {e}")
    
    def _is_ip_address(self, addr: str) -> bool:
        """Check if string is a valid IP address (IPv4 or IPv6)."""
        try:
            import ipaddress
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False
