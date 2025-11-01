"""Threat intelligence module for downloading and parsing threat lists."""
import logging
import re
import urllib.parse
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Set, Optional, Any
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import ipaddress

logger = logging.getLogger(__name__)


class ThreatFeedBase(ABC):
    """Base class for threat intelligence feeds."""
    
    def __init__(self, name: str, url: str, enabled: bool = True):
        """Initialize threat feed.
        
        Args:
            name: Human-readable name for the feed
            url: URL to download the threat list from
            enabled: Whether this feed is enabled
        """
        self.name = name
        self.url = url
        self.enabled = enabled
        self.last_update: Optional[datetime] = None
        self.last_error: Optional[str] = None
    
    @abstractmethod
    def parse(self, content: str) -> Dict[str, Set[str]]:
        """Parse threat list content and extract indicators.
        
        Args:
            content: Raw content from the threat list URL
            
        Returns:
            Dictionary with 'domains' and 'ips' keys, each containing a set of indicators
        """
        pass
    
    def download(self) -> Optional[str]:
        """Download threat list content from URL.
        
        Returns:
            Content as string, or None if download failed
        """
        if not self.enabled:
            logger.debug(f"Feed {self.name} is disabled, skipping download")
            return None
        
        try:
            logger.info(f"Downloading threat list from {self.url}")
            with urlopen(self.url, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                self.last_update = datetime.utcnow()
                self.last_error = None
                logger.info(f"Successfully downloaded {len(content)} bytes from {self.name}")
                return content
        except HTTPError as e:
            error_msg = f"HTTP error {e.code}: {e.reason}"
            logger.error(f"Error downloading {self.name}: {error_msg}")
            self.last_error = error_msg
            return None
        except URLError as e:
            error_msg = f"URL error: {str(e)}"
            logger.error(f"Error downloading {self.name}: {error_msg}")
            self.last_error = error_msg
            return None
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(f"Error downloading {self.name}: {error_msg}")
            self.last_error = error_msg
            return None
    
    def extract_domains_and_ips(self, content: str) -> Dict[str, Set[str]]:
        """Extract domains and IPs from downloaded content."""
        indicators = self.parse(content)
        return indicators


class URLhausFeed(ThreatFeedBase):
    """URLhaus threat feed from abuse.ch."""
    
    def __init__(self):
        """Initialize URLhaus feed."""
        super().__init__(
            name="URLhaus",
            url="https://urlhaus.abuse.ch/downloads/text",
            enabled=True
        )
    
    def parse(self, content: str) -> Dict[str, Set[str]]:
        """Parse URLhaus plain text format.
        
        Format: One URL per line, comments start with #
        
        Returns:
            Dictionary with 'domains' and 'ips' sets
        """
        domains: Set[str] = set()
        ips: Set[str] = set()
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Try to parse as URL
            try:
                # Handle both http:// and https:// URLs
                if line.startswith(('http://', 'https://')):
                    parsed = urllib.parse.urlparse(line)
                    host = parsed.hostname
                    if not host:
                        continue
                    
                    # Check if host is an IP address
                    try:
                        # Validate IP address
                        ip_obj = ipaddress.ip_address(host)
                        # Only include public IPs
                        if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local and not ip_obj.is_multicast:
                            ips.add(str(ip_obj))
                    except ValueError:
                        # Not an IP, treat as domain
                        # Extract root domain (remove port if present)
                        domain = host.split(':')[0].lower()
                        # Filter out local domains
                        if not self._is_local_domain(domain):
                            domains.add(domain)
                else:
                    # Might be just a domain or IP
                    # Try parsing as IP first
                    try:
                        ip_obj = ipaddress.ip_address(line)
                        if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local and not ip_obj.is_multicast:
                            ips.add(str(ip_obj))
                        continue
                    except ValueError:
                        pass
                    
                    # Try parsing as domain
                    if '.' in line and not line.startswith('.'):
                        domain = line.split(':')[0].lower().strip()
                        if not self._is_local_domain(domain):
                            domains.add(domain)
            except Exception as e:
                logger.debug(f"Error parsing line '{line}': {e}")
                continue
        
        logger.info(f"Parsed {len(domains)} domains and {len(ips)} IPs from URLhaus")
        return {'domains': domains, 'ips': ips}
    
    @staticmethod
    def _is_local_domain(domain: str) -> bool:
        """Check if domain is local/private and should be excluded."""
        domain_lower = domain.lower()
        
        # Local/private TLDs
        local_tlds = [
            '.local', '.localhost', '.internal', '.lan', '.home', '.corp',
            '.localdomain', '.arpa', '.test', '.example', '.invalid'
        ]
        
        if any(domain_lower.endswith(tld) for tld in local_tlds):
            return True
        
        # Single label domains (no dots)
        if '.' not in domain_lower or domain_lower.count('.') == 0:
            return True
        
        # Reserved/local hostnames
        local_hostnames = ['localhost', 'localhost.localdomain', 'broadcasthost']
        if domain_lower in local_hostnames:
            return True
        
        return False


class PhishingArmyFeed(ThreatFeedBase):
    """Phishing Army blocklist feed."""
    
    def __init__(self):
        """Initialize Phishing Army feed."""
        super().__init__(
            name="PhishingArmy",
            url="https://phishing.army/download/phishing_army_blocklist_extended.txt",
            enabled=True
        )
    
    def parse(self, content: str) -> Dict[str, Set[str]]:
        """Parse Phishing Army plain text format.
        
        Format: One domain per line, comments start with #
        
        Returns:
            Dictionary with 'domains' and 'ips' sets
        """
        domains: Set[str] = set()
        ips: Set[str] = set()
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse domain
            try:
                domain = line.lower().strip()
                
                # Skip if it's just whitespace or invalid
                if not domain or domain.startswith('#'):
                    continue
                
                # Check if it's an IP address
                try:
                    ip_obj = ipaddress.ip_address(domain)
                    # Only include public IPs
                    if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local and not ip_obj.is_multicast:
                        ips.add(str(ip_obj))
                    continue
                except ValueError:
                    pass
                
                # Filter out local domains
                if not self._is_local_domain(domain):
                    domains.add(domain)
            except Exception as e:
                logger.debug(f"Error parsing line '{line}': {e}")
                continue
        
        logger.info(f"Parsed {len(domains)} domains and {len(ips)} IPs from PhishingArmy")
        return {'domains': domains, 'ips': ips}
    
    @staticmethod
    def _is_local_domain(domain: str) -> bool:
        """Check if domain is local/private and should be excluded."""
        domain_lower = domain.lower()
        
        # Local/private TLDs
        local_tlds = [
            '.local', '.localhost', '.internal', '.lan', '.home', '.corp',
            '.localdomain', '.arpa', '.test', '.example', '.invalid'
        ]
        
        if any(domain_lower.endswith(tld) for tld in local_tlds):
            return True
        
        # Single label domains (no dots)
        if '.' not in domain_lower or domain_lower.count('.') == 0:
            return True
        
        # Reserved/local hostnames
        local_hostnames = ['localhost', 'localhost.localdomain', 'broadcasthost']
        if domain_lower in local_hostnames:
            return True
        
        return False


class ThreatIntelligenceManager:
    """Manages threat intelligence feeds and indicator matching."""
    
    def __init__(self, db):
        """Initialize threat intelligence manager.
        
        Args:
            db: Database instance
        """
        self.db = db
        self.feeds: Dict[str, ThreatFeedBase] = {}
        
        # Register default feeds
        self.register_feed(URLhausFeed())
        self.register_feed(PhishingArmyFeed())
    
    def register_feed(self, feed: ThreatFeedBase):
        """Register a threat feed.
        
        Args:
            feed: Threat feed instance
        """
        self.feeds[feed.name] = feed
        logger.info(f"Registered threat feed: {feed.name}")
    
    def update_feed(self, feed_name: str) -> Dict[str, Any]:
        """Download and update a specific threat feed.
        
        Args:
            feed_name: Name of the feed to update
            
        Returns:
            Dictionary with update results
        """
        if feed_name not in self.feeds:
            raise ValueError(f"Feed '{feed_name}' not found")
        
        feed = self.feeds[feed_name]
        content = feed.download()
        
        if content is None:
            return {
                'success': False,
                'error': feed.last_error or 'Download failed',
                'feed': feed_name
            }
        
        try:
            indicators = feed.extract_domains_and_ips(content)
            
            # Store indicators in database
            result = self.db.update_threat_indicators(
                feed_name=feed_name,
                domains=list(indicators['domains']),
                ips=list(indicators['ips']),
                source_url=feed.url
            )
            
            # Update feed metadata
            self.db.update_threat_feed_metadata(
                feed_name=feed_name,
                last_update=feed.last_update or datetime.utcnow(),
                indicator_count=result,
                source_url=feed.url,
                enabled=feed.enabled,
                error=None
            )
            
            return {
                'success': True,
                'feed': feed_name,
                'domains': len(indicators['domains']),
                'ips': len(indicators['ips']),
                'last_update': feed.last_update.isoformat() if feed.last_update else None,
                'indicator_count': result
            }
        except Exception as e:
            logger.error(f"Error updating feed {feed_name}: {e}", exc_info=True)
            # Update feed metadata with error
            try:
                self.db.update_threat_feed_metadata(
                    feed_name=feed_name,
                    last_update=feed.last_update or datetime.utcnow(),
                    indicator_count=0,
                    source_url=feed.url,
                    enabled=feed.enabled,
                    error=str(e)
                )
            except:
                pass
            return {
                'success': False,
                'error': str(e),
                'feed': feed_name
            }
    
    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if a domain matches any threat indicators.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Threat match information or None
        """
        domain_lower = domain.lower().strip()
        if not domain_lower:
            return None
        
        # Check exact match first
        match = self.db.check_threat_indicator(domain=domain_lower)
        if match:
            return match
        
        # Check if domain is a subdomain of a threat domain
        # For example, if "evil.com" is in threat list, check "subdomain.evil.com"
        parts = domain_lower.split('.')
        # Start from index 1 to skip the first label (subdomain)
        # Check progressively: "subdomain.evil.com" -> "evil.com" -> "com" (skip single labels)
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            # Skip single-label domains (e.g., "com", "net")
            if len(parent_domain.split('.')) >= 2:
                match = self.db.check_threat_indicator(domain=parent_domain)
                if match:
                    return match
        
        return None
    
    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check if an IP matches any threat indicators.
        
        Args:
            ip: IP address to check
            
        Returns:
            Threat match information or None
        """
        try:
            # Normalize IP
            ip_obj = ipaddress.ip_address(ip)
            ip_str = str(ip_obj)
        except ValueError:
            return None
        
        return self.db.check_threat_indicator(ip=ip_str)
    
    def create_alert(self, domain: Optional[str], ip: Optional[str], 
                    query_type: str, source_ip: str, 
                    threat_feed: str, indicator_type: str) -> int:
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
        return self.db.create_threat_alert(
            domain=domain,
            ip=ip,
            query_type=query_type,
            source_ip=source_ip,
            threat_feed=threat_feed,
            indicator_type=indicator_type
        )

