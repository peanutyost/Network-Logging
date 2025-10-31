"""WHOIS lookup service with caching."""
import logging
import ipaddress
try:
    import whois
except ImportError:
    # Alternative: python-whois package
    try:
        import pythonwhois as whois
    except ImportError:
        whois = None
        logging.warning("WHOIS library not found. Install python-whois or whois package")
from datetime import datetime
from typing import Optional, Dict, Any
from database import get_database

logger = logging.getLogger(__name__)


class WhoisService:
    """Handles WHOIS lookups with caching."""
    
    def __init__(self):
        """Initialize WHOIS service."""
        self.db = get_database()
        self.cache_days = 60  # Cache WHOIS data for 60 days
    
    def is_local_domain(self, domain: str) -> bool:
        """Check if a domain is local/private and should not have WHOIS lookups.
        
        Args:
            domain: Domain name to check
        
        Returns:
            True if domain is local/private, False otherwise
        """
        if not domain:
            return True
        
        domain_lower = domain.lower().strip()
        
        # Check for localhost
        if domain_lower == 'localhost' or domain_lower.startswith('localhost.'):
            return True
        
        # Check for .local TLD (mDNS/Bonjour)
        if domain_lower.endswith('.local'):
            return True
        
        # Check for private/internal domains (single label or common internal TLDs)
        internal_tlds = ['.lan', '.internal', '.home', '.corp', '.localdomain', '.local']
        for tld in internal_tlds:
            if domain_lower.endswith(tld):
                return True
        
        # Check if it's an IP address (shouldn't do WHOIS on IPs directly via domain lookup)
        try:
            # Remove port if present
            domain_part = domain_lower.split(':')[0]
            ipaddress.ip_address(domain_part)
            return True
        except ValueError:
            pass
        
        # Check for single-label domains (no dots) - likely internal
        if '.' not in domain_lower:
            return True
        
        return False
    
    def get_whois(self, domain: str, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
        """Get WHOIS data for a domain with caching.
        
        Args:
            domain: Domain name to look up
            force_refresh: If True, bypass cache and fetch fresh data
        
        Returns:
            Dictionary with WHOIS data or None if lookup fails
        """
        try:
            # Skip WHOIS lookup for local/private domains
            if self.is_local_domain(domain):
                logger.debug(f"Skipping WHOIS lookup for local/private domain: {domain}")
                return None
            
            # Check cache first
            if not force_refresh:
                cached = self.db.get_whois_by_domain(domain)
                if cached and self._is_cache_valid(cached.get('whois_updated_at')):
                    logger.debug(f"Using cached WHOIS data for {domain}")
                    return cached.get('whois_data')
            
            # Fetch new WHOIS data
            if whois is None:
                logger.warning("WHOIS library not available")
                return None
            
            logger.info(f"Fetching WHOIS data for {domain}")
            try:
                # Try different methods depending on the library
                if hasattr(whois, 'whois'):
                    whois_data = whois.whois(domain)
                elif hasattr(whois, 'get_whois'):
                    whois_data = whois.get_whois(domain)
                else:
                    logger.error("Unknown WHOIS library interface")
                    return None
                
                # Convert WHOIS object to dictionary
                whois_dict = self._parse_whois_data(whois_data)
                
                # Save to database
                self.db.save_whois_data(domain, whois_dict)
                
                return whois_dict
            
            except Exception as whois_error:
                # Handle various WHOIS exception types
                logger.warning(f"WHOIS lookup failed for {domain}: {whois_error}")
                return None
            except Exception as e:
                logger.error(f"Error fetching WHOIS data for {domain}: {e}")
                return None
        
        except Exception as e:
            logger.error(f"Error in get_whois for {domain}: {e}")
            return None
    
    def _is_cache_valid(self, update_time: Optional[datetime]) -> bool:
        """Check if cached WHOIS data is still valid."""
        if not update_time:
            return False
        
        age = datetime.utcnow() - update_time
        return age.days < self.cache_days
    
    def _parse_whois_data(self, whois_data) -> Dict[str, Any]:
        """Parse WHOIS data object into dictionary."""
        result = {}
        
        # Extract common WHOIS fields
        fields = [
            'domain_name', 'registrar', 'whois_server', 'updated_date',
            'creation_date', 'expiration_date', 'name_servers', 'status',
            'emails', 'dnssec', 'name', 'org', 'address', 'city', 'state',
            'zipcode', 'country', 'registrant_country', 'registrant_name',
            'registrant_organization', 'admin_country', 'admin_name',
            'tech_country', 'tech_name'
        ]
        
        for field in fields:
            try:
                value = getattr(whois_data, field, None)
                if value is not None:
                    # Handle date objects
                    if isinstance(value, datetime):
                        result[field] = value.isoformat()
                    elif isinstance(value, list):
                        # Handle lists (like name_servers, emails)
                        result[field] = [str(v) for v in value if v]
                    else:
                        result[field] = str(value)
            except Exception:
                pass
        
        return result

