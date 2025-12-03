"""Traffic flow monitoring module."""
import logging
from datetime import datetime
from typing import Dict, Any
from collections import defaultdict
from database import get_database
from config import config

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """Monitors and tracks traffic flows."""
    
    def __init__(self):
        """Initialize traffic monitor."""
        self.db = get_database()
        self.db.connect()
        
        # In-memory cache for flow aggregation (to reduce DB writes)
        self.flow_cache = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packet_count': 0,
            'first_seen': datetime.utcnow(),
            'last_update': datetime.utcnow(),
            'is_abnormal': False
        })
        self.cache_flush_interval = 60  # Flush cache every 60 seconds
        self.last_flush = datetime.utcnow()
    
    def process_packet(self, traffic_data: Dict[str, Any]):
        """Process a traffic packet and update flow statistics.
        
        Args:
            traffic_data: Dictionary containing traffic information
                - source_ip: Source IP address
                - destination_ip: Destination IP address
                - destination_port: Destination port
                - source_port: Source port
                - protocol: Protocol (TCP/UDP)
                - packet_size: Size of packet in bytes
                - timestamp: Packet timestamp
        """
        try:
            source_ip = traffic_data.get('source_ip')
            dest_ip = traffic_data.get('destination_ip')
            dest_port = traffic_data.get('destination_port')
            source_port = traffic_data.get('source_port')
            protocol = traffic_data.get('protocol')
            packet_size = traffic_data.get('packet_size', 0)
            
            if not all([source_ip, dest_ip, dest_port, source_port, protocol]):
                return
            
            # Track bidirectional traffic properly
            # Ensure client is always RFC1918 (private) IP and server is always public (outside) IP
            source_is_local = self._is_local_ip(source_ip)
            dest_is_local = self._is_local_ip(dest_ip)
            
            # Identify the well-known server port for flow normalization
            # The server port is typically:
            # 1. A well-known port (< 1024) or common service port (80, 443, etc.)
            # 2. The port that the client initially connected to (for outbound)
            # 3. The port the server is listening on (for inbound responses)
            def _identify_server_port(src_port: int, dst_port: int, src_is_local: bool, dst_is_local: bool) -> int:
                """Identify which port is the server's well-known port."""
                # Common well-known service ports
                well_known_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 8080, 8443}
                
                # If one port is well-known, it's the server port
                if src_port in well_known_ports and dst_port not in well_known_ports:
                    return src_port
                if dst_port in well_known_ports and src_port not in well_known_ports:
                    return dst_port
                
                # If one port is < 1024 (privileged), it's likely the server port
                if src_port < 1024 and dst_port >= 1024:
                    return src_port
                if dst_port < 1024 and src_port >= 1024:
                    return dst_port
                
                # If source is local and dest is not, dest_port is the server port (outbound)
                if src_is_local and not dst_is_local:
                    return dst_port
                
                # If dest is local and source is not, source_port is the server port (inbound)
                if dst_is_local and not src_is_local:
                    return src_port
                
                # Default: use the lower port number (often the server)
                return min(src_port, dst_port)
            
            # Normalize flow key to always use (client_ip, server_ip, server_port, protocol)
            # Client must be RFC1918, server must be public (unless abnormal flow)
            is_abnormal = False
            if source_is_local and not dest_is_local:
                # Outbound: local client -> external server
                client_ip = source_ip
                server_ip = dest_ip
                server_port = _identify_server_port(source_port, dest_port, source_is_local, dest_is_local)
                is_outbound_packet = True
            elif dest_is_local and not source_is_local:
                # Inbound response: external server -> local client
                # Normalize to same flow key: client is RFC1918, server is public
                client_ip = dest_ip
                server_ip = source_ip
                server_port = _identify_server_port(source_port, dest_port, source_is_local, dest_is_local)
                is_outbound_packet = False
            elif source_is_local and dest_is_local:
                # Both local - use source as client (RFC1918)
                client_ip = source_ip
                server_ip = dest_ip
                server_port = _identify_server_port(source_port, dest_port, source_is_local, dest_is_local)
                is_outbound_packet = True
            else:
                # Both external - mark as abnormal flow
                # For abnormal flows, we can't normalize to client/server, so use source/dest as-is
                client_ip = source_ip
                server_ip = dest_ip
                server_port = _identify_server_port(source_port, dest_port, source_is_local, dest_is_local)
                is_outbound_packet = True
                is_abnormal = True
            
            # Create normalized flow key: (client_ip, server_ip, server_port, protocol)
            # For normal flows (client is local, server is external), both directions use the same key
            # Only use is_abnormal flag for storage, not for flow key matching
            flow_key = (client_ip, server_ip, server_port, protocol)
            
            # Update flow statistics based on direction
            if is_outbound_packet:
                # Outbound packet: client -> server
                self.flow_cache[flow_key]['bytes_sent'] += packet_size
            else:
                # Inbound packet: server -> client (response)
                self.flow_cache[flow_key]['bytes_received'] += packet_size
            
            self.flow_cache[flow_key]['packet_count'] += 1
            # Track first_seen (only set on first packet)
            if 'first_seen' not in self.flow_cache[flow_key] or self.flow_cache[flow_key]['first_seen'] > datetime.fromtimestamp(traffic_data.get('timestamp', datetime.utcnow().timestamp())):
                self.flow_cache[flow_key]['first_seen'] = datetime.fromtimestamp(traffic_data.get('timestamp', datetime.utcnow().timestamp()))
            self.flow_cache[flow_key]['last_update'] = datetime.utcnow()
            # Store is_abnormal flag in cache
            if 'is_abnormal' in locals():
                self.flow_cache[flow_key]['is_abnormal'] = is_abnormal
            
            # Flush cache periodically
            if (datetime.utcnow() - self.last_flush).total_seconds() >= self.cache_flush_interval:
                self._flush_cache()
        
        except Exception as e:
            logger.error(f"Error processing traffic packet: {e}")
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is RFC1918 (private/local) or loopback."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            # Check for RFC1918 private IPs, loopback, link-local, and multicast
            return (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or 
                ip_obj.is_multicast
            )
        except (ValueError, AttributeError):
            # Fallback for invalid IPs or if ipaddress not available
            # Try IPv4 parsing
            try:
                parts = ip.split('.')
                if len(parts) != 4:
                    return False
                
                first_octet = int(parts[0])
                # Private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
                return (
                    first_octet == 10 or
                    (first_octet == 172 and 16 <= int(parts[1]) <= 31) or
                    (first_octet == 192 and int(parts[1]) == 168) or
                    (first_octet == 127)
                )
            except (ValueError, IndexError):
                return False
    
    def _flush_cache(self):
        """Flush accumulated flow data to database."""
        try:
            if not self.flow_cache:
                return
            
            logger.debug(f"Flushing {len(self.flow_cache)} flow entries to database")
            
            for flow_key, flow_data in self.flow_cache.items():
                # Flow key is always (client_ip, server_ip, server_port, protocol)
                client_ip, server_ip, server_port, protocol = flow_key
                is_abnormal = flow_data.get('is_abnormal', False)
                
                # Get domain by looking up DNS records that occurred before flow started
                first_seen = flow_data.get('first_seen', datetime.utcnow())
                
                self.db.upsert_traffic_flow(
                    source_ip=client_ip,  # RFC1918 client IP (or source IP for abnormal flows)
                    destination_ip=server_ip,  # Public server IP (or dest IP for abnormal flows)
                    destination_port=server_port,
                    protocol=protocol,
                    bytes_sent=flow_data['bytes_sent'],
                    bytes_received=flow_data['bytes_received'],
                    packet_count=flow_data['packet_count'],
                    first_seen=first_seen,  # Pass first_seen for domain lookup
                    is_abnormal=is_abnormal  # Mark as abnormal if both IPs are external
                )
            
            # Clear cache
            self.flow_cache.clear()
            self.last_flush = datetime.utcnow()
            logger.debug("Flow cache flushed successfully")
        
        except Exception as e:
            logger.error(f"Error flushing flow cache: {e}")
    
    def flush(self):
        """Force flush cache (call this on shutdown)."""
        self._flush_cache()

