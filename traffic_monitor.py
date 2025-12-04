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
            
            # Simple logic: RFC1918 IP is always the client (local), non-RFC1918 is server (external)
            source_is_local = self._is_local_ip(source_ip)
            dest_is_local = self._is_local_ip(dest_ip)
            
            # Normalize flow key to always use (client_ip, server_ip, server_port, protocol)
            # Client is always RFC1918, server is always public (unless abnormal flow)
            is_abnormal = False
            
            if source_is_local and not dest_is_local:
                # Outbound: RFC1918 client -> external server
                client_ip = source_ip
                server_ip = dest_ip
                server_port = dest_port  # Server port is the destination port (where client connects to)
                is_outbound_packet = True
            elif dest_is_local and not source_is_local:
                # Inbound: external server -> RFC1918 client
                # Normalize to same flow key: client is RFC1918, server is public
                client_ip = dest_ip
                server_ip = source_ip
                server_port = source_port  # Server port is the source port (server's listening port)
                is_outbound_packet = False
            elif source_is_local and dest_is_local:
                # Both local (RFC1918 to RFC1918) - use port numbers to determine client vs server
                # Ephemeral ports (typically >= 49152) indicate client, well-known ports indicate server
                # IANA ephemeral port range: 49152-65535 (Linux), Windows uses 49152-65535
                source_is_ephemeral = source_port >= 49152
                dest_is_ephemeral = dest_port >= 49152
                
                if source_is_ephemeral and not dest_is_ephemeral:
                    # Source is client (ephemeral port), dest is server (well-known port)
                    client_ip = source_ip
                    server_ip = dest_ip
                    server_port = dest_port
                    is_outbound_packet = True
                elif dest_is_ephemeral and not source_is_ephemeral:
                    # Dest is client (ephemeral port), source is server (well-known port)
                    client_ip = dest_ip
                    server_ip = source_ip
                    server_port = source_port
                    is_outbound_packet = False
                else:
                    # Both ephemeral or both well-known - use lower port as server, source as client
                    if source_port < dest_port:
                        client_ip = source_ip
                        server_ip = dest_ip
                        server_port = dest_port
                        is_outbound_packet = True
                    else:
                        client_ip = dest_ip
                        server_ip = source_ip
                        server_port = source_port
                        is_outbound_packet = False
            else:
                # Both external - mark as abnormal flow
                client_ip = source_ip
                server_ip = dest_ip
                server_port = dest_port
                is_outbound_packet = True
                is_abnormal = True
            
            # Create normalized flow key: (client_ip, server_ip, server_port, protocol)
            # For normal flows (client is local, server is external), both directions use the same key
            # Only use is_abnormal flag for storage, not for flow key matching
            flow_key = (client_ip, server_ip, server_port, protocol)
            
            # Ensure flow cache entry exists and is properly initialized
            if flow_key not in self.flow_cache:
                self.flow_cache[flow_key] = {
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'packet_count': 0,
                    'first_seen': datetime.fromtimestamp(traffic_data.get('timestamp', datetime.utcnow().timestamp())),
                    'last_update': datetime.utcnow(),
                    'is_abnormal': is_abnormal
                }
            
            # Update flow statistics based on direction
            # Ensure is_outbound_packet is explicitly set (defensive check)
            if 'is_outbound_packet' not in locals():
                logger.error(f"is_outbound_packet not set for packet {source_ip}:{source_port} -> {dest_ip}:{dest_port}")
                return
            
            # Log direction detection for debugging
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Packet direction: source={source_ip}:{source_port} (local={source_is_local}) -> "
                           f"dest={dest_ip}:{dest_port} (local={dest_is_local}), "
                           f"normalized: client={client_ip} -> server={server_ip}:{server_port}, "
                           f"is_outbound={is_outbound_packet}, packet_size={packet_size}")
            
            if is_outbound_packet:
                # Outbound packet: client -> server
                self.flow_cache[flow_key]['bytes_sent'] += packet_size
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Outbound packet: {source_ip}:{source_port} -> {dest_ip}:{dest_port}, "
                               f"flow_key={flow_key}, bytes_sent={self.flow_cache[flow_key]['bytes_sent']}")
            else:
                # Inbound packet: server -> client (response)
                self.flow_cache[flow_key]['bytes_received'] += packet_size
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Inbound packet: {source_ip}:{source_port} -> {dest_ip}:{dest_port}, "
                               f"flow_key={flow_key}, bytes_received={self.flow_cache[flow_key]['bytes_received']}")
            
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
                
                # Ensure we have valid values (defensive programming)
                bytes_sent = max(0, flow_data.get('bytes_sent', 0))
                bytes_received = max(0, flow_data.get('bytes_received', 0))
                packet_count = max(0, flow_data.get('packet_count', 0))
                
                # Log warnings for potential issues
                if bytes_sent == 0 and bytes_received == 0 and packet_count > 0:
                    logger.warning(f"Flow {flow_key} has {packet_count} packets but both bytes_sent and bytes_received are 0")
                elif bytes_sent == bytes_received and bytes_sent > 0:
                    logger.warning(f"Flow {flow_key} has equal bytes_sent and bytes_received ({bytes_sent}). "
                                 f"This may indicate a direction detection issue.")
                elif bytes_sent == 0 and packet_count > 0 and bytes_received > 0:
                    logger.warning(f"Flow {flow_key} has {packet_count} packets, {bytes_received} bytes_received, but 0 bytes_sent. "
                                 f"This suggests outbound packets may not be detected correctly. "
                                 f"Check direction detection logic.")
                elif bytes_received == 0 and packet_count > 0 and bytes_sent > 0:
                    logger.warning(f"Flow {flow_key} has {packet_count} packets, {bytes_sent} bytes_sent, but 0 bytes_received. "
                                 f"This suggests inbound packets may not be detected correctly.")
                
                self.db.upsert_traffic_flow(
                    source_ip=client_ip,  # RFC1918 client IP (or source IP for abnormal flows)
                    destination_ip=server_ip,  # Public server IP (or dest IP for abnormal flows)
                    destination_port=server_port,
                    protocol=protocol,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                    packet_count=packet_count,
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

