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
            'last_update': datetime.utcnow()
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
            # Determine direction based on whether source is local/private
            source_is_local = self._is_local_ip(source_ip)
            dest_is_local = self._is_local_ip(dest_ip)
            
            # Normalize flow key to always use (client_ip, server_ip, server_port, protocol)
            # This ensures both directions of a bidirectional flow use the same key
            if source_is_local and not dest_is_local:
                # Outbound: local client -> external server
                # Flow key: (client_ip, server_ip, server_port, protocol)
                client_ip = source_ip
                server_ip = dest_ip
                server_port = dest_port
                is_outbound_packet = True
            elif dest_is_local and not source_is_local:
                # Inbound response: external server -> local client
                # Normalize to same flow key as outbound: (client_ip, server_ip, server_port, protocol)
                # The server's port is now the source_port (from server's perspective)
                client_ip = dest_ip
                server_ip = source_ip
                server_port = source_port  # Server's port in response
                is_outbound_packet = False
            else:
                # Both local or both external - treat first IP as client
                if source_is_local:
                    client_ip = source_ip
                    server_ip = dest_ip
                    server_port = dest_port
                    is_outbound_packet = True
                else:
                    # Both external or edge case - use destination as client
                    client_ip = dest_ip
                    server_ip = source_ip
                    server_port = source_port
                    is_outbound_packet = False
            
            # Create normalized flow key: (client_ip, server_ip, server_port, protocol)
            flow_key = (client_ip, server_ip, server_port, protocol)
            
            # Update flow statistics based on direction
            if is_outbound_packet:
                # Outbound packet: client -> server
                self.flow_cache[flow_key]['bytes_sent'] += packet_size
            else:
                # Inbound packet: server -> client (response)
                self.flow_cache[flow_key]['bytes_received'] += packet_size
            
            self.flow_cache[flow_key]['packet_count'] += 1
            self.flow_cache[flow_key]['last_update'] = datetime.utcnow()
            
            # Flush cache periodically
            if (datetime.utcnow() - self.last_flush).total_seconds() >= self.cache_flush_interval:
                self._flush_cache()
        
        except Exception as e:
            logger.error(f"Error processing traffic packet: {e}")
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is local/private."""
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
    
    def _flush_cache(self):
        """Flush accumulated flow data to database."""
        try:
            if not self.flow_cache:
                return
            
            logger.debug(f"Flushing {len(self.flow_cache)} flow entries to database")
            
            for flow_key, flow_data in self.flow_cache.items():
                source_ip, dest_ip, dest_port, protocol = flow_key
                
                self.db.upsert_traffic_flow(
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    destination_port=dest_port,
                    protocol=protocol,
                    bytes_sent=flow_data['bytes_sent'],
                    bytes_received=flow_data['bytes_received'],
                    packet_count=flow_data['packet_count']
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

