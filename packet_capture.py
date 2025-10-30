"""Packet capture module for network traffic monitoring."""
import logging
import threading
from typing import Optional, Callable
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR
from scapy.layers.inet import Ether
import config

logger = logging.getLogger(__name__)


class PacketCapture:
    """Handles packet capture and parsing."""
    
    def __init__(
        self,
        dns_callback: Optional[Callable] = None,
        traffic_callback: Optional[Callable] = None
    ):
        """Initialize packet capture.
        
        Args:
            dns_callback: Function to call when DNS packet is captured
            traffic_callback: Function to call when traffic packet is captured
        """
        self.dns_callback = dns_callback
        self.traffic_callback = traffic_callback
        self.capture_config = config.config.capture
        self.running = False
        self.capture_thread = None
    
    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            # Check if packet has IP layer
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            
            # Process DNS packets
            if packet.haslayer(DNS):
                self._process_dns_packet(packet, ip_layer)
            
            # Process traffic packets
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                self._process_traffic_packet(packet, ip_layer)
        
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
    
    def _process_dns_packet(self, packet, ip_layer):
        """Extract DNS information from packet."""
        try:
            dns_layer = packet[DNS]
            
            # Process DNS queries
            if dns_layer.qr == 0:  # Query
                if dns_layer.haslayer(DNSQR):
                    query = dns_layer[DNSQR]
                    query_name = query.qname.decode('utf-8').rstrip('.')
                    query_type = query.qtype
                    
                    if self.dns_callback:
                        self.dns_callback({
                            'type': 'query',
                            'domain': query_name,
                            'query_type': self._dns_type_to_string(query_type),
                            'source_ip': ip_layer.src,
                            'destination_ip': ip_layer.dst,
                            'timestamp': packet.time
                        })
            
            # Process DNS responses
            elif dns_layer.qr == 1:  # Response
                if dns_layer.haslayer(DNSRR):
                    resolved_ips = []
                    domain = None
                    
                    # Get domain from question section
                    if dns_layer.haslayer(DNSQR):
                        query = dns_layer[DNSQR]
                        domain = query.qname.decode('utf-8').rstrip('.')
                    
                    # Extract IP addresses from answer section
                    answer_count = dns_layer.ancount
                    for i in range(answer_count):
                        if dns_layer.an is not None:
                            answer = dns_layer.an[i] if answer_count == 1 else dns_layer.an[i]
                            if hasattr(answer, 'rdata') and answer.type == 1:  # A record
                                resolved_ips.append(str(answer.rdata))
                            elif hasattr(answer, 'rdata') and answer.type == 28:  # AAAA record
                                resolved_ips.append(str(answer.rdata))
                    
                    if domain and resolved_ips and self.dns_callback:
                        self.dns_callback({
                            'type': 'response',
                            'domain': domain,
                            'query_type': 'A',  # Simplified
                            'resolved_ips': resolved_ips,
                            'source_ip': ip_layer.src,
                            'destination_ip': ip_layer.dst,
                            'timestamp': packet.time
                        })
        
        except Exception as e:
            logger.debug(f"Error processing DNS packet: {e}")
    
    def _process_traffic_packet(self, packet, ip_layer):
        """Extract traffic information from packet."""
        try:
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst
            protocol = None
            source_port = None
            dest_port = None
            packet_size = len(packet)
            
            if packet.haslayer(TCP):
                protocol = 'TCP'
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                dest_port = tcp_layer.dport
            elif packet.haslayer(UDP):
                protocol = 'UDP'
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                dest_port = udp_layer.dport
            
            if not protocol or not dest_port:
                return
            
            # Apply port filtering if configured
            if self.capture_config.ports and dest_port not in self.capture_config.ports:
                return
            
            if self.traffic_callback:
                # Determine direction and bytes
                # For simplicity, we'll track both directions separately
                self.traffic_callback({
                    'source_ip': source_ip,
                    'destination_ip': dest_ip,
                    'destination_port': dest_port,
                    'source_port': source_port,
                    'protocol': protocol,
                    'packet_size': packet_size,
                    'timestamp': packet.time
                })
        
        except Exception as e:
            logger.debug(f"Error processing traffic packet: {e}")
    
    def _dns_type_to_string(self, qtype: int) -> str:
        """Convert DNS query type number to string."""
        dns_types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            33: 'SRV'
        }
        return dns_types.get(qtype, f'TYPE{qtype}')
    
    def _build_bpf_filter(self) -> Optional[str]:
        """Build BPF filter string."""
        filters = []
        
        # Always include DNS
        filters.append("port 53")
        
        # Add port filters if specified
        if self.capture_config.ports:
            port_filter = " or ".join([f"port {p}" for p in self.capture_config.ports])
            filters.append(f"({port_filter})")
        
        # Add custom BPF filter if specified
        if self.capture_config.bpf_filter:
            filters.append(f"({self.capture_config.bpf_filter})")
        
        return " or ".join(filters) if len(filters) > 1 else (filters[0] if filters else None)
    
    def start(self):
        """Start packet capture in a separate thread."""
        if self.running:
            logger.warning("Packet capture is already running")
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        logger.info("Packet capture started")
    
    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Packet capture stopped")
    
    def _capture_loop(self):
        """Main capture loop."""
        try:
            bpf_filter = self._build_bpf_filter()
            logger.info(f"Starting packet capture with filter: {bpf_filter}")
            
            sniff(
                iface=self.capture_config.interface,
                filter=bpf_filter,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            logger.error(f"Error in packet capture loop: {e}")
            self.running = False

