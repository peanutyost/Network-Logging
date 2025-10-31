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
                # Handle multiple questions if present
                if dns_layer.haslayer(DNSQR):
                    # DNSQR can be a single question or a list
                    questions = dns_layer.qd
                    if questions is None:
                        return
                    
                    # Handle single question or list of questions
                    if not isinstance(questions, list):
                        questions = [questions]
                    
                    for query in questions:
                        if not query:
                            continue
                        query_name = query.qname.decode('utf-8').rstrip('.')
                        query_type_num = query.qtype
                        query_type_str = self._dns_type_to_string(query_type_num)
                        
                        if self.dns_callback:
                            self.dns_callback({
                                'type': 'query',
                                'domain': query_name,
                                'query_type': query_type_str,
                                'source_ip': ip_layer.src,
                                'destination_ip': ip_layer.dst,
                                'timestamp': packet.time
                            })
            
            # Process DNS responses
            elif dns_layer.qr == 1:  # Response
                domain = None
                query_type_str = 'A'  # Default fallback
                resolved_data = []  # Store all resolved data (IPs, hostnames, etc.)
                
                # Get domain and query type from question section
                if dns_layer.haslayer(DNSQR):
                    questions = dns_layer.qd
                    if questions:
                        # Handle single question or list
                        if not isinstance(questions, list):
                            questions = [questions]
                        
                        # Use the first question to determine domain and query type
                        query = questions[0]
                        if query:
                            domain = query.qname.decode('utf-8').rstrip('.')
                            query_type_num = query.qtype
                            query_type_str = self._dns_type_to_string(query_type_num)
                
                if not domain:
                    return
                
                # Extract all resource records from answer section
                answer_count = dns_layer.ancount
                if answer_count > 0 and dns_layer.an is not None:
                    answers = dns_layer.an
                    # Handle single answer or list
                    if not isinstance(answers, list):
                        answers = [answers] if answers else []
                    
                    for answer in answers:
                        if not answer or not hasattr(answer, 'type'):
                            continue
                        
                        answer_type = answer.type
                        answer_type_str = self._dns_type_to_string(answer_type)
                        
                        # Extract data based on record type
                        if hasattr(answer, 'rdata'):
                            rdata = answer.rdata
                            if answer_type == 1:  # A record
                                resolved_data.append(str(rdata))
                            elif answer_type == 28:  # AAAA record
                                resolved_data.append(str(rdata))
                            elif answer_type == 5:  # CNAME
                                cname = rdata.decode('utf-8').rstrip('.') if isinstance(rdata, bytes) else str(rdata).rstrip('.')
                                resolved_data.append(f"CNAME:{cname}")
                            elif answer_type == 2:  # NS
                                ns = rdata.decode('utf-8').rstrip('.') if isinstance(rdata, bytes) else str(rdata).rstrip('.')
                                resolved_data.append(f"NS:{ns}")
                            elif answer_type == 15:  # MX
                                # MX records have priority and exchange
                                if isinstance(rdata, tuple) and len(rdata) >= 2:
                                    priority, exchange = rdata[0], rdata[1]
                                    exchange_str = exchange.decode('utf-8').rstrip('.') if isinstance(exchange, bytes) else str(exchange).rstrip('.')
                                    resolved_data.append(f"MX:{priority} {exchange_str}")
                                else:
                                    resolved_data.append(f"MX:{str(rdata)}")
                            elif answer_type == 16:  # TXT
                                txt = rdata.decode('utf-8') if isinstance(rdata, bytes) else str(rdata)
                                resolved_data.append(f"TXT:{txt}")
                            elif answer_type == 33:  # SRV
                                # SRV has priority, weight, port, target
                                if isinstance(rdata, tuple) and len(rdata) >= 4:
                                    priority, weight, port, target = rdata[0], rdata[1], rdata[2], rdata[3]
                                    target_str = target.decode('utf-8').rstrip('.') if isinstance(target, bytes) else str(target).rstrip('.')
                                    resolved_data.append(f"SRV:{priority} {weight} {port} {target_str}")
                                else:
                                    resolved_data.append(f"SRV:{str(rdata)}")
                            else:
                                # For other record types, store as TYPE:data
                                data_str = rdata.decode('utf-8') if isinstance(rdata, bytes) else str(rdata)
                                resolved_data.append(f"{answer_type_str}:{data_str}")
                
                # Log response even if there's no data (NXDOMAIN, etc.)
                if domain and self.dns_callback:
                    self.dns_callback({
                        'type': 'response',
                        'domain': domain,
                        'query_type': query_type_str,  # Use the actual query type from question
                        'resolved_ips': resolved_data if resolved_data else None,  # Store all resolved data
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
            3: 'MD',
            4: 'MF',
            5: 'CNAME',
            6: 'SOA',
            7: 'MB',
            8: 'MG',
            9: 'MR',
            10: 'NULL',
            11: 'WKS',
            12: 'PTR',
            13: 'HINFO',
            14: 'MINFO',
            15: 'MX',
            16: 'TXT',
            17: 'RP',
            18: 'AFSDB',
            19: 'X25',
            20: 'ISDN',
            21: 'RT',
            22: 'NSAP',
            23: 'NSAP-PTR',
            24: 'SIG',
            25: 'KEY',
            26: 'PX',
            27: 'GPOS',
            28: 'AAAA',
            29: 'LOC',
            30: 'NXT',
            31: 'EID',
            32: 'NIMLOC',
            33: 'SRV',
            34: 'ATMA',
            35: 'NAPTR',
            36: 'KX',
            37: 'CERT',
            38: 'A6',
            39: 'DNAME',
            40: 'SINK',
            41: 'OPT',
            42: 'APL',
            43: 'DS',
            44: 'SSHFP',
            45: 'IPSECKEY',
            46: 'RRSIG',
            47: 'NSEC',
            48: 'DNSKEY',
            49: 'DHCID',
            50: 'NSEC3',
            51: 'NSEC3PARAM',
            52: 'TLSA',
            53: 'SMIMEA',
            55: 'HIP',
            56: 'NINFO',
            57: 'RKEY',
            58: 'TALINK',
            59: 'CDS',
            60: 'CDNSKEY',
            61: 'OPENPGPKEY',
            62: 'CSYNC',
            99: 'SPF',
            108: 'EUI48',
            109: 'EUI64',
            249: 'TKEY',
            250: 'TSIG',
            251: 'IXFR',
            252: 'AXFR',
            253: 'MAILB',
            254: 'MAILA',
            255: 'ANY',
            256: 'URI',
            257: 'CAA',
            258: 'AVC',
            32768: 'TA',
            32769: 'DLV'
        }
        return dns_types.get(qtype, f'TYPE{qtype}')
    
    def _build_bpf_filter(self) -> Optional[str]:
        """Build BPF filter string."""
        filters = []
        
        # If specific ports are configured, use those ports
        if self.capture_config.ports:
            port_filter = " or ".join([f"port {p}" for p in self.capture_config.ports])
            filters.append(f"({port_filter})")
            # Always include DNS (port 53) even when specific ports are configured
            if 53 not in self.capture_config.ports:
                filters.append("port 53")
        else:
            # If no ports specified, capture all traffic (DNS will be captured too)
            # Don't add any port filters - let it capture everything
            pass
        
        # Add custom BPF filter if specified (this overrides port filters)
        if self.capture_config.bpf_filter:
            return self.capture_config.bpf_filter
        
        # If we have port filters, combine them with OR
        if filters:
            return " or ".join(filters) if len(filters) > 1 else filters[0]
        
        # No filters = capture all traffic
        return None
    
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
            # Check if interface is specified and valid
            from scapy.all import get_if_list
            available_interfaces = get_if_list()
            
            if self.capture_config.interface:
                if self.capture_config.interface not in available_interfaces:
                    logger.error(f"Interface '{self.capture_config.interface}' not found!")
                    logger.info(f"Available interfaces: {', '.join(available_interfaces)}")
                    logger.warning(f"Attempting to use '{self.capture_config.interface}' anyway (may fail)")
                else:
                    logger.info(f"Using interface: {self.capture_config.interface}")
            else:
                logger.info(f"No interface specified, using default. Available: {', '.join(available_interfaces)}")
            
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
            logger.error(f"Error in packet capture loop: {e}", exc_info=True)
            self.running = False

