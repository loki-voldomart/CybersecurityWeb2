#!/usr/bin/env python3
"""
Professional Network Packet Capture System
Real-time network monitoring with enterprise-grade capabilities
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import threading
import queue
import time
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import psutil
import netifaces
import socket
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProfessionalPacketCapture:
    """
    Enterprise-grade packet capture system for cybersecurity monitoring
    Supports real-time analysis, feature extraction, and threat detection
    """
    
    def __init__(self, interface: str = None, db_path: str = "network_data.db"):
        self.interface = interface or self._get_default_interface()
        self.db_path = db_path
        self.capture_active = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.analysis_thread = None
        self.capture_thread = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'suspicious_packets': 0,
            'start_time': None
        }
        
        # Initialize database
        self._init_database()
        
        # Network baseline for anomaly detection
        self.network_baseline = {
            'avg_packet_size': 0,
            'common_ports': set(),
            'normal_protocols': {'TCP', 'UDP', 'ICMP'},
            'connection_patterns': {}
        }
        
        logger.info(f"Packet capture initialized on interface: {self.interface}")

    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            return default_interface
        except:
            # Fallback to first available interface
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('docker'):
                    return iface
            return 'eth0'  # Final fallback

    def _init_database(self):
        """Initialize SQLite database for packet storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                flags TEXT,
                payload_size INTEGER,
                ttl INTEGER,
                window_size INTEGER,
                is_suspicious BOOLEAN,
                threat_score REAL,
                features TEXT
            )
        ''')
        
        # Create connections table for flow analysis
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                start_time REAL,
                end_time REAL,
                packet_count INTEGER,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                connection_state TEXT,
                is_suspicious BOOLEAN
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

    def start_capture(self, filter_expression: str = None):
        """Start professional packet capture with optional BPF filter"""
        if self.capture_active:
            logger.warning("Packet capture already active")
            return
        
        self.capture_active = True
        self.stats['start_time'] = time.time()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analyze_packets, daemon=True)
        self.analysis_thread.start()
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets, 
            args=(filter_expression,), 
            daemon=True
        )
        self.capture_thread.start()
        
        logger.info(f"Packet capture started on {self.interface}")
        if filter_expression:
            logger.info(f"Using filter: {filter_expression}")

    def stop_capture(self):
        """Stop packet capture and analysis"""
        self.capture_active = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        
        logger.info("Packet capture stopped")
        self._print_statistics()

    def _capture_packets(self, filter_expression: str = None):
        """Main packet capture loop using Scapy"""
        try:
            def packet_handler(packet):
                if not self.capture_active:
                    return
                
                try:
                    self.packet_queue.put(packet, timeout=1)
                    self.stats['total_packets'] += 1
                except queue.Full:
                    logger.warning("Packet queue full, dropping packet")
            
            # Start sniffing
            scapy.sniff(
                iface=self.interface,
                prn=packet_handler,
                filter=filter_expression,
                stop_filter=lambda x: not self.capture_active,
                store=False
            )
            
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.capture_active = False

    def _analyze_packets(self):
        """Analyze captured packets for threats and features"""
        connection_tracker = {}
        
        while self.capture_active or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                
                # Extract packet features
                features = self._extract_packet_features(packet)
                if not features:
                    continue
                
                # Update statistics
                self._update_statistics(features)
                
                # Track connections
                self._track_connection(features, connection_tracker)
                
                # Detect suspicious activity
                is_suspicious, threat_score = self._detect_suspicious_activity(features)
                
                # Store packet data
                self._store_packet_data(features, is_suspicious, threat_score)
                
                if is_suspicious:
                    self.stats['suspicious_packets'] += 1
                    logger.warning(f"Suspicious packet detected: {features['src_ip']}:{features['src_port']} -> {features['dst_ip']}:{features['dst_port']}")
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Packet analysis error: {e}")

    def _extract_packet_features(self, packet) -> Optional[Dict[str, Any]]:
        """Extract comprehensive features from network packet"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            features = {
                'timestamp': time.time(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'packet_size': len(packet),
                'ttl': ip_layer.ttl,
                'flags': 0,
                'src_port': 0,
                'dst_port': 0,
                'window_size': 0,
                'payload_size': 0
            }
            
            # TCP specific features
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                features.update({
                    'protocol': 'TCP',
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': tcp_layer.flags,
                    'window_size': tcp_layer.window,
                    'payload_size': len(tcp_layer.payload) if tcp_layer.payload else 0
                })
                self.stats['tcp_packets'] += 1
            
            # UDP specific features
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                features.update({
                    'protocol': 'UDP',
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'payload_size': len(udp_layer.payload) if udp_layer.payload else 0
                })
                self.stats['udp_packets'] += 1
            
            # ICMP specific features
            elif packet.haslayer(ICMP):
                features.update({
                    'protocol': 'ICMP',
                    'payload_size': len(packet[ICMP].payload) if packet[ICMP].payload else 0
                })
                self.stats['icmp_packets'] += 1
            
            # Additional network features
            features.update({
                'is_internal': self._is_internal_ip(features['src_ip']) and self._is_internal_ip(features['dst_ip']),
                'is_broadcast': features['dst_ip'].endswith('.255'),
                'is_multicast': features['dst_ip'].startswith('224.'),
                'packet_rate': self._calculate_packet_rate(features['src_ip']),
                'connection_count': self._get_connection_count(features['src_ip'])
            })
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return None

    def _detect_suspicious_activity(self, features: Dict[str, Any]) -> tuple[bool, float]:
        """Professional threat detection based on packet features"""
        threat_score = 0.0
        suspicious_indicators = []
        
        # Port scanning detection
        if self._detect_port_scanning(features):
            threat_score += 0.3
            suspicious_indicators.append("port_scanning")
        
        # DoS attack detection
        if self._detect_dos_patterns(features):
            threat_score += 0.4
            suspicious_indicators.append("dos_attack")
        
        # Unusual protocol usage
        if self._detect_protocol_anomalies(features):
            threat_score += 0.2
            suspicious_indicators.append("protocol_anomaly")
        
        # Suspicious payload patterns
        if self._detect_payload_anomalies(features):
            threat_score += 0.3
            suspicious_indicators.append("payload_anomaly")
        
        # Geographic anomalies
        if self._detect_geographic_anomalies(features):
            threat_score += 0.2
            suspicious_indicators.append("geographic_anomaly")
        
        # Time-based anomalies
        if self._detect_temporal_anomalies(features):
            threat_score += 0.1
            suspicious_indicators.append("temporal_anomaly")
        
        is_suspicious = threat_score > 0.3
        
        if is_suspicious:
            logger.info(f"Threat detected - Score: {threat_score:.2f}, Indicators: {suspicious_indicators}")
        
        return is_suspicious, min(threat_score, 1.0)

    def _detect_port_scanning(self, features: Dict[str, Any]) -> bool:
        """Detect port scanning patterns"""
        src_ip = features['src_ip']
        dst_port = features['dst_port']
        
        # Track unique destination ports per source IP
        if not hasattr(self, '_port_scan_tracker'):
            self._port_scan_tracker = {}
        
        if src_ip not in self._port_scan_tracker:
            self._port_scan_tracker[src_ip] = {
                'ports': set(),
                'first_seen': time.time(),
                'packet_count': 0
            }
        
        tracker = self._port_scan_tracker[src_ip]
        tracker['ports'].add(dst_port)
        tracker['packet_count'] += 1
        
        # Port scan indicators
        time_window = time.time() - tracker['first_seen']
        unique_ports = len(tracker['ports'])
        
        # Rapid port scanning detection
        if time_window < 60 and unique_ports > 20:  # 20+ ports in 1 minute
            return True
        
        # Sequential port scanning
        if unique_ports > 10 and tracker['packet_count'] / unique_ports < 2:  # Low packets per port
            return True
        
        return False

    def _detect_dos_patterns(self, features: Dict[str, Any]) -> bool:
        """Detect DoS attack patterns"""
        src_ip = features['src_ip']
        
        # Track packet rates per source IP
        if not hasattr(self, '_dos_tracker'):
            self._dos_tracker = {}
        
        current_time = time.time()
        
        if src_ip not in self._dos_tracker:
            self._dos_tracker[src_ip] = {
                'packet_times': [],
                'total_bytes': 0
            }
        
        tracker = self._dos_tracker[src_ip]
        tracker['packet_times'].append(current_time)
        tracker['total_bytes'] += features['packet_size']
        
        # Keep only last 60 seconds of data
        tracker['packet_times'] = [t for t in tracker['packet_times'] if current_time - t < 60]
        
        # DoS indicators
        packets_per_minute = len(tracker['packet_times'])
        
        # High packet rate (>1000 packets/minute from single IP)
        if packets_per_minute > 1000:
            return True
        
        # High bandwidth usage (>10MB/minute from single IP)
        if tracker['total_bytes'] > 10 * 1024 * 1024:
            return True
        
        return False

    def _detect_protocol_anomalies(self, features: Dict[str, Any]) -> bool:
        """Detect unusual protocol usage"""
        protocol = features['protocol']
        dst_port = features['dst_port']
        
        # Unusual protocol/port combinations
        suspicious_combinations = [
            ('TCP', 1433),  # SQL Server on non-server
            ('TCP', 3389),  # RDP from external
            ('UDP', 53),    # DNS from non-DNS server
            ('TCP', 22),    # SSH from unusual sources
        ]
        
        if (protocol, dst_port) in suspicious_combinations:
            if not self._is_internal_ip(features['src_ip']):
                return True
        
        # Unusual high ports
        if dst_port > 49152 and not features['is_internal']:
            return True
        
        return False

    def _detect_payload_anomalies(self, features: Dict[str, Any]) -> bool:
        """Detect suspicious payload patterns"""
        payload_size = features['payload_size']
        
        # Unusually large payloads
        if payload_size > 8192:  # >8KB payload
            return True
        
        # Zero-byte payloads in TCP (potential scanning)
        if features['protocol'] == 'TCP' and payload_size == 0:
            return True
        
        return False

    def _detect_geographic_anomalies(self, features: Dict[str, Any]) -> bool:
        """Detect geographic anomalies (simplified)"""
        src_ip = features['src_ip']
        
        # Check for known malicious IP ranges (simplified)
        malicious_ranges = [
            '10.0.0.',    # Internal network abuse
            '192.168.',   # Internal network from external
        ]
        
        for range_prefix in malicious_ranges:
            if src_ip.startswith(range_prefix) and not features['is_internal']:
                return True
        
        return False

    def _detect_temporal_anomalies(self, features: Dict[str, Any]) -> bool:
        """Detect time-based anomalies"""
        current_hour = datetime.now().hour
        
        # Activity during unusual hours (2 AM - 5 AM)
        if 2 <= current_hour <= 5:
            if not features['is_internal']:
                return True
        
        return False

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in internal network ranges"""
        internal_ranges = [
            '10.',
            '192.168.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '127.'
        ]
        
        return any(ip.startswith(prefix) for prefix in internal_ranges)

    def _calculate_packet_rate(self, src_ip: str) -> float:
        """Calculate packet rate for source IP"""
        if not hasattr(self, '_rate_tracker'):
            self._rate_tracker = {}
        
        current_time = time.time()
        
        if src_ip not in self._rate_tracker:
            self._rate_tracker[src_ip] = []
        
        self._rate_tracker[src_ip].append(current_time)
        
        # Keep only last 60 seconds
        self._rate_tracker[src_ip] = [
            t for t in self._rate_tracker[src_ip] 
            if current_time - t < 60
        ]
        
        return len(self._rate_tracker[src_ip]) / 60.0  # packets per second

    def _get_connection_count(self, src_ip: str) -> int:
        """Get active connection count for source IP"""
        if not hasattr(self, '_connection_tracker'):
            self._connection_tracker = {}
        
        return len(self._connection_tracker.get(src_ip, {}))

    def _track_connection(self, features: Dict[str, Any], tracker: Dict):
        """Track network connections for flow analysis"""
        if features['protocol'] not in ['TCP', 'UDP']:
            return
        
        connection_key = (
            features['src_ip'], features['dst_ip'],
            features['src_port'], features['dst_port'],
            features['protocol']
        )
        
        if connection_key not in tracker:
            tracker[connection_key] = {
                'start_time': features['timestamp'],
                'packet_count': 0,
                'bytes_total': 0,
                'last_seen': features['timestamp']
            }
        
        conn = tracker[connection_key]
        conn['packet_count'] += 1
        conn['bytes_total'] += features['packet_size']
        conn['last_seen'] = features['timestamp']

    def _update_statistics(self, features: Dict[str, Any]):
        """Update capture statistics"""
        # Update baseline
        if self.network_baseline['avg_packet_size'] == 0:
            self.network_baseline['avg_packet_size'] = features['packet_size']
        else:
            # Running average
            self.network_baseline['avg_packet_size'] = (
                self.network_baseline['avg_packet_size'] * 0.99 + 
                features['packet_size'] * 0.01
            )
        
        # Track common ports
        if features['dst_port'] > 0:
            self.network_baseline['common_ports'].add(features['dst_port'])

    def _store_packet_data(self, features: Dict[str, Any], is_suspicious: bool, threat_score: float):
        """Store packet data in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO packets (
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                    packet_size, flags, payload_size, ttl, window_size,
                    is_suspicious, threat_score, features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                features['timestamp'], features['src_ip'], features['dst_ip'],
                features['src_port'], features['dst_port'], features['protocol'],
                features['packet_size'], str(features['flags']), features['payload_size'],
                features['ttl'], features['window_size'], is_suspicious, threat_score,
                json.dumps(features)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Database storage error: {e}")

    def _print_statistics(self):
        """Print capture statistics"""
        if self.stats['start_time']:
            duration = time.time() - self.stats['start_time']
            pps = self.stats['total_packets'] / duration if duration > 0 else 0
            
            print("\n" + "="*50)
            print("PACKET CAPTURE STATISTICS")
            print("="*50)
            print(f"Duration: {duration:.2f} seconds")
            print(f"Total packets: {self.stats['total_packets']}")
            print(f"Packets per second: {pps:.2f}")
            print(f"TCP packets: {self.stats['tcp_packets']}")
            print(f"UDP packets: {self.stats['udp_packets']}")
            print(f"ICMP packets: {self.stats['icmp_packets']}")
            print(f"Suspicious packets: {self.stats['suspicious_packets']}")
            print(f"Threat detection rate: {(self.stats['suspicious_packets']/self.stats['total_packets']*100):.2f}%")
            print("="*50)

    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time statistics for dashboard"""
        duration = time.time() - self.stats['start_time'] if self.stats['start_time'] else 1
        
        return {
            'total_packets': self.stats['total_packets'],
            'packets_per_second': self.stats['total_packets'] / duration,
            'tcp_packets': self.stats['tcp_packets'],
            'udp_packets': self.stats['udp_packets'],
            'icmp_packets': self.stats['icmp_packets'],
            'suspicious_packets': self.stats['suspicious_packets'],
            'threat_rate': (self.stats['suspicious_packets'] / max(self.stats['total_packets'], 1)) * 100,
            'capture_active': self.capture_active,
            'interface': self.interface,
            'avg_packet_size': self.network_baseline['avg_packet_size']
        }
