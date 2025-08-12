"""
Specialized Detection Agents for Different Attack Types
Professional threat detection with specialized expertise
"""

import numpy as np
import time
import sqlite3
from typing import Dict, List, Any, Optional
from agents.base_agent import BaseSecurityAgent, AgentMessage, MessageType, AgentStatus
import logging

logger = logging.getLogger(__name__)

class DoSDetectionAgent(BaseSecurityAgent):
    """
    Specialized agent for Denial of Service attack detection
    Uses advanced algorithms and behavioral analysis
    """
    
    def __init__(self, agent_id: str = "dos_detector"):
        super().__init__(agent_id, "DoS Detection Agent")
        
        # DoS-specific configuration
        self.dos_config = {
            'packet_rate_threshold': 1000,  # packets per minute
            'bandwidth_threshold': 10 * 1024 * 1024,  # 10MB per minute
            'connection_threshold': 500,  # connections per minute
            'time_window': 60,  # analysis window in seconds
            'confidence_threshold': 0.8
        }
        
        # Tracking data structures
        self.ip_tracking = {}
        self.connection_tracking = {}
        self.bandwidth_tracking = {}
        
        logger.info("DoS Detection Agent initialized")

    def _do_work(self):
        """Main DoS detection work"""
        try:
            # Analyze recent network data
            suspicious_ips = self._analyze_traffic_patterns()
            
            for ip_data in suspicious_ips:
                threat_message = AgentMessage(
                    sender_id=self.agent_id,
                    receiver_id="coordinator",
                    message_type=MessageType.THREAT_DETECTED,
                    payload={
                        'threat_type': 'dos',
                        'source_ip': ip_data['ip'],
                        'confidence': ip_data['confidence'],
                        'severity': ip_data['severity'],
                        'evidence': ip_data['evidence'],
                        'recommended_action': 'block_ip'
                    },
                    timestamp=time.time(),
                    priority=4  # Critical priority
                )
                
                self.send_message(threat_message)
                self.stats['threats_detected'] += 1
                
                logger.warning(f"DoS attack detected from {ip_data['ip']} (confidence: {ip_data['confidence']:.2f})")
        
        except Exception as e:
            logger.error(f"DoS detection error: {e}")

    def _analyze_traffic_patterns(self) -> List[Dict[str, Any]]:
        """Analyze traffic patterns for DoS indicators"""
        suspicious_ips = []
        current_time = time.time()
        
        # Clean old tracking data
        self._cleanup_old_data(current_time)
        
        # Analyze each tracked IP
        for ip, data in self.ip_tracking.items():
            confidence = 0.0
            evidence = []
            
            # Check packet rate
            packet_rate = len(data.get('packet_times', []))
            if packet_rate > self.dos_config['packet_rate_threshold']:
                confidence += 0.4
                evidence.append(f"High packet rate: {packet_rate}/min")
            
            # Check bandwidth usage
            bandwidth = self.bandwidth_tracking.get(ip, {}).get('total_bytes', 0)
            if bandwidth > self.dos_config['bandwidth_threshold']:
                confidence += 0.3
                evidence.append(f"High bandwidth: {bandwidth/1024/1024:.1f}MB/min")
            
            # Check connection patterns
            connections = len(self.connection_tracking.get(ip, {}))
            if connections > self.dos_config['connection_threshold']:
                confidence += 0.3
                evidence.append(f"High connection count: {connections}")
            
            # Determine severity
            if confidence >= 0.9:
                severity = 'critical'
            elif confidence >= 0.7:
                severity = 'high'
            elif confidence >= 0.5:
                severity = 'medium'
            else:
                severity = 'low'
            
            if confidence >= self.dos_config['confidence_threshold']:
                suspicious_ips.append({
                    'ip': ip,
                    'confidence': confidence,
                    'severity': severity,
                    'evidence': evidence
                })
        
        return suspicious_ips

    def _cleanup_old_data(self, current_time: float):
        """Clean up old tracking data"""
        cutoff_time = current_time - self.dos_config['time_window']
        
        # Clean packet times
        for ip in list(self.ip_tracking.keys()):
            if 'packet_times' in self.ip_tracking[ip]:
                self.ip_tracking[ip]['packet_times'] = [
                    t for t in self.ip_tracking[ip]['packet_times'] 
                    if t > cutoff_time
                ]
                
                if not self.ip_tracking[ip]['packet_times']:
                    del self.ip_tracking[ip]

    def handle_custom_message(self, message: AgentMessage):
        """Handle DoS-specific messages"""
        if message.message_type == MessageType.ANALYSIS_REQUEST:
            payload = message.payload
            
            if 'packet_data' in payload:
                self._process_packet_data(payload['packet_data'])

    def _process_packet_data(self, packet_data: Dict[str, Any]):
        """Process individual packet data for DoS analysis"""
        src_ip = packet_data.get('src_ip')
        if not src_ip:
            return
        
        current_time = time.time()
        
        # Initialize tracking for new IPs
        if src_ip not in self.ip_tracking:
            self.ip_tracking[src_ip] = {
                'packet_times': [],
                'first_seen': current_time
            }
        
        if src_ip not in self.bandwidth_tracking:
            self.bandwidth_tracking[src_ip] = {
                'total_bytes': 0,
                'last_reset': current_time
            }
        
        # Update tracking data
        self.ip_tracking[src_ip]['packet_times'].append(current_time)
        self.bandwidth_tracking[src_ip]['total_bytes'] += packet_data.get('packet_size', 0)
        
        # Track connections
        connection_key = f"{src_ip}:{packet_data.get('dst_port', 0)}"
        if src_ip not in self.connection_tracking:
            self.connection_tracking[src_ip] = {}
        self.connection_tracking[src_ip][connection_key] = current_time

class PortScanDetectionAgent(BaseSecurityAgent):
    """
    Specialized agent for port scanning detection
    Identifies reconnaissance and scanning activities
    """
    
    def __init__(self, agent_id: str = "port_scan_detector"):
        super().__init__(agent_id, "Port Scan Detection Agent")
        
        # Port scan specific configuration
        self.scan_config = {
            'port_threshold': 20,  # unique ports accessed
            'time_window': 300,    # 5 minutes
            'sequential_threshold': 10,  # sequential ports
            'failed_connection_ratio': 0.8,
            'confidence_threshold': 0.7
        }
        
        # Tracking structures
        self.port_access_tracking = {}
        self.connection_attempts = {}
        
        logger.info("Port Scan Detection Agent initialized")

    def _do_work(self):
        """Main port scan detection work"""
        try:
            suspicious_scanners = self._analyze_port_patterns()
            
            for scanner_data in suspicious_scanners:
                threat_message = AgentMessage(
                    sender_id=self.agent_id,
                    receiver_id="coordinator",
                    message_type=MessageType.THREAT_DETECTED,
                    payload={
                        'threat_type': 'port_scan',
                        'source_ip': scanner_data['ip'],
                        'confidence': scanner_data['confidence'],
                        'severity': scanner_data['severity'],
                        'evidence': scanner_data['evidence'],
                        'scan_type': scanner_data['scan_type'],
                        'recommended_action': 'monitor_and_log'
                    },
                    timestamp=time.time(),
                    priority=3  # High priority
                )
                
                self.send_message(threat_message)
                self.stats['threats_detected'] += 1
                
                logger.warning(f"Port scan detected from {scanner_data['ip']} (type: {scanner_data['scan_type']})")
        
        except Exception as e:
            logger.error(f"Port scan detection error: {e}")

    def _analyze_port_patterns(self) -> List[Dict[str, Any]]:
        """Analyze port access patterns for scanning behavior"""
        suspicious_scanners = []
        current_time = time.time()
        
        # Clean old data
        self._cleanup_scan_data(current_time)
        
        for ip, access_data in self.port_access_tracking.items():
            confidence = 0.0
            evidence = []
            scan_type = "unknown"
            
            unique_ports = len(access_data.get('ports', set()))
            total_attempts = access_data.get('total_attempts', 0)
            failed_attempts = access_data.get('failed_attempts', 0)
            
            # Check for high port diversity
            if unique_ports > self.scan_config['port_threshold']:
                confidence += 0.4
                evidence.append(f"High port diversity: {unique_ports} unique ports")
                scan_type = "horizontal_scan"
            
            # Check for sequential port access
            if self._detect_sequential_scanning(access_data.get('ports', set())):
                confidence += 0.3
                evidence.append("Sequential port scanning detected")
                scan_type = "sequential_scan"
            
            # Check failed connection ratio
            if total_attempts > 0:
                fail_ratio = failed_attempts / total_attempts
                if fail_ratio > self.scan_config['failed_connection_ratio']:
                    confidence += 0.3
                    evidence.append(f"High failure rate: {fail_ratio:.1%}")
            
            # Check for stealth scanning patterns
            if self._detect_stealth_patterns(access_data):
                confidence += 0.2
                evidence.append("Stealth scanning patterns detected")
                scan_type = "stealth_scan"
            
            # Determine severity
            if confidence >= 0.9:
                severity = 'critical'
            elif confidence >= 0.7:
                severity = 'high'
            elif confidence >= 0.5:
                severity = 'medium'
            else:
                severity = 'low'
            
            if confidence >= self.scan_config['confidence_threshold']:
                suspicious_scanners.append({
                    'ip': ip,
                    'confidence': confidence,
                    'severity': severity,
                    'evidence': evidence,
                    'scan_type': scan_type
                })
        
        return suspicious_scanners

    def _detect_sequential_scanning(self, ports: set) -> bool:
        """Detect sequential port scanning patterns"""
        if len(ports) < self.scan_config['sequential_threshold']:
            return False
        
        sorted_ports = sorted(ports)
        sequential_count = 0
        
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] - sorted_ports[i-1] == 1:
                sequential_count += 1
            else:
                sequential_count = 0
            
            if sequential_count >= self.scan_config['sequential_threshold']:
                return True
        
        return False

    def _detect_stealth_patterns(self, access_data: Dict) -> bool:
        """Detect stealth scanning patterns"""
        # Check for low-frequency, distributed scanning
        timestamps = access_data.get('timestamps', [])
        if len(timestamps) < 10:
            return False
        
        # Calculate time intervals between accesses
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i-1])
        
        # Stealth pattern: consistent timing intervals
        if len(intervals) > 5:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # Low variance indicates systematic scanning
            if variance < avg_interval * 0.1:
                return True
        
        return False

    def _cleanup_scan_data(self, current_time: float):
        """Clean up old scanning data"""
        cutoff_time = current_time - self.scan_config['time_window']
        
        for ip in list(self.port_access_tracking.keys()):
            if 'timestamps' in self.port_access_tracking[ip]:
                old_timestamps = self.port_access_tracking[ip]['timestamps']
                new_timestamps = [t for t in old_timestamps if t > cutoff_time]
                
                if not new_timestamps:
                    del self.port_access_tracking[ip]
                else:
                    self.port_access_tracking[ip]['timestamps'] = new_timestamps

    def handle_custom_message(self, message: AgentMessage):
        """Handle port scan specific messages"""
        if message.message_type == MessageType.ANALYSIS_REQUEST:
            payload = message.payload
            
            if 'connection_data' in payload:
                self._process_connection_data(payload['connection_data'])

    def _process_connection_data(self, connection_data: Dict[str, Any]):
        """Process connection data for port scan analysis"""
        src_ip = connection_data.get('src_ip')
        dst_port = connection_data.get('dst_port')
        success = connection_data.get('success', False)
        
        if not src_ip or not dst_port:
            return
        
        current_time = time.time()
        
        # Initialize tracking
        if src_ip not in self.port_access_tracking:
            self.port_access_tracking[src_ip] = {
                'ports': set(),
                'timestamps': [],
                'total_attempts': 0,
                'failed_attempts': 0
            }
        
        # Update tracking
        tracking = self.port_access_tracking[src_ip]
        tracking['ports'].add(dst_port)
        tracking['timestamps'].append(current_time)
        tracking['total_attempts'] += 1
        
        if not success:
            tracking['failed_attempts'] += 1

class MalwareDetectionAgent(BaseSecurityAgent):
    """
    Specialized agent for malware detection
    Analyzes payload patterns and behavioral indicators
    """
    
    def __init__(self, agent_id: str = "malware_detector"):
        super().__init__(agent_id, "Malware Detection Agent")
        
        # Malware detection configuration
        self.malware_config = {
            'payload_size_threshold': 8192,
            'suspicious_patterns': [
                b'exec', b'eval', b'system', b'shell',
                b'cmd.exe', b'powershell', b'/bin/sh'
            ],
            'entropy_threshold': 7.5,  # High entropy indicates encryption/packing
            'confidence_threshold': 0.6
        }
        
        # Known malware signatures (simplified)
        self.malware_signatures = {
            'trojan_generic': [b'\x4d\x5a\x90\x00', b'\x50\x45\x00\x00'],
            'script_injection': [b'<script>', b'javascript:', b'eval('],
            'shell_code': [b'\x90\x90\x90\x90', b'\xcc\xcc\xcc\xcc']
        }
        
        logger.info("Malware Detection Agent initialized")

    def _do_work(self):
        """Main malware detection work"""
        try:
            # This would typically analyze file uploads, email attachments, etc.
            # For now, we'll focus on network payload analysis
            pass
        except Exception as e:
            logger.error(f"Malware detection error: {e}")

    def handle_custom_message(self, message: AgentMessage):
        """Handle malware-specific messages"""
        if message.message_type == MessageType.ANALYSIS_REQUEST:
            payload = message.payload
            
            if 'payload_data' in payload:
                result = self._analyze_payload(payload['payload_data'])
                if result['is_malicious']:
                    self._report_malware(result)

    def _analyze_payload(self, payload_data: bytes) -> Dict[str, Any]:
        """Analyze payload for malware indicators"""
        confidence = 0.0
        evidence = []
        malware_type = "unknown"
        
        # Check payload size
        if len(payload_data) > self.malware_config['payload_size_threshold']:
            confidence += 0.2
            evidence.append(f"Large payload: {len(payload_data)} bytes")
        
        # Check for suspicious patterns
        for pattern in self.malware_config['suspicious_patterns']:
            if pattern in payload_data:
                confidence += 0.3
                evidence.append(f"Suspicious pattern found: {pattern.decode('utf-8', errors='ignore')}")
        
        # Check malware signatures
        for malware_name, signatures in self.malware_signatures.items():
            for signature in signatures:
                if signature in payload_data:
                    confidence += 0.5
                    evidence.append(f"Malware signature detected: {malware_name}")
                    malware_type = malware_name
                    break
        
        # Calculate entropy (simplified)
        entropy = self._calculate_entropy(payload_data)
        if entropy > self.malware_config['entropy_threshold']:
            confidence += 0.2
            evidence.append(f"High entropy: {entropy:.2f}")
        
        return {
            'is_malicious': confidence >= self.malware_config['confidence_threshold'],
            'confidence': confidence,
            'evidence': evidence,
            'malware_type': malware_type,
            'payload_size': len(payload_data),
            'entropy': entropy
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy

    def _report_malware(self, analysis_result: Dict[str, Any]):
        """Report detected malware to coordinator"""
        threat_message = AgentMessage(
            sender_id=self.agent_id,
            receiver_id="coordinator",
            message_type=MessageType.THREAT_DETECTED,
            payload={
                'threat_type': 'malware',
                'malware_type': analysis_result['malware_type'],
                'confidence': analysis_result['confidence'],
                'severity': 'critical',
                'evidence': analysis_result['evidence'],
                'recommended_action': 'quarantine_and_alert'
            },
            timestamp=time.time(),
            priority=4  # Critical priority
        )
        
        self.send_message(threat_message)
        self.stats['threats_detected'] += 1
        
        logger.critical(f"Malware detected: {analysis_result['malware_type']} (confidence: {analysis_result['confidence']:.2f})")

class PhishingDetectionAgent(BaseSecurityAgent):
    """
    Specialized agent for phishing detection
    Analyzes URLs, email content, and social engineering patterns
    """
    
    def __init__(self, agent_id: str = "phishing_detector"):
        super().__init__(agent_id, "Phishing Detection Agent")
        
        # Phishing detection configuration
        self.phishing_config = {
            'suspicious_domains': [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co'  # URL shorteners
            ],
            'suspicious_keywords': [
                'urgent', 'verify', 'suspended', 'click here',
                'limited time', 'act now', 'confirm identity'
            ],
            'confidence_threshold': 0.6
        }
        
        # Known phishing patterns
        self.phishing_patterns = {
            'domain_spoofing': [
                'paypaI.com', 'arnazon.com', 'microsft.com',  # Typosquatting
                'secure-bank.net', 'verify-account.org'
            ],
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf'],
            'ip_addresses': True  # URLs with IP addresses instead of domains
        }
        
        logger.info("Phishing Detection Agent initialized")

    def _do_work(self):
        """Main phishing detection work"""
        try:
            # This would typically analyze emails, web requests, etc.
            # Implementation would depend on data sources
            pass
        except Exception as e:
            logger.error(f"Phishing detection error: {e}")

    def handle_custom_message(self, message: AgentMessage):
        """Handle phishing-specific messages"""
        if message.message_type == MessageType.ANALYSIS_REQUEST:
            payload = message.payload
            
            if 'url_data' in payload:
                result = self._analyze_url(payload['url_data'])
                if result['is_phishing']:
                    self._report_phishing(result)
            
            elif 'email_data' in payload:
                result = self._analyze_email(payload['email_data'])
                if result['is_phishing']:
                    self._report_phishing(result)

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for phishing indicators"""
        confidence = 0.0
        evidence = []
        
        # Check for suspicious domains
        for domain in self.phishing_config['suspicious_domains']:
            if domain in url:
                confidence += 0.3
                evidence.append(f"Suspicious domain: {domain}")
        
        # Check for domain spoofing
        for spoofed_domain in self.phishing_patterns['domain_spoofing']:
            if spoofed_domain in url:
                confidence += 0.5
                evidence.append(f"Domain spoofing detected: {spoofed_domain}")
        
        # Check for suspicious TLDs
        for tld in self.phishing_patterns['suspicious_tlds']:
            if url.endswith(tld):
                confidence += 0.2
                evidence.append(f"Suspicious TLD: {tld}")
        
        # Check for IP addresses instead of domains
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, url):
            confidence += 0.4
            evidence.append("IP address used instead of domain")
        
        return {
            'is_phishing': confidence >= self.phishing_config['confidence_threshold'],
            'confidence': confidence,
            'evidence': evidence,
            'url': url
        }

    def _analyze_email(self, email_content: str) -> Dict[str, Any]:
        """Analyze email content for phishing indicators"""
        confidence = 0.0
        evidence = []
        
        # Check for suspicious keywords
        email_lower = email_content.lower()
        for keyword in self.phishing_config['suspicious_keywords']:
            if keyword in email_lower:
                confidence += 0.2
                evidence.append(f"Suspicious keyword: {keyword}")
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediate', 'expires', 'deadline']
        urgency_count = sum(1 for word in urgency_words if word in email_lower)
        if urgency_count >= 2:
            confidence += 0.3
            evidence.append("Multiple urgency indicators")
        
        return {
            'is_phishing': confidence >= self.phishing_config['confidence_threshold'],
            'confidence': confidence,
            'evidence': evidence
        }

    def _report_phishing(self, analysis_result: Dict[str, Any]):
        """Report detected phishing to coordinator"""
        threat_message = AgentMessage(
            sender_id=self.agent_id,
            receiver_id="coordinator",
            message_type=MessageType.THREAT_DETECTED,
            payload={
                'threat_type': 'phishing',
                'confidence': analysis_result['confidence'],
                'severity': 'high',
                'evidence': analysis_result['evidence'],
                'recommended_action': 'block_and_warn'
            },
            timestamp=time.time(),
            priority=3  # High priority
        )
        
        self.send_message(threat_message)
        self.stats['threats_detected'] += 1
        
        logger.warning(f"Phishing attempt detected (confidence: {analysis_result['confidence']:.2f})")
