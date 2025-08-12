#!/usr/bin/env python3
"""
Network Traffic Simulator for Cybersecurity Platform
Generates realistic network traffic patterns and attack scenarios
"""

import random
import time
import json
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Any
import asyncio
import aiohttp
import os

class NetworkTrafficSimulator:
    def __init__(self):
        self.internal_networks = [
            ipaddress.IPv4Network('10.0.0.0/24'),
            ipaddress.IPv4Network('192.168.1.0/24'),
        ]
        
        self.external_ips = [
            '203.0.113.45',   # Suspicious scanner
            '198.51.100.23',  # Malware source
            '192.0.2.15',     # Phishing source
            '203.0.113.67',   # DDoS attacker
            '8.8.8.8',        # Legitimate DNS
            '1.1.1.1',        # Legitimate DNS
        ]
        
        self.common_ports = {
            'web': [80, 443, 8080, 8443],
            'mail': [25, 587, 993, 995],
            'ssh': [22],
            'dns': [53],
            'ftp': [21, 22],
            'database': [3306, 5432, 1433, 27017],
            'high_ports': list(range(1024, 65535))
        }
        
        self.protocols = ['TCP', 'UDP', 'ICMP']
        
    def generate_internal_ip(self) -> str:
        """Generate random internal IP address"""
        network = random.choice(self.internal_networks)
        return str(network.network_address + random.randint(1, network.num_addresses - 2))
    
    def generate_normal_traffic(self) -> Dict[str, Any]:
        """Generate normal network traffic"""
        source_ip = self.generate_internal_ip()
        dest_ip = random.choice(['8.8.8.8', '1.1.1.1', '172.217.164.110'])  # Google services
        
        return {
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'source_port': random.randint(1024, 65535),
            'destination_port': random.choice(self.common_ports['web'] + self.common_ports['dns']),
            'protocol': random.choice(['TCP', 'UDP']),
            'packet_size': random.randint(64, 1500),
            'threat_score': round(random.uniform(0.0, 0.3), 2),
            'is_suspicious': False,
            'metadata': {
                'traffic_type': 'normal',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        }
    
    def generate_dos_attack(self) -> Dict[str, Any]:
        """Generate DoS attack traffic"""
        attacker_ip = random.choice(['203.0.113.67', '198.51.100.89', '192.0.2.123'])
        target_ip = self.generate_internal_ip()
        
        return {
            'source_ip': attacker_ip,
            'destination_ip': target_ip,
            'source_port': random.randint(1024, 65535),
            'destination_port': random.choice(self.common_ports['web']),
            'protocol': 'TCP',
            'packet_size': random.randint(1400, 1500),  # Large packets
            'threat_score': round(random.uniform(0.7, 0.95), 2),
            'is_suspicious': True,
            'metadata': {
                'traffic_type': 'dos_attack',
                'attack_pattern': 'high_volume',
                'requests_per_second': random.randint(100, 1000)
            }
        }
    
    def generate_port_scan(self) -> Dict[str, Any]:
        """Generate port scanning traffic"""
        scanner_ip = '203.0.113.45'
        target_ip = self.generate_internal_ip()
        
        return {
            'source_ip': scanner_ip,
            'destination_ip': target_ip,
            'source_port': random.randint(1024, 65535),
            'destination_port': random.randint(1, 65535),
            'protocol': 'TCP',
            'packet_size': 64,  # Small SYN packets
            'threat_score': round(random.uniform(0.6, 0.8), 2),
            'is_suspicious': True,
            'metadata': {
                'traffic_type': 'port_scan',
                'scan_type': 'sequential',
                'flags': 'SYN'
            }
        }
    
    def generate_malware_traffic(self) -> Dict[str, Any]:
        """Generate malware communication traffic"""
        infected_ip = self.generate_internal_ip()
        c2_server = '198.51.100.23'
        
        return {
            'source_ip': infected_ip,
            'destination_ip': c2_server,
            'source_port': random.randint(1024, 65535),
            'destination_port': random.choice([443, 8080, 53]),  # Common C2 ports
            'protocol': random.choice(['TCP', 'UDP']),
            'packet_size': random.randint(128, 2048),
            'threat_score': round(random.uniform(0.8, 0.98), 2),
            'is_suspicious': True,
            'metadata': {
                'traffic_type': 'malware',
                'malware_family': random.choice(['trojan', 'botnet', 'ransomware']),
                'encrypted': True
            }
        }
    
    def generate_phishing_traffic(self) -> Dict[str, Any]:
        """Generate phishing-related traffic"""
        victim_ip = self.generate_internal_ip()
        phishing_server = '192.0.2.15'
        
        return {
            'source_ip': victim_ip,
            'destination_ip': phishing_server,
            'source_port': random.randint(1024, 65535),
            'destination_port': 443,
            'protocol': 'TCP',
            'packet_size': random.randint(512, 1024),
            'threat_score': round(random.uniform(0.65, 0.85), 2),
            'is_suspicious': True,
            'metadata': {
                'traffic_type': 'phishing',
                'domain': 'fake-bank-login.com',
                'ssl_cert_suspicious': True
            }
        }
    
    async def send_to_api(self, session: aiohttp.ClientSession, data: Dict[str, Any]):
        """Send network log data to the API"""
        try:
            async with session.post('http://localhost:3000/api/network-logs', json=data) as response:
                if response.status == 201:
                    print(f"✓ Sent {data['metadata']['traffic_type']} traffic log")
                else:
                    print(f"✗ Failed to send log: {response.status}")
        except Exception as e:
            print(f"✗ Error sending to API: {e}")
    
    async def generate_threat_event(self, session: aiohttp.ClientSession, traffic_type: str):
        """Generate corresponding threat event for suspicious traffic"""
        threat_events = {
            'dos_attack': {
                'threat_type': 'dos',
                'severity': random.choice(['high', 'critical']),
                'source_ip': '203.0.113.67',
                'target_ip': self.generate_internal_ip(),
                'port': 80,
                'description': 'High volume DoS attack detected from external IP',
                'status': 'active'
            },
            'port_scan': {
                'threat_type': 'port_scan',
                'severity': 'medium',
                'source_ip': '203.0.113.45',
                'target_ip': self.generate_internal_ip(),
                'description': 'Sequential port scanning activity detected',
                'status': 'investigating'
            },
            'malware': {
                'threat_type': 'malware',
                'severity': 'critical',
                'source_ip': self.generate_internal_ip(),
                'target_ip': '198.51.100.23',
                'port': 443,
                'description': 'Malware C2 communication detected',
                'status': 'blocked'
            },
            'phishing': {
                'threat_type': 'phishing',
                'severity': 'medium',
                'source_ip': '192.0.2.15',
                'target_ip': self.generate_internal_ip(),
                'port': 443,
                'description': 'Phishing attempt detected - suspicious domain access',
                'status': 'active'
            }
        }
        
        if traffic_type in threat_events:
            try:
                async with session.post('http://localhost:3000/api/threats', json=threat_events[traffic_type]) as response:
                    if response.status == 201:
                        print(f"✓ Created {traffic_type} threat event")
            except Exception as e:
                print(f"✗ Error creating threat event: {e}")
    
    async def simulate_traffic(self, duration_minutes: int = 60):
        """Main simulation loop"""
        print(f"🚀 Starting network traffic simulation for {duration_minutes} minutes...")
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        async with aiohttp.ClientSession() as session:
            while datetime.now() < end_time:
                # Generate traffic based on weighted probabilities
                traffic_type = random.choices(
                    ['normal', 'dos_attack', 'port_scan', 'malware', 'phishing'],
                    weights=[70, 8, 10, 7, 5],  # 70% normal, 30% threats
                    k=1
                )[0]
                
                # Generate appropriate traffic
                if traffic_type == 'normal':
                    traffic_data = self.generate_normal_traffic()
                elif traffic_type == 'dos_attack':
                    traffic_data = self.generate_dos_attack()
                elif traffic_type == 'port_scan':
                    traffic_data = self.generate_port_scan()
                elif traffic_type == 'malware':
                    traffic_data = self.generate_malware_traffic()
                elif traffic_type == 'phishing':
                    traffic_data = self.generate_phishing_traffic()
                
                # Send network log
                await self.send_to_api(session, traffic_data)
                
                # Generate threat event for suspicious traffic (occasionally)
                if traffic_type != 'normal' and random.random() < 0.3:
                    await self.generate_threat_event(session, traffic_type)
                
                # Wait between packets (simulate realistic timing)
                if traffic_type == 'dos_attack':
                    await asyncio.sleep(random.uniform(0.01, 0.1))  # Fast DoS packets
                elif traffic_type == 'port_scan':
                    await asyncio.sleep(random.uniform(0.1, 0.5))   # Sequential scanning
                else:
                    await asyncio.sleep(random.uniform(0.5, 3.0))   # Normal traffic
        
        print("✅ Network traffic simulation completed!")

async def main():
    simulator = NetworkTrafficSimulator()
    
    # Run simulation for 30 minutes by default
    duration = int(os.getenv('SIMULATION_DURATION', 30))
    await simulator.simulate_traffic(duration)

if __name__ == "__main__":
    asyncio.run(main())
