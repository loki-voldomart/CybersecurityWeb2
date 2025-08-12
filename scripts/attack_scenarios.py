#!/usr/bin/env python3
"""
Specific Attack Scenario Generators
Creates realistic attack patterns for cybersecurity training
"""

import asyncio
import aiohttp
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

class AttackScenarios:
    def __init__(self):
        self.api_base = 'http://localhost:3000/api'
    
    async def ddos_attack_scenario(self, session: aiohttp.ClientSession):
        """Simulate a coordinated DDoS attack"""
        print("🔥 Launching DDoS attack scenario...")
        
        # Multiple attacker IPs
        attacker_ips = [
            '203.0.113.67', '198.51.100.89', '192.0.2.123',
            '203.0.113.78', '198.51.100.45', '192.0.2.234'
        ]
        
        target_ip = '10.0.0.1'  # Web server
        
        # Create initial threat event
        threat_data = {
            'threat_type': 'dos',
            'severity': 'critical',
            'source_ip': attacker_ips[0],
            'target_ip': target_ip,
            'port': 80,
            'description': 'Coordinated DDoS attack detected - multiple source IPs',
            'status': 'active',
            'metadata': {
                'attack_type': 'volumetric',
                'attacker_count': len(attacker_ips),
                'target_service': 'web_server'
            }
        }
        
        async with session.post(f'{self.api_base}/threats', json=threat_data) as response:
            threat_id = (await response.json()).get('threat', {}).get('id')
        
        # Generate high-volume traffic from multiple IPs
        for _ in range(50):  # 50 packets per attacker
            for attacker_ip in attacker_ips:
                traffic_data = {
                    'source_ip': attacker_ip,
                    'destination_ip': target_ip,
                    'source_port': random.randint(1024, 65535),
                    'destination_port': 80,
                    'protocol': 'TCP',
                    'packet_size': 1500,
                    'threat_score': 0.95,
                    'is_suspicious': True,
                    'metadata': {
                        'traffic_type': 'ddos_attack',
                        'attack_vector': 'http_flood',
                        'threat_event_id': threat_id
                    }
                }
                
                await session.post(f'{self.api_base}/network-logs', json=traffic_data)
                await asyncio.sleep(0.01)  # Very fast packets
        
        print("✅ DDoS attack scenario completed")
    
    async def advanced_port_scan_scenario(self, session: aiohttp.ClientSession):
        """Simulate advanced port scanning techniques"""
        print("🔍 Launching advanced port scan scenario...")
        
        scanner_ip = '203.0.113.45'
        target_network = '10.0.0'
        
        # Create threat event
        threat_data = {
            'threat_type': 'port_scan',
            'severity': 'high',
            'source_ip': scanner_ip,
            'target_ip': f'{target_network}.0/24',
            'description': 'Advanced port scanning - stealth scan detected',
            'status': 'investigating',
            'metadata': {
                'scan_type': 'stealth_syn',
                'target_range': f'{target_network}.0/24'
            }
        }
        
        async with session.post(f'{self.api_base}/threats', json=threat_data) as response:
            threat_id = (await response.json()).get('threat', {}).get('id')
        
        # Scan multiple hosts and ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        for host_suffix in range(1, 20):  # Scan 19 hosts
            target_ip = f'{target_network}.{host_suffix}'
            
            for port in common_ports:
                traffic_data = {
                    'source_ip': scanner_ip,
                    'destination_ip': target_ip,
                    'source_port': random.randint(1024, 65535),
                    'destination_port': port,
                    'protocol': 'TCP',
                    'packet_size': 64,
                    'threat_score': 0.75,
                    'is_suspicious': True,
                    'metadata': {
                        'traffic_type': 'port_scan',
                        'scan_technique': 'syn_stealth',
                        'flags': 'SYN',
                        'threat_event_id': threat_id
                    }
                }
                
                await session.post(f'{self.api_base}/network-logs', json=traffic_data)
                await asyncio.sleep(0.2)  # Stealth timing
        
        print("✅ Port scan scenario completed")
    
    async def malware_infection_scenario(self, session: aiohttp.ClientSession):
        """Simulate malware infection and C2 communication"""
        print("🦠 Launching malware infection scenario...")
        
        infected_hosts = ['10.0.0.15', '10.0.0.23', '10.0.0.31']
        c2_servers = ['198.51.100.23', '203.0.113.89']
        
        # Create threat event
        threat_data = {
            'threat_type': 'malware',
            'severity': 'critical',
            'source_ip': infected_hosts[0],
            'target_ip': c2_servers[0],
            'port': 443,
            'description': 'Botnet C2 communication detected - multiple infected hosts',
            'status': 'active',
            'metadata': {
                'malware_family': 'banking_trojan',
                'infected_count': len(infected_hosts),
                'c2_servers': c2_servers
            }
        }
        
        async with session.post(f'{self.api_base}/threats', json=threat_data) as response:
            threat_id = (await response.json()).get('threat', {}).get('id')
        
        # Simulate C2 communication patterns
        for _ in range(30):  # 30 communication cycles
            for infected_ip in infected_hosts:
                c2_server = random.choice(c2_servers)
                
                # Outbound C2 communication
                traffic_data = {
                    'source_ip': infected_ip,
                    'destination_ip': c2_server,
                    'source_port': random.randint(1024, 65535),
                    'destination_port': random.choice([443, 8080, 53]),
                    'protocol': 'TCP',
                    'packet_size': random.randint(256, 1024),
                    'threat_score': 0.92,
                    'is_suspicious': True,
                    'metadata': {
                        'traffic_type': 'malware_c2',
                        'direction': 'outbound',
                        'encrypted': True,
                        'threat_event_id': threat_id
                    }
                }
                
                await session.post(f'{self.api_base}/network-logs', json=traffic_data)
                
                # Inbound C2 response
                response_data = {
                    'source_ip': c2_server,
                    'destination_ip': infected_ip,
                    'source_port': random.choice([443, 8080, 53]),
                    'destination_port': random.randint(1024, 65535),
                    'protocol': 'TCP',
                    'packet_size': random.randint(128, 512),
                    'threat_score': 0.88,
                    'is_suspicious': True,
                    'metadata': {
                        'traffic_type': 'malware_c2',
                        'direction': 'inbound',
                        'command_type': random.choice(['heartbeat', 'update', 'execute']),
                        'threat_event_id': threat_id
                    }
                }
                
                await session.post(f'{self.api_base}/network-logs', json=response_data)
                await asyncio.sleep(random.uniform(5, 15))  # Realistic C2 timing
        
        print("✅ Malware infection scenario completed")
    
    async def phishing_campaign_scenario(self, session: aiohttp.ClientSession):
        """Simulate phishing campaign with multiple victims"""
        print("🎣 Launching phishing campaign scenario...")
        
        phishing_domains = [
            '192.0.2.15',  # fake-bank-login.com
            '203.0.113.88', # secure-update-portal.com
            '198.51.100.77' # account-verification-center.com
        ]
        
        victim_ips = ['10.0.0.12', '10.0.0.18', '10.0.0.25', '10.0.0.33']
        
        # Create threat event
        threat_data = {
            'threat_type': 'phishing',
            'severity': 'high',
            'source_ip': phishing_domains[0],
            'description': 'Coordinated phishing campaign detected - multiple malicious domains',
            'status': 'active',
            'metadata': {
                'campaign_type': 'credential_harvesting',
                'target_count': len(victim_ips),
                'malicious_domains': len(phishing_domains)
            }
        }
        
        async with session.post(f'{self.api_base}/threats', json=threat_data) as response:
            threat_id = (await response.json()).get('threat', {}).get('id')
        
        # Simulate victims accessing phishing sites
        for victim_ip in victim_ips:
            for phishing_domain in phishing_domains:
                # Initial access
                traffic_data = {
                    'source_ip': victim_ip,
                    'destination_ip': phishing_domain,
                    'source_port': random.randint(1024, 65535),
                    'destination_port': 443,
                    'protocol': 'TCP',
                    'packet_size': random.randint(512, 1024),
                    'threat_score': 0.78,
                    'is_suspicious': True,
                    'metadata': {
                        'traffic_type': 'phishing_access',
                        'ssl_cert_suspicious': True,
                        'domain_age_days': random.randint(1, 30),
                        'threat_event_id': threat_id
                    }
                }
                
                await session.post(f'{self.api_base}/network-logs', json=traffic_data)
                
                # Credential submission (POST request)
                submit_data = {
                    'source_ip': victim_ip,
                    'destination_ip': phishing_domain,
                    'source_port': random.randint(1024, 65535),
                    'destination_port': 443,
                    'protocol': 'TCP',
                    'packet_size': random.randint(256, 512),
                    'threat_score': 0.85,
                    'is_suspicious': True,
                    'metadata': {
                        'traffic_type': 'credential_theft',
                        'http_method': 'POST',
                        'form_fields': ['username', 'password'],
                        'threat_event_id': threat_id
                    }
                }
                
                await session.post(f'{self.api_base}/network-logs', json=submit_data)
                await asyncio.sleep(random.uniform(2, 8))
        
        print("✅ Phishing campaign scenario completed")

async def run_attack_scenarios():
    """Run all attack scenarios"""
    scenarios = AttackScenarios()
    
    async with aiohttp.ClientSession() as session:
        print("🎯 Starting comprehensive attack scenarios...")
        
        # Run scenarios with delays between them
        await scenarios.ddos_attack_scenario(session)
        await asyncio.sleep(10)
        
        await scenarios.advanced_port_scan_scenario(session)
        await asyncio.sleep(10)
        
        await scenarios.malware_infection_scenario(session)
        await asyncio.sleep(10)
        
        await scenarios.phishing_campaign_scenario(session)
        
        print("🏁 All attack scenarios completed!")

if __name__ == "__main__":
    asyncio.run(run_attack_scenarios())
