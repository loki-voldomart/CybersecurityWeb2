"""
Professional Attack Orchestration System
Coordinates multiple attack scenarios and manages red team operations
"""

import time
import threading
import random
from typing import Dict, List, Any, Optional
from attack_simulation.attack_framework import (
    BaseAttackSimulator, AttackScenario, AttackType, AttackStatus,
    DoSAttackSimulator, PortScanSimulator, MalwareSimulator, PhishingSimulator
)
import logging
import json
import sqlite3

logger = logging.getLogger(__name__)

class AttackOrchestrator:
    """
    Professional attack orchestration system
    Manages coordinated multi-vector attacks and red team scenarios
    """
    
    def __init__(self):
        # Initialize attack simulators
        self.simulators = {
            AttackType.DOS: DoSAttackSimulator(),
            AttackType.PORT_SCAN: PortScanSimulator(),
            AttackType.MALWARE: MalwareSimulator(),
            AttackType.PHISHING: PhishingSimulator()
        }
        
        # Orchestration state
        self.active_scenarios = {}
        self.scenario_queue = []
        self.orchestration_stats = {
            'total_scenarios': 0,
            'completed_scenarios': 0,
            'failed_scenarios': 0,
            'start_time': time.time()
        }
        
        # Orchestration thread
        self.orchestration_active = False
        self.orchestration_thread = None
        
        # Database
        self.db_path = "attack_orchestration.db"
        self._init_database()
        
        logger.info("Attack Orchestrator initialized")

    def _init_database(self):
        """Initialize orchestration database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orchestration_campaigns (
                campaign_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                target_network TEXT,
                start_time REAL,
                end_time REAL,
                status TEXT,
                scenarios TEXT,
                results TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def start_orchestration(self):
        """Start attack orchestration engine"""
        if self.orchestration_active:
            logger.warning("Attack orchestration already active")
            return
        
        self.orchestration_active = True
        self.orchestration_thread = threading.Thread(target=self._orchestration_loop, daemon=True)
        self.orchestration_thread.start()
        
        logger.info("Attack orchestration started")

    def stop_orchestration(self):
        """Stop attack orchestration"""
        self.orchestration_active = False
        
        # Stop all active scenarios
        for scenario_id in list(self.active_scenarios.keys()):
            self.stop_scenario(scenario_id)
        
        if self.orchestration_thread:
            self.orchestration_thread.join(timeout=5)
        
        logger.info("Attack orchestration stopped")

    def create_attack_scenario(self, 
                             attack_type: AttackType,
                             target_ip: str,
                             target_ports: List[int],
                             duration: int,
                             intensity: str = "medium",
                             parameters: Dict[str, Any] = None) -> str:
        """Create new attack scenario"""
        
        scenario_id = f"{attack_type.value}_{int(time.time())}_{random.randint(1000, 9999)}"
        
        scenario = AttackScenario(
            scenario_id=scenario_id,
            attack_type=attack_type,
            target_ip=target_ip,
            target_ports=target_ports,
            duration=duration,
            intensity=intensity,
            parameters=parameters or {}
        )
        
        self.scenario_queue.append(scenario)
        logger.info(f"Created attack scenario: {scenario_id}")
        
        return scenario_id

    def start_scenario(self, scenario_id: str) -> bool:
        """Start specific attack scenario"""
        # Find scenario in queue
        scenario = None
        for s in self.scenario_queue:
            if s.scenario_id == scenario_id:
                scenario = s
                break
        
        if not scenario:
            logger.error(f"Scenario not found: {scenario_id}")
            return False
        
        # Get appropriate simulator
        simulator = self.simulators.get(scenario.attack_type)
        if not simulator:
            logger.error(f"No simulator for attack type: {scenario.attack_type}")
            return False
        
        # Start attack
        if simulator.start_attack(scenario):
            self.active_scenarios[scenario_id] = {
                'scenario': scenario,
                'simulator': simulator,
                'start_time': time.time()
            }
            
            # Remove from queue
            self.scenario_queue.remove(scenario)
            self.orchestration_stats['total_scenarios'] += 1
            
            logger.info(f"Started attack scenario: {scenario_id}")
            return True
        
        return False

    def stop_scenario(self, scenario_id: str) -> bool:
        """Stop specific attack scenario"""
        if scenario_id not in self.active_scenarios:
            logger.warning(f"Scenario not active: {scenario_id}")
            return False
        
        scenario_info = self.active_scenarios[scenario_id]
        simulator = scenario_info['simulator']
        
        simulator.stop_attack()
        del self.active_scenarios[scenario_id]
        
        logger.info(f"Stopped attack scenario: {scenario_id}")
        return True

    def create_coordinated_attack_campaign(self, 
                                         campaign_name: str,
                                         target_network: str,
                                         attack_sequence: List[Dict[str, Any]]) -> str:
        """Create coordinated multi-vector attack campaign"""
        
        campaign_id = f"campaign_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Create scenarios for each attack in sequence
        scenario_ids = []
        
        for i, attack_config in enumerate(attack_sequence):
            attack_type = AttackType(attack_config['type'])
            
            # Calculate timing
            delay = attack_config.get('delay', 0)
            start_time = time.time() + delay
            
            scenario_id = self.create_attack_scenario(
                attack_type=attack_type,
                target_ip=attack_config['target_ip'],
                target_ports=attack_config.get('target_ports', [80, 443, 22]),
                duration=attack_config.get('duration', 300),
                intensity=attack_config.get('intensity', 'medium'),
                parameters=attack_config.get('parameters', {})
            )
            
            scenario_ids.append({
                'scenario_id': scenario_id,
                'start_time': start_time,
                'attack_type': attack_type.value
            })
        
        # Store campaign
        campaign_data = {
            'campaign_id': campaign_id,
            'name': campaign_name,
            'description': f"Coordinated attack with {len(attack_sequence)} phases",
            'target_network': target_network,
            'start_time': time.time(),
            'status': 'scheduled',
            'scenarios': scenario_ids
        }
        
        self._store_campaign(campaign_data)
        
        # Schedule campaign execution
        self._schedule_campaign_execution(campaign_data)
        
        logger.info(f"Created coordinated attack campaign: {campaign_id} with {len(scenario_ids)} scenarios")
        return campaign_id

    def _orchestration_loop(self):
        """Main orchestration loop"""
        while self.orchestration_active:
            try:
                # Check for completed scenarios
                self._check_completed_scenarios()
                
                # Process scheduled campaigns
                self._process_scheduled_campaigns()
                
                # Generate background traffic
                if random.random() < 0.1:  # 10% chance
                    self._generate_background_attack()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Orchestration loop error: {e}")
                time.sleep(1)

    def _check_completed_scenarios(self):
        """Check for completed attack scenarios"""
        completed_scenarios = []
        
        for scenario_id, scenario_info in self.active_scenarios.items():
            simulator = scenario_info['simulator']
            
            if not simulator.is_running:
                completed_scenarios.append(scenario_id)
                
                # Update statistics
                scenario = scenario_info['scenario']
                if scenario.status == AttackStatus.COMPLETED:
                    self.orchestration_stats['completed_scenarios'] += 1
                else:
                    self.orchestration_stats['failed_scenarios'] += 1
        
        # Remove completed scenarios
        for scenario_id in completed_scenarios:
            del self.active_scenarios[scenario_id]
            logger.info(f"Scenario completed: {scenario_id}")

    def _process_scheduled_campaigns(self):
        """Process scheduled campaign executions"""
        # This would implement campaign scheduling logic
        pass

    def _generate_background_attack(self):
        """Generate random background attack for realism"""
        attack_types = list(AttackType)
        attack_type = random.choice(attack_types)
        
        # Random target (simulate internal network)
        target_ip = f"192.168.1.{random.randint(1, 254)}"
        target_ports = [80, 443, 22, 21, 25]
        
        scenario_id = self.create_attack_scenario(
            attack_type=attack_type,
            target_ip=target_ip,
            target_ports=target_ports,
            duration=random.randint(30, 120),  # 30 seconds to 2 minutes
            intensity="low",
            parameters={'background': True}
        )
        
        # Start immediately
        self.start_scenario(scenario_id)
        
        logger.debug(f"Generated background attack: {attack_type.value} -> {target_ip}")

    def _schedule_campaign_execution(self, campaign_data: Dict[str, Any]):
        """Schedule campaign execution"""
        def execute_campaign():
            try:
                logger.info(f"Executing campaign: {campaign_data['campaign_id']}")
                
                for scenario_info in campaign_data['scenarios']:
                    # Wait for scheduled start time
                    wait_time = scenario_info['start_time'] - time.time()
                    if wait_time > 0:
                        time.sleep(wait_time)
                    
                    # Start scenario
                    self.start_scenario(scenario_info['scenario_id'])
                    
                    logger.info(f"Campaign scenario started: {scenario_info['scenario_id']}")
                
            except Exception as e:
                logger.error(f"Campaign execution error: {e}")
        
        # Start campaign thread
        campaign_thread = threading.Thread(target=execute_campaign, daemon=True)
        campaign_thread.start()

    def _store_campaign(self, campaign_data: Dict[str, Any]):
        """Store campaign data in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO orchestration_campaigns
                (campaign_id, name, description, target_network, start_time, 
                 end_time, status, scenarios, results)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                campaign_data['campaign_id'],
                campaign_data['name'],
                campaign_data['description'],
                campaign_data['target_network'],
                campaign_data['start_time'],
                campaign_data.get('end_time'),
                campaign_data['status'],
                json.dumps(campaign_data['scenarios']),
                json.dumps(campaign_data.get('results', {}))
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing campaign: {e}")

    def get_orchestration_status(self) -> Dict[str, Any]:
        """Get comprehensive orchestration status"""
        return {
            'orchestration_active': self.orchestration_active,
            'active_scenarios': len(self.active_scenarios),
            'queued_scenarios': len(self.scenario_queue),
            'statistics': self.orchestration_stats.copy(),
            'simulator_status': {
                attack_type.value: simulator.get_attack_statistics()
                for attack_type, simulator in self.simulators.items()
            },
            'active_scenario_details': {
                scenario_id: {
                    'attack_type': info['scenario'].attack_type.value,
                    'target_ip': info['scenario'].target_ip,
                    'duration': info['scenario'].duration,
                    'intensity': info['scenario'].intensity,
                    'runtime': time.time() - info['start_time']
                }
                for scenario_id, info in self.active_scenarios.items()
            }
        }

    def create_realistic_attack_scenarios(self, target_network: str = "192.168.1.0/24"):
        """Create realistic attack scenarios for testing"""
        scenarios = []
        
        # Reconnaissance phase
        scenarios.append({
            'type': 'port_scan',
            'target_ip': '192.168.1.1',
            'target_ports': list(range(1, 1024)),
            'duration': 300,
            'intensity': 'low',
            'delay': 0,
            'parameters': {'technique': 'syn_scan'}
        })
        
        # DoS attack phase
        scenarios.append({
            'type': 'dos',
            'target_ip': '192.168.1.100',
            'target_ports': [80, 443],
            'duration': 600,
            'intensity': 'high',
            'delay': 300,  # Start 5 minutes after port scan
            'parameters': {'technique': 'syn_flood'}
        })
        
        # Malware delivery phase
        scenarios.append({
            'type': 'malware',
            'target_ip': '192.168.1.50',
            'target_ports': [80, 443],
            'duration': 180,
            'intensity': 'medium',
            'delay': 600,  # Start 10 minutes after beginning
            'parameters': {'malware_type': 'payload_delivery'}
        })
        
        # Phishing phase
        scenarios.append({
            'type': 'phishing',
            'target_ip': '192.168.1.200',
            'target_ports': [80, 443],
            'duration': 300,
            'intensity': 'low',
            'delay': 900,  # Start 15 minutes after beginning
            'parameters': {'phishing_type': 'credential_harvesting'}
        })
        
        campaign_id = self.create_coordinated_attack_campaign(
            campaign_name="Realistic Multi-Vector Attack",
            target_network=target_network,
            attack_sequence=scenarios
        )
        
        logger.info(f"Created realistic attack campaign: {campaign_id}")
        return campaign_id
