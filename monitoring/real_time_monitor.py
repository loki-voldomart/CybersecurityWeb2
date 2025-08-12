import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging
from dataclasses import dataclass
import numpy as np
from collections import defaultdict, deque

from ml_engine.threat_models import ThreatDetectionEnsemble
from network_monitor.network_analyzer import NetworkAnalyzer
from agents.coordinator_agent import CoordinatorAgent
from response.response_agents import ResponseOrchestrator

@dataclass
class ThreatMetrics:
    total_threats: int = 0
    critical_threats: int = 0
    blocked_ips: int = 0
    false_positives: int = 0
    detection_accuracy: float = 0.0
    response_time: float = 0.0

class RealTimeMonitor:
    def __init__(self):
        self.ml_engine = ThreatDetectionEnsemble()
        self.network_analyzer = NetworkAnalyzer()
        self.coordinator = CoordinatorAgent()
        self.response_orchestrator = ResponseOrchestrator()
        
        # Real-time metrics storage
        self.threat_metrics = ThreatMetrics()
        self.hourly_stats = defaultdict(int)
        self.threat_timeline = deque(maxlen=1000)
        self.performance_metrics = deque(maxlen=100)
        
        # Alert thresholds
        self.alert_thresholds = {
            'critical_threats_per_hour': 10,
            'detection_accuracy_min': 0.95,
            'response_time_max': 5.0,
            'false_positive_rate_max': 0.05
        }
        
        self.logger = logging.getLogger(__name__)
        
    async def start_monitoring(self):
        """Start comprehensive real-time monitoring"""
        self.logger.info("Starting enterprise-grade real-time monitoring")
        
        # Start monitoring tasks
        tasks = [
            self.monitor_network_traffic(),
            self.monitor_threat_detection(),
            self.monitor_response_performance(),
            self.generate_analytics(),
            self.check_system_health()
        ]
        
        await asyncio.gather(*tasks)
    
    async def monitor_network_traffic(self):
        """Monitor network traffic and feed to ML models"""
        while True:
            try:
                # Capture network packets
                packets = await self.network_analyzer.capture_packets(duration=5)
                
                for packet in packets:
                    # Extract features for ML analysis
                    features = self.network_analyzer.extract_features(packet)
                    
                    # Run through ML models
                    threat_prediction = self.ml_engine.predict_threat(features)
                    
                    if threat_prediction['is_threat']:
                        await self.process_threat_detection(packet, threat_prediction)
                
                await asyncio.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def process_threat_detection(self, packet: Dict, prediction: Dict):
        """Process detected threats through agent coordination"""
        threat_data = {
            'timestamp': datetime.now(),
            'source_ip': packet.get('src_ip'),
            'dest_ip': packet.get('dest_ip'),
            'threat_type': prediction['threat_type'],
            'confidence': prediction['confidence'],
            'severity': prediction['severity'],
            'packet_data': packet
        }
        
        # Send to coordinator agent for analysis
        agent_response = await self.coordinator.analyze_threat(threat_data)
        
        # Execute response if needed
        if agent_response['requires_response']:
            response_start = time.time()
            await self.response_orchestrator.execute_response(agent_response)
            response_time = time.time() - response_start
            
            # Update metrics
            self.threat_metrics.response_time = (
                self.threat_metrics.response_time * 0.9 + response_time * 0.1
            )
        
        # Update threat timeline
        self.threat_timeline.append(threat_data)
        self.update_threat_metrics(threat_data, agent_response)
    
    def update_threat_metrics(self, threat_data: Dict, response: Dict):
        """Update real-time threat metrics"""
        self.threat_metrics.total_threats += 1
        
        if threat_data['severity'] == 'critical':
            self.threat_metrics.critical_threats += 1
        
        if response.get('action_taken') == 'block_ip':
            self.threat_metrics.blocked_ips += 1
        
        # Update hourly statistics
        hour_key = datetime.now().strftime('%Y-%m-%d-%H')
        self.hourly_stats[hour_key] += 1
        
        # Calculate detection accuracy (simplified)
        if hasattr(self, 'validation_data'):
            accuracy = self.calculate_detection_accuracy()
            self.threat_metrics.detection_accuracy = accuracy
    
    async def monitor_response_performance(self):
        """Monitor response system performance"""
        while True:
            try:
                # Check response agent health
                response_health = await self.response_orchestrator.get_health_status()
                
                # Monitor blocked IPs effectiveness
                blocked_effectiveness = await self.analyze_blocking_effectiveness()
                
                # Update performance metrics
                perf_data = {
                    'timestamp': datetime.now(),
                    'response_health': response_health,
                    'blocking_effectiveness': blocked_effectiveness,
                    'active_blocks': len(self.response_orchestrator.blocked_ips)
                }
                
                self.performance_metrics.append(perf_data)
                
                await asyncio.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Response monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def generate_analytics(self):
        """Generate comprehensive analytics and reports"""
        while True:
            try:
                # Generate hourly analytics
                analytics = {
                    'threat_summary': self.generate_threat_summary(),
                    'attack_patterns': self.analyze_attack_patterns(),
                    'geographic_analysis': self.analyze_geographic_threats(),
                    'performance_metrics': self.generate_performance_report(),
                    'predictions': self.generate_threat_predictions()
                }
                
                # Store analytics in database
                await self.store_analytics(analytics)
                
                # Check for alert conditions
                await self.check_alert_conditions(analytics)
                
                await asyncio.sleep(300)  # Every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Analytics generation error: {e}")
                await asyncio.sleep(300)
    
    def generate_threat_summary(self) -> Dict:
        """Generate comprehensive threat summary"""
        recent_threats = [t for t in self.threat_timeline 
                         if t['timestamp'] > datetime.now() - timedelta(hours=1)]
        
        threat_types = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for threat in recent_threats:
            threat_types[threat['threat_type']] += 1
            severity_counts[threat['severity']] += 1
        
        return {
            'total_threats_last_hour': len(recent_threats),
            'threat_types': dict(threat_types),
            'severity_distribution': dict(severity_counts),
            'detection_rate': self.threat_metrics.detection_accuracy,
            'average_response_time': self.threat_metrics.response_time
        }
    
    def analyze_attack_patterns(self) -> Dict:
        """Analyze attack patterns and trends"""
        patterns = {
            'dos_attacks': 0,
            'port_scans': 0,
            'malware_attempts': 0,
            'phishing_attempts': 0,
            'coordinated_attacks': 0
        }
        
        # Analyze recent threats for patterns
        recent_threats = [t for t in self.threat_timeline 
                         if t['timestamp'] > datetime.now() - timedelta(hours=24)]
        
        for threat in recent_threats:
            threat_type = threat['threat_type'].lower()
            if 'dos' in threat_type:
                patterns['dos_attacks'] += 1
            elif 'port' in threat_type or 'scan' in threat_type:
                patterns['port_scans'] += 1
            elif 'malware' in threat_type:
                patterns['malware_attempts'] += 1
            elif 'phishing' in threat_type:
                patterns['phishing_attempts'] += 1
        
        # Detect coordinated attacks
        patterns['coordinated_attacks'] = self.detect_coordinated_attacks(recent_threats)
        
        return patterns
    
    def detect_coordinated_attacks(self, threats: List[Dict]) -> int:
        """Detect coordinated attack campaigns"""
        # Group threats by source IP and time windows
        ip_groups = defaultdict(list)
        for threat in threats:
            ip_groups[threat['source_ip']].append(threat)
        
        coordinated_count = 0
        for ip, ip_threats in ip_groups.items():
            if len(ip_threats) > 5:  # Multiple attacks from same IP
                # Check if attacks span multiple types (coordinated)
                threat_types = set(t['threat_type'] for t in ip_threats)
                if len(threat_types) > 2:
                    coordinated_count += 1
        
        return coordinated_count
    
    async def check_system_health(self):
        """Monitor overall system health"""
        while True:
            try:
                health_status = {
                    'ml_engine_status': await self.check_ml_engine_health(),
                    'network_monitor_status': await self.check_network_health(),
                    'agent_system_status': await self.check_agent_health(),
                    'response_system_status': await self.check_response_health(),
                    'database_status': await self.check_database_health()
                }
                
                # Log system health
                self.logger.info(f"System health check: {health_status}")
                
                # Alert on critical issues
                for component, status in health_status.items():
                    if status != 'healthy':
                        await self.send_system_alert(component, status)
                
                await asyncio.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Health check error: {e}")
                await asyncio.sleep(120)
    
    async def check_alert_conditions(self, analytics: Dict):
        """Check for alert conditions and send notifications"""
        alerts = []
        
        # Check critical threat threshold
        if analytics['threat_summary']['total_threats_last_hour'] > self.alert_thresholds['critical_threats_per_hour']:
            alerts.append({
                'type': 'high_threat_volume',
                'message': f"High threat volume: {analytics['threat_summary']['total_threats_last_hour']} threats in last hour",
                'severity': 'critical'
            })
        
        # Check detection accuracy
        if analytics['threat_summary']['detection_rate'] < self.alert_thresholds['detection_accuracy_min']:
            alerts.append({
                'type': 'low_accuracy',
                'message': f"Detection accuracy below threshold: {analytics['threat_summary']['detection_rate']:.2%}",
                'severity': 'warning'
            })
        
        # Send alerts
        for alert in alerts:
            await self.send_alert(alert)
    
    async def send_alert(self, alert: Dict):
        """Send alert through multiple channels"""
        # This would integrate with email, SMS, Slack, etc.
        self.logger.critical(f"SECURITY ALERT: {alert['message']}")
        
        # Store alert in database for dashboard
        alert_data = {
            'timestamp': datetime.now(),
            'type': alert['type'],
            'message': alert['message'],
            'severity': alert['severity']
        }
        
        # In real implementation, this would send to external systems
        print(f"🚨 SECURITY ALERT: {alert['message']}")

if __name__ == "__main__":
    monitor = RealTimeMonitor()
    asyncio.run(monitor.start_monitoring())
