import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any
import json
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

class AnalyticsEngine:
    def __init__(self):
        self.threat_data = []
        self.network_data = []
        self.response_data = []
        
    def generate_comprehensive_report(self, timeframe_hours: int = 24) -> Dict:
        """Generate comprehensive cybersecurity analytics report"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=timeframe_hours)
        
        report = {
            'executive_summary': self.generate_executive_summary(start_time, end_time),
            'threat_analysis': self.analyze_threats(start_time, end_time),
            'attack_vectors': self.analyze_attack_vectors(start_time, end_time),
            'geographic_analysis': self.analyze_geographic_distribution(start_time, end_time),
            'response_effectiveness': self.analyze_response_effectiveness(start_time, end_time),
            'ml_performance': self.analyze_ml_performance(start_time, end_time),
            'recommendations': self.generate_recommendations(),
            'predictions': self.generate_threat_predictions()
        }
        
        return report
    
    def generate_executive_summary(self, start_time: datetime, end_time: datetime) -> Dict:
        """Generate executive-level summary"""
        threats_in_period = self.get_threats_in_timeframe(start_time, end_time)
        
        total_threats = len(threats_in_period)
        critical_threats = len([t for t in threats_in_period if t.get('severity') == 'critical'])
        blocked_threats = len([t for t in threats_in_period if t.get('blocked', False)])
        
        return {
            'total_threats_detected': total_threats,
            'critical_threats': critical_threats,
            'threats_blocked': blocked_threats,
            'block_success_rate': (blocked_threats / total_threats * 100) if total_threats > 0 else 0,
            'average_detection_time': self.calculate_average_detection_time(threats_in_period),
            'system_uptime': 99.9,  # Would be calculated from actual system metrics
            'false_positive_rate': self.calculate_false_positive_rate(threats_in_period)
        }
    
    def analyze_attack_vectors(self, start_time: datetime, end_time: datetime) -> Dict:
        """Analyze different attack vectors and their effectiveness"""
        threats = self.get_threats_in_timeframe(start_time, end_time)
        
        attack_vectors = defaultdict(lambda: {
            'count': 0,
            'success_rate': 0,
            'average_severity': 0,
            'blocked_count': 0
        })
        
        for threat in threats:
            vector = threat.get('threat_type', 'unknown')
            attack_vectors[vector]['count'] += 1
            
            if threat.get('blocked', False):
                attack_vectors[vector]['blocked_count'] += 1
            
            # Convert severity to numeric for averaging
            severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            severity_num = severity_map.get(threat.get('severity', 'low'), 1)
            attack_vectors[vector]['average_severity'] += severity_num
        
        # Calculate averages and success rates
        for vector, data in attack_vectors.items():
            if data['count'] > 0:
                data['success_rate'] = (data['blocked_count'] / data['count']) * 100
                data['average_severity'] /= data['count']
        
        return dict(attack_vectors)
    
    def analyze_geographic_distribution(self, start_time: datetime, end_time: datetime) -> Dict:
        """Analyze geographic distribution of threats"""
        threats = self.get_threats_in_timeframe(start_time, end_time)
        
        # This would use IP geolocation in real implementation
        geographic_data = defaultdict(int)
        
        for threat in threats:
            # Simulate geographic analysis
            source_ip = threat.get('source_ip', '')
            if source_ip:
                # In real implementation, use IP geolocation service
                country = self.get_country_from_ip(source_ip)
                geographic_data[country] += 1
        
        return dict(geographic_data)
    
    def get_country_from_ip(self, ip: str) -> str:
        """Simulate IP geolocation (would use real service in production)"""
        # Simplified simulation based on IP ranges
        if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('172.'):
            return 'Internal'
        elif ip.startswith('203.'):
            return 'Australia'
        elif ip.startswith('185.'):
            return 'Europe'
        elif ip.startswith('123.'):
            return 'Asia'
        else:
            return 'Unknown'
    
    def analyze_ml_performance(self, start_time: datetime, end_time: datetime) -> Dict:
        """Analyze machine learning model performance"""
        threats = self.get_threats_in_timeframe(start_time, end_time)
        
        if not threats:
            return {'error': 'No data available for analysis'}
        
        # Calculate performance metrics
        true_positives = len([t for t in threats if t.get('verified', True) and t.get('ml_detected', True)])
        false_positives = len([t for t in threats if not t.get('verified', True) and t.get('ml_detected', True)])
        false_negatives = len([t for t in threats if t.get('verified', True) and not t.get('ml_detected', True)])
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': (true_positives / len(threats)) if threats else 0,
            'total_predictions': len(threats),
            'model_confidence_avg': np.mean([t.get('confidence', 0) for t in threats])
        }
    
    def generate_threat_predictions(self) -> Dict:
        """Generate predictions for future threats"""
        # Analyze historical patterns to predict future threats
        recent_threats = self.get_threats_in_timeframe(
            datetime.now() - timedelta(days=7), 
            datetime.now()
        )
        
        if len(recent_threats) < 10:
            return {'error': 'Insufficient data for predictions'}
        
        # Analyze trends
        daily_counts = defaultdict(int)
        threat_types = defaultdict(int)
        
        for threat in recent_threats:
            day = threat['timestamp'].strftime('%Y-%m-%d')
            daily_counts[day] += 1
            threat_types[threat.get('threat_type', 'unknown')] += 1
        
        # Simple trend analysis
        daily_values = list(daily_counts.values())
        if len(daily_values) > 3:
            trend = np.polyfit(range(len(daily_values)), daily_values, 1)[0]
        else:
            trend = 0
        
        return {
            'trend_direction': 'increasing' if trend > 0 else 'decreasing' if trend < 0 else 'stable',
            'predicted_daily_threats': max(0, int(np.mean(daily_values) + trend)),
            'most_likely_attack_type': max(threat_types.items(), key=lambda x: x[1])[0] if threat_types else 'unknown',
            'confidence': min(0.95, len(recent_threats) / 100)  # Higher confidence with more data
        }
    
    def get_threats_in_timeframe(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get threats within specified timeframe"""
        # In real implementation, this would query the database
        # For now, return simulated data
        return [
            {
                'timestamp': datetime.now() - timedelta(hours=i),
                'threat_type': ['dos_attack', 'port_scan', 'malware', 'phishing'][i % 4],
                'severity': ['low', 'medium', 'high', 'critical'][i % 4],
                'source_ip': f"192.168.1.{100 + i}",
                'blocked': i % 3 == 0,
                'verified': i % 5 != 0,
                'ml_detected': True,
                'confidence': 0.8 + (i % 20) / 100
            }
            for i in range(50)  # Simulate 50 recent threats
        ]
