#!/usr/bin/env python3
"""
Professional Network Traffic Analyzer
Integrates packet capture with ML threat detection
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from network_monitor.packet_capture import ProfessionalPacketCapture
from ml_engine.threat_models import ProfessionalThreatDetectionModels
import numpy as np
import sqlite3
import json
import time
import threading
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class NetworkThreatAnalyzer:
    """
    Professional network threat analyzer combining packet capture with ML detection
    """
    
    def __init__(self, interface: str = None, model_dir: str = "trained_models"):
        self.packet_capture = ProfessionalPacketCapture(interface)
        self.threat_models = ProfessionalThreatDetectionModels(model_dir)
        
        # Load trained models
        if not self.threat_models.load_trained_models():
            logger.warning("No trained models found. Train models first.")
        
        self.analysis_active = False
        self.threat_queue = []
        self.analysis_thread = None
        
        # Feature mapping for ML models
        self.feature_mapping = {
            'duration': 0,
            'protocol_type': 0,
            'service': 0,
            'flag': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        }

    def start_analysis(self, filter_expression: str = None):
        """Start comprehensive network analysis"""
        logger.info("Starting professional network threat analysis...")
        
        # Start packet capture
        self.packet_capture.start_capture(filter_expression)
        
        # Start ML analysis thread
        self.analysis_active = True
        self.analysis_thread = threading.Thread(target=self._ml_analysis_loop, daemon=True)
        self.analysis_thread.start()
        
        logger.info("Network threat analysis active")

    def stop_analysis(self):
        """Stop network analysis"""
        self.analysis_active = False
        self.packet_capture.stop_capture()
        
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        
        logger.info("Network threat analysis stopped")

    def _ml_analysis_loop(self):
        """Main ML analysis loop"""
        while self.analysis_active:
            try:
                # Get recent packets from database
                recent_packets = self._get_recent_packets()
                
                for packet_data in recent_packets:
                    # Convert packet to ML features
                    ml_features = self._convert_to_ml_features(packet_data)
                    
                    if ml_features is not None:
                        # Run ML threat detection
                        prediction = self.threat_models.predict_threat(ml_features)
                        
                        # Process threat prediction
                        self._process_threat_prediction(packet_data, prediction)
                
                time.sleep(5)  # Analyze every 5 seconds
                
            except Exception as e:
                logger.error(f"ML analysis error: {e}")
                time.sleep(1)

    def _get_recent_packets(self, seconds: int = 10) -> List[Dict]:
        """Get recent packets from database"""
        try:
            conn = sqlite3.connect(self.packet_capture.db_path)
            cursor = conn.cursor()
            
            cutoff_time = time.time() - seconds
            
            cursor.execute('''
                SELECT * FROM packets 
                WHERE timestamp > ? AND is_suspicious = 0
                ORDER BY timestamp DESC
                LIMIT 100
            ''', (cutoff_time,))
            
            columns = [desc[0] for desc in cursor.description]
            packets = []
            
            for row in cursor.fetchall():
                packet_dict = dict(zip(columns, row))
                if packet_dict['features']:
                    packet_dict['features'] = json.loads(packet_dict['features'])
                packets.append(packet_dict)
            
            conn.close()
            return packets
            
        except Exception as e:
            logger.error(f"Database query error: {e}")
            return []

    def _convert_to_ml_features(self, packet_data: Dict) -> np.ndarray:
        """Convert packet data to ML model features"""
        try:
            features = packet_data.get('features', {})
            
            # Create feature vector matching training data
            feature_vector = []
            
            # Map packet features to ML features
            feature_vector.extend([
                features.get('packet_size', 0) / 1500.0,  # Normalized packet size
                1 if features.get('protocol') == 'TCP' else 0,  # Protocol type
                features.get('dst_port', 0) / 65535.0,  # Normalized port
                1 if features.get('flags', 0) & 0x02 else 0,  # SYN flag
                features.get('payload_size', 0) / 1500.0,  # Normalized payload
                features.get('ttl', 64) / 255.0,  # Normalized TTL
                0,  # land
                0,  # wrong_fragment
                0,  # urgent
                1 if features.get('dst_port', 0) in [80, 443, 22, 21] else 0,  # hot
                0,  # num_failed_logins
                1 if features.get('is_internal', False) else 0,  # logged_in
                0,  # num_compromised
                0,  # root_shell
                0,  # su_attempted
                0,  # num_root
                0,  # num_file_creations
                0,  # num_shells
                0,  # num_access_files
                0,  # num_outbound_cmds
                0,  # is_host_login
                0,  # is_guest_login
                features.get('connection_count', 1),  # count
                1,  # srv_count
                0,  # serror_rate
                0,  # srv_serror_rate
                0,  # rerror_rate
                0,  # srv_rerror_rate
                0,  # same_srv_rate
                0,  # diff_srv_rate
                0,  # srv_diff_host_rate
                1,  # dst_host_count
                1,  # dst_host_srv_count
                0,  # dst_host_same_srv_rate
                0,  # dst_host_diff_srv_rate
                0,  # dst_host_same_src_port_rate
                0,  # dst_host_srv_diff_host_rate
                0,  # dst_host_serror_rate
                0,  # dst_host_srv_serror_rate
                0,  # dst_host_rerror_rate
                0   # dst_host_srv_rerror_rate
            ])
            
            # Ensure we have the right number of features
            while len(feature_vector) < 41:  # KDD99 has 41 features
                feature_vector.append(0)
            
            return np.array(feature_vector[:41])
            
        except Exception as e:
            logger.error(f"Feature conversion error: {e}")
            return None

    def _process_threat_prediction(self, packet_data: Dict, prediction: Dict):
        """Process ML threat prediction and take action"""
        threat_level = prediction['threat_level']
        confidence = prediction['confidence']
        attack_type = prediction['prediction']
        
        if attack_type != 'normal' and confidence > 0.7:
            # High confidence threat detected
            threat_event = {
                'timestamp': time.time(),
                'src_ip': packet_data['src_ip'],
                'dst_ip': packet_data['dst_ip'],
                'src_port': packet_data['src_port'],
                'dst_port': packet_data['dst_port'],
                'attack_type': attack_type,
                'threat_level': threat_level,
                'confidence': confidence,
                'ml_prediction': prediction
            }
            
            # Add to threat queue
            self.threat_queue.append(threat_event)
            
            # Log threat
            logger.warning(f"ML THREAT DETECTED: {attack_type} from {packet_data['src_ip']} (confidence: {confidence:.2f})")
            
            # Update database
            self._update_threat_in_database(packet_data['id'], True, confidence)

    def _update_threat_in_database(self, packet_id: int, is_suspicious: bool, threat_score: float):
        """Update packet threat status in database"""
        try:
            conn = sqlite3.connect(self.packet_capture.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE packets 
                SET is_suspicious = ?, threat_score = ?
                WHERE id = ?
            ''', (is_suspicious, threat_score, packet_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Database update error: {e}")

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get comprehensive threat summary"""
        # Get packet capture stats
        capture_stats = self.packet_capture.get_real_time_stats()
        
        # Get recent threats
        recent_threats = self.threat_queue[-10:] if self.threat_queue else []
        
        # Calculate threat statistics
        threat_stats = self._calculate_threat_statistics()
        
        return {
            'capture_stats': capture_stats,
            'recent_threats': recent_threats,
            'threat_statistics': threat_stats,
            'analysis_active': self.analysis_active,
            'total_threats_detected': len(self.threat_queue)
        }

    def _calculate_threat_statistics(self) -> Dict[str, int]:
        """Calculate threat type statistics"""
        stats = {
            'dos': 0,
            'probe': 0,
            'r2l': 0,
            'u2r': 0,
            'normal': 0
        }
        
        for threat in self.threat_queue:
            attack_type = threat.get('attack_type', 'normal')
            if attack_type in stats:
                stats[attack_type] += 1
        
        return stats

def main():
    """Main function for standalone network analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Professional Network Threat Analyzer')
    parser.add_argument('--interface', '-i', help='Network interface to monitor')
    parser.add_argument('--filter', '-f', help='BPF filter expression')
    parser.add_argument('--duration', '-d', type=int, default=60, help='Analysis duration in seconds')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = NetworkThreatAnalyzer(args.interface)
    
    try:
        # Start analysis
        analyzer.start_analysis(args.filter)
        
        print(f"Network analysis running for {args.duration} seconds...")
        print("Press Ctrl+C to stop early")
        
        # Run for specified duration
        time.sleep(args.duration)
        
    except KeyboardInterrupt:
        print("\nStopping analysis...")
    
    finally:
        analyzer.stop_analysis()
        
        # Print summary
        summary = analyzer.get_threat_summary()
        print("\nANALYSIS SUMMARY:")
        print(f"Total threats detected: {summary['total_threats_detected']}")
        print(f"Threat statistics: {summary['threat_statistics']}")

if __name__ == "__main__":
    main()
