#!/usr/bin/env python3
"""
AI/ML Threat Detection Engine
Analyzes network traffic patterns to identify cybersecurity threats
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
import ipaddress
from typing import Dict, List, Any, Tuple
import warnings
warnings.filterwarnings('ignore')

class ThreatDetectionEngine:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_columns = [
            'packet_size', 'source_port', 'destination_port', 
            'protocol_encoded', 'hour', 'minute', 'day_of_week',
            'source_ip_class', 'dest_ip_class', 'port_category',
            'packet_size_category', 'time_since_last_packet'
        ]
        
        # Port categories for feature engineering
        self.port_categories = {
            'web': [80, 443, 8080, 8443],
            'mail': [25, 587, 993, 995],
            'ssh': [22],
            'dns': [53],
            'ftp': [21, 22],
            'database': [3306, 5432, 1433, 27017],
            'high': list(range(1024, 65535))
        }
    
    def extract_features(self, network_logs: pd.DataFrame) -> pd.DataFrame:
        """Extract features from network logs for ML analysis"""
        df = network_logs.copy()
        
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Time-based features
        df['hour'] = df['timestamp'].dt.hour
        df['minute'] = df['timestamp'].dt.minute
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # IP address classification
        df['source_ip_class'] = df['source_ip'].apply(self._classify_ip)
        df['dest_ip_class'] = df['destination_ip'].apply(self._classify_ip)
        
        # Port categorization
        df['port_category'] = df['destination_port'].apply(self._categorize_port)
        
        # Packet size categories
        df['packet_size_category'] = pd.cut(df['packet_size'], 
                                          bins=[0, 64, 512, 1024, 1500, float('inf')],
                                          labels=['tiny', 'small', 'medium', 'large', 'jumbo'])
        
        # Protocol encoding
        if 'protocol_encoded' not in df.columns:
            le_protocol = LabelEncoder()
            df['protocol_encoded'] = le_protocol.fit_transform(df['protocol'].fillna('TCP'))
            self.encoders['protocol'] = le_protocol
        
        # Time since last packet (for sequence analysis)
        df = df.sort_values('timestamp')
        df['time_since_last_packet'] = df['timestamp'].diff().dt.total_seconds().fillna(0)
        
        # Encode categorical features
        categorical_features = ['source_ip_class', 'dest_ip_class', 'port_category', 'packet_size_category']
        for feature in categorical_features:
            if feature not in self.encoders:
                self.encoders[feature] = LabelEncoder()
                df[f'{feature}'] = self.encoders[feature].fit_transform(df[feature].astype(str))
            else:
                df[f'{feature}'] = self.encoders[feature].transform(df[feature].astype(str))
        
        return df
    
    def _classify_ip(self, ip_str: str) -> str:
        """Classify IP address as internal, external, or special"""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private:
                return 'internal'
            elif ip.is_loopback or ip.is_multicast:
                return 'special'
            else:
                return 'external'
        except:
            return 'unknown'
    
    def _categorize_port(self, port: int) -> str:
        """Categorize port numbers"""
        if pd.isna(port):
            return 'unknown'
        
        port = int(port)
        for category, ports in self.port_categories.items():
            if port in ports:
                return category
        
        if port < 1024:
            return 'system'
        else:
            return 'user'
    
    def train_dos_detector(self, training_data: pd.DataFrame) -> float:
        """Train DoS attack detection model"""
        print("Training DoS detection model...")
        
        # Prepare features
        features_df = self.extract_features(training_data)
        X = features_df[self.feature_columns].fillna(0)
        
        # Create labels (1 for DoS, 0 for normal)
        y = (features_df['metadata'].apply(lambda x: 
            json.loads(x) if isinstance(x, str) else x
        ).apply(lambda x: x.get('traffic_type', 'normal') == 'dos_attack')).astype(int)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train Random Forest model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        accuracy = model.score(X_test_scaled, y_test)
        print(f"DoS Detection Accuracy: {accuracy:.3f}")
        
        # Save model and scaler
        self.models['dos'] = model
        self.scalers['dos'] = scaler
        
        return accuracy
    
    def train_port_scan_detector(self, training_data: pd.DataFrame) -> float:
        """Train port scanning detection model"""
        print("Training port scan detection model...")
        
        # Group by source IP to detect scanning patterns
        scan_features = []
        
        for source_ip, group in training_data.groupby('source_ip'):
            if len(group) < 5:  # Skip IPs with too few connections
                continue
            
            # Calculate scanning indicators
            unique_ports = group['destination_port'].nunique()
            unique_hosts = group['destination_ip'].nunique()
            total_connections = len(group)
            avg_packet_size = group['packet_size'].mean()
            time_span = (group['timestamp'].max() - group['timestamp'].min()).total_seconds()
            
            # Port scan indicators
            port_diversity = unique_ports / total_connections if total_connections > 0 else 0
            connection_rate = total_connections / max(time_span, 1)
            
            # Label (1 for port scan, 0 for normal)
            is_scan = any(group['metadata'].apply(lambda x: 
                json.loads(x) if isinstance(x, str) else x
            ).apply(lambda x: x.get('traffic_type', 'normal') == 'port_scan'))
            
            scan_features.append({
                'unique_ports': unique_ports,
                'unique_hosts': unique_hosts,
                'total_connections': total_connections,
                'avg_packet_size': avg_packet_size,
                'port_diversity': port_diversity,
                'connection_rate': connection_rate,
                'time_span': time_span,
                'is_scan': int(is_scan)
            })
        
        if not scan_features:
            print("No sufficient data for port scan training")
            return 0.0
        
        scan_df = pd.DataFrame(scan_features)
        feature_cols = ['unique_ports', 'unique_hosts', 'total_connections', 
                       'avg_packet_size', 'port_diversity', 'connection_rate', 'time_span']
        
        X = scan_df[feature_cols].fillna(0)
        y = scan_df['is_scan']
        
        if len(X) < 10:  # Need minimum samples
            print("Insufficient data for port scan model training")
            return 0.0
        
        # Split and train
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train_scaled, y_train)
        
        accuracy = model.score(X_test_scaled, y_test)
        print(f"Port Scan Detection Accuracy: {accuracy:.3f}")
        
        self.models['port_scan'] = model
        self.scalers['port_scan'] = scaler
        
        return accuracy
    
    def train_anomaly_detector(self, training_data: pd.DataFrame) -> float:
        """Train anomaly detection model for unknown threats"""
        print("Training anomaly detection model...")
        
        # Use only normal traffic for anomaly detection
        normal_data = training_data[training_data['is_suspicious'] == False]
        
        if len(normal_data) < 50:
            print("Insufficient normal traffic data for anomaly detection")
            return 0.0
        
        features_df = self.extract_features(normal_data)
        X = features_df[self.feature_columns].fillna(0)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Isolation Forest
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)
        
        # Test on mixed data
        test_features = self.extract_features(training_data)
        X_test = test_features[self.feature_columns].fillna(0)
        X_test_scaled = scaler.transform(X_test)
        
        predictions = model.predict(X_test_scaled)
        anomaly_score = np.mean(predictions == -1)  # Percentage of anomalies detected
        
        print(f"Anomaly Detection Rate: {anomaly_score:.3f}")
        
        self.models['anomaly'] = model
        self.scalers['anomaly'] = scaler
        
        return anomaly_score
    
    def predict_threat(self, network_log: Dict[str, Any]) -> Dict[str, Any]:
        """Predict threat for a single network log entry"""
        # Convert to DataFrame for feature extraction
        df = pd.DataFrame([network_log])
        
        try:
            features_df = self.extract_features(df)
            X = features_df[self.feature_columns].fillna(0)
            
            predictions = {}
            
            # DoS prediction
            if 'dos' in self.models:
                X_scaled = self.scalers['dos'].transform(X)
                dos_prob = self.models['dos'].predict_proba(X_scaled)[0][1]
                predictions['dos_probability'] = float(dos_prob)
                predictions['is_dos'] = dos_prob > 0.5
            
            # Anomaly detection
            if 'anomaly' in self.models:
                X_scaled = self.scalers['anomaly'].transform(X)
                anomaly_score = self.models['anomaly'].decision_function(X_scaled)[0]
                predictions['anomaly_score'] = float(anomaly_score)
                predictions['is_anomaly'] = anomaly_score < -0.1
            
            # Calculate overall threat score
            threat_score = 0.0
            if 'dos_probability' in predictions:
                threat_score += predictions['dos_probability'] * 0.4
            if 'anomaly_score' in predictions:
                # Convert anomaly score to 0-1 range
                normalized_anomaly = max(0, min(1, (-predictions['anomaly_score'] + 0.5) / 1.0))
                threat_score += normalized_anomaly * 0.6
            
            predictions['overall_threat_score'] = min(1.0, threat_score)
            predictions['threat_level'] = self._categorize_threat_level(threat_score)
            
            return predictions
            
        except Exception as e:
            print(f"Error in threat prediction: {e}")
            return {
                'overall_threat_score': 0.0,
                'threat_level': 'unknown',
                'error': str(e)
            }
    
    def _categorize_threat_level(self, score: float) -> str:
        """Categorize threat level based on score"""
        if score >= 0.8:
            return 'critical'
        elif score >= 0.6:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score >= 0.2:
            return 'low'
        else:
            return 'minimal'
    
    def save_models(self, model_dir: str = 'models'):
        """Save trained models to disk"""
        import os
        os.makedirs(model_dir, exist_ok=True)
        
        for name, model in self.models.items():
            joblib.dump(model, f'{model_dir}/{name}_model.pkl')
            if name in self.scalers:
                joblib.dump(self.scalers[name], f'{model_dir}/{name}_scaler.pkl')
        
        # Save encoders
        joblib.dump(self.encoders, f'{model_dir}/encoders.pkl')
        print(f"Models saved to {model_dir}/")
    
    def load_models(self, model_dir: str = 'models'):
        """Load trained models from disk"""
        import os
        
        try:
            for model_file in os.listdir(model_dir):
                if model_file.endswith('_model.pkl'):
                    name = model_file.replace('_model.pkl', '')
                    self.models[name] = joblib.load(f'{model_dir}/{model_file}')
                elif model_file.endswith('_scaler.pkl'):
                    name = model_file.replace('_scaler.pkl', '')
                    self.scalers[name] = joblib.load(f'{model_dir}/{model_file}')
                elif model_file == 'encoders.pkl':
                    self.encoders = joblib.load(f'{model_dir}/{model_file}')
            
            print(f"Models loaded from {model_dir}/")
            return True
        except Exception as e:
            print(f"Error loading models: {e}")
            return False

async def train_models_from_api():
    """Fetch data from API and train models"""
    engine = ThreatDetectionEngine()
    
    async with aiohttp.ClientSession() as session:
        # Fetch network logs for training
        async with session.get('http://localhost:3000/api/network-logs?limit=1000') as response:
            if response.status == 200:
                data = await response.json()
                logs_df = pd.DataFrame(data['logs'])
                
                if len(logs_df) > 0:
                    print(f"Training on {len(logs_df)} network log entries...")
                    
                    # Train models
                    dos_accuracy = engine.train_dos_detector(logs_df)
                    scan_accuracy = engine.train_port_scan_detector(logs_df)
                    anomaly_rate = engine.train_anomaly_detector(logs_df)
                    
                    # Save models
                    engine.save_models()
                    
                    print("Model training completed!")
                    print(f"DoS Detection Accuracy: {dos_accuracy:.3f}")
                    print(f"Port Scan Detection Accuracy: {scan_accuracy:.3f}")
                    print(f"Anomaly Detection Rate: {anomaly_rate:.3f}")
                else:
                    print("No training data available")
            else:
                print(f"Failed to fetch training data: {response.status}")

if __name__ == "__main__":
    asyncio.run(train_models_from_api())
