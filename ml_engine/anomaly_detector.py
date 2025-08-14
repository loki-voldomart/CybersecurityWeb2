"""
Phase 1: Professional Anomaly Detection System
Integrates with existing ML models for real-time threat detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import json
import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class AnomalyDetectionEngine:
    """
    Professional anomaly detection engine for cybersecurity
    Supports multiple algorithms: Isolation Forest, One-Class SVM
    """
    
    def __init__(self, model_dir: str = "/app/models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {}
        self.model_metadata = {}
        
        # Supported algorithms
        self.algorithms = {
            'isolation_forest': IsolationForest,
            'one_class_svm': OneClassSVM
        }
        
        logger.info("Anomaly Detection Engine initialized")

    def extract_features(self, telemetry: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical features from telemetry data for ML models
        """
        features = []
        
        # Network-based features
        features.extend([
            telemetry.get('packet_size', 0),
            telemetry.get('duration', 0),
            telemetry.get('bytes_sent', 0),
            telemetry.get('bytes_received', 0),
            hash(telemetry.get('protocol', 'unknown')) % 1000,
            hash(telemetry.get('source_ip', '0.0.0.0')) % 10000,
            hash(telemetry.get('destination_ip', '0.0.0.0')) % 10000,
            telemetry.get('port', 0),
        ])
        
        # Time-based features
        hour = datetime.now().hour
        features.extend([hour, hour < 6 or hour > 22])  # Off-hours indicator
        
        # Statistical features from metadata
        metadata = telemetry.get('metadata', {})
        features.extend([
            metadata.get('connection_count', 0),
            metadata.get('error_rate', 0),
            metadata.get('retry_count', 0),
            len(metadata.get('flags', [])),
        ])
        
        # Derived features
        if telemetry.get('bytes_sent', 0) > 0 and telemetry.get('bytes_received', 0) > 0:
            features.append(telemetry['bytes_sent'] / telemetry['bytes_received'])
        else:
            features.append(0)
        
        return np.array(features, dtype=np.float64)

    def train_model(self, 
                   algorithm: str,
                   normal_samples: List[Dict[str, Any]],
                   **algorithm_params) -> Dict[str, Any]:
        """
        Train anomaly detection model on normal behavior samples
        """
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        logger.info(f"Training {algorithm} model with {len(normal_samples)} samples")
        
        # Extract features from normal samples
        feature_vectors = []
        for sample in normal_samples:
            features = self.extract_features(sample)
            feature_vectors.append(features)
        
        X = np.array(feature_vectors)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Initialize model with parameters
        if algorithm == 'isolation_forest':
            model = IsolationForest(
                contamination=algorithm_params.get('contamination', 0.1),
                random_state=42,
                n_jobs=-1
            )
        elif algorithm == 'one_class_svm':
            model = OneClassSVM(
                gamma=algorithm_params.get('gamma', 'scale'),
                nu=algorithm_params.get('nu', 0.05)
            )
        
        # Train model
        model.fit(X_scaled)
        
        # Generate model ID
        model_id = str(uuid.uuid4())
        
        # Store model and scaler
        self.models[model_id] = model
        self.scalers[model_id] = scaler
        
        # Store metadata
        feature_names = [
            'packet_size', 'duration', 'bytes_sent', 'bytes_received',
            'protocol_hash', 'source_ip_hash', 'dest_ip_hash', 'port',
            'hour', 'off_hours', 'connection_count', 'error_rate',
            'retry_count', 'flags_count', 'bytes_ratio'
        ]
        
        self.model_metadata[model_id] = {
            'algorithm': algorithm,
            'trained_at': datetime.now().isoformat(),
            'n_samples': len(normal_samples),
            'feature_names': feature_names,
            'parameters': algorithm_params,
            'version': '1.0'
        }
        
        # Save to disk
        self._save_model(model_id)
        
        logger.info(f"Model {model_id} trained successfully")
        
        return {
            'model_id': model_id,
            'algorithm': algorithm,
            'n_samples': len(normal_samples),
            'feature_count': len(feature_names),
            'status': 'trained'
        }

    def predict(self, telemetry: Dict[str, Any], model_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Predict if telemetry represents anomalous behavior
        """
        if not self.models:
            raise ValueError("No trained models available")
        
        # Use latest model if not specified
        if model_id is None:
            model_id = max(self.model_metadata.keys(), 
                          key=lambda k: self.model_metadata[k]['trained_at'])
        
        if model_id not in self.models:
            raise ValueError(f"Model {model_id} not found")
        
        model = self.models[model_id]
        scaler = self.scalers[model_id]
        metadata = self.model_metadata[model_id]
        
        # Extract and scale features
        features = self.extract_features(telemetry)
        features_scaled = scaler.transform([features])
        
        # Get prediction
        prediction = model.predict(features_scaled)[0]
        is_anomaly = prediction == -1  # -1 indicates anomaly in sklearn
        
        # Get anomaly score
        if hasattr(model, 'decision_function'):
            raw_score = model.decision_function(features_scaled)[0]
            # Normalize score to 0-1 range (higher = more anomalous)
            if metadata['algorithm'] == 'isolation_forest':
                score = max(0, (0.5 - raw_score) * 2)  # Invert and normalize
            else:  # one_class_svm
                score = max(0, -raw_score)
        else:
            score = 0.5 if is_anomaly else 0.1
        
        result = {
            'model_id': model_id,
            'algorithm': metadata['algorithm'],
            'is_anomaly': bool(is_anomaly),
            'score': float(min(1.0, max(0.0, score))),
            'raw_decision': float(raw_score) if 'raw_score' in locals() else None,
            'feature_vector': features.tolist(),
            'feature_names': metadata['feature_names'],
            'timestamp': datetime.now().isoformat()
        }
        
        logger.debug(f"Anomaly prediction: {result}")
        return result

    def get_status(self) -> Dict[str, Any]:
        """
        Get anomaly detection system status
        """
        return {
            'installed': True,
            'has_model': len(self.models) > 0,
            'model_count': len(self.models),
            'models': [
                {
                    'id': model_id,
                    'algorithm': metadata['algorithm'],
                    'trained_at': metadata['trained_at'],
                    'n_samples': metadata['n_samples'],
                    'version': metadata['version']
                }
                for model_id, metadata in self.model_metadata.items()
            ],
            'supported_algorithms': list(self.algorithms.keys())
        }

    def _save_model(self, model_id: str):
        """Save model, scaler, and metadata to disk"""
        model_path = os.path.join(self.model_dir, f"anomaly_{model_id}.pkl")
        scaler_path = os.path.join(self.model_dir, f"scaler_{model_id}.pkl")
        metadata_path = os.path.join(self.model_dir, f"metadata_{model_id}.json")
        
        joblib.dump(self.models[model_id], model_path)
        joblib.dump(self.scalers[model_id], scaler_path)
        
        with open(metadata_path, 'w') as f:
            json.dump(self.model_metadata[model_id], f, indent=2)

    def load_models(self) -> int:
        """Load all saved models from disk"""
        loaded_count = 0
        
        if not os.path.exists(self.model_dir):
            return loaded_count
        
        for filename in os.listdir(self.model_dir):
            if filename.startswith('metadata_') and filename.endswith('.json'):
                model_id = filename.replace('metadata_', '').replace('.json', '')
                
                try:
                    # Load metadata
                    with open(os.path.join(self.model_dir, filename), 'r') as f:
                        self.model_metadata[model_id] = json.load(f)
                    
                    # Load model and scaler
                    model_path = os.path.join(self.model_dir, f"anomaly_{model_id}.pkl")
                    scaler_path = os.path.join(self.model_dir, f"scaler_{model_id}.pkl")
                    
                    if os.path.exists(model_path) and os.path.exists(scaler_path):
                        self.models[model_id] = joblib.load(model_path)
                        self.scalers[model_id] = joblib.load(scaler_path)
                        loaded_count += 1
                        logger.info(f"Loaded model {model_id}")
                
                except Exception as e:
                    logger.error(f"Error loading model {model_id}: {e}")
        
        return loaded_count

# Global instance
anomaly_engine = AnomalyDetectionEngine()
anomaly_engine.load_models()