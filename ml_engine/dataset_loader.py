import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import requests
import zipfile
import os
from typing import Tuple, Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CybersecurityDatasetLoader:
    """
    Professional dataset loader for cybersecurity ML training
    Supports KDD Cup 1999, CICIDS2017, NSL-KDD datasets
    """
    
    def __init__(self, data_dir: str = "datasets"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        
        # Dataset URLs and configurations
        self.datasets = {
            'kdd99': {
                'url': 'http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz',
                'columns': [
                    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
                    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                    'num_access_files', 'num_outbound_cmds', 'is_host_login',
                    'is_guest_login', 'count', 'srv_count', 'serror_rate',
                    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                    'dst_host_srv_rerror_rate', 'attack_type'
                ]
            }
        }
        
        # Attack type mappings for professional classification
        self.attack_mappings = {
            'normal': 'normal',
            'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos',
            'smurf': 'dos', 'teardrop': 'dos', 'mailbomb': 'dos', 'apache2': 'dos',
            'processtable': 'dos', 'udpstorm': 'dos',
            'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe',
            'satan': 'probe', 'mscan': 'probe', 'saint': 'probe',
            'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l',
            'multihop': 'r2l', 'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l',
            'warezmaster': 'r2l', 'sendmail': 'r2l', 'named': 'r2l',
            'snmpgetattack': 'r2l', 'snmpguess': 'r2l', 'xlock': 'r2l',
            'xsnoop': 'r2l', 'worm': 'r2l',
            'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r',
            'rootkit': 'u2r', 'httptunnel': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r',
            'xterm': 'u2r'
        }

    def download_dataset(self, dataset_name: str) -> str:
        """Download dataset if not exists"""
        if dataset_name not in self.datasets:
            raise ValueError(f"Dataset {dataset_name} not supported")
        
        dataset_info = self.datasets[dataset_name]
        file_path = os.path.join(self.data_dir, f"{dataset_name}.csv")
        
        if os.path.exists(file_path):
            logger.info(f"Dataset {dataset_name} already exists")
            return file_path
        
        logger.info(f"Downloading {dataset_name} dataset...")
        response = requests.get(dataset_info['url'])
        
        if dataset_name == 'kdd99':
            # Handle gzipped data
            import gzip
            with open(file_path, 'wb') as f:
                f.write(gzip.decompress(response.content))
        
        logger.info(f"Dataset downloaded to {file_path}")
        return file_path

    def load_kdd99(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Load and preprocess KDD Cup 1999 dataset"""
        file_path = self.download_dataset('kdd99')
        
        # Load dataset
        df = pd.read_csv(file_path, names=self.datasets['kdd99']['columns'])
        
        # Map attack types to categories
        df['attack_category'] = df['attack_type'].map(self.attack_mappings)
        
        # Separate features and labels
        X = df.drop(['attack_type', 'attack_category'], axis=1)
        y = df['attack_category']
        
        # Encode categorical features
        categorical_columns = ['protocol_type', 'service', 'flag']
        for col in categorical_columns:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col])
        
        logger.info(f"Loaded KDD99: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"Attack distribution: {y.value_counts().to_dict()}")
        
        return X, y

    def create_feature_engineering_pipeline(self, X: pd.DataFrame) -> pd.DataFrame:
        """Advanced feature engineering for cybersecurity data"""
        X_engineered = X.copy()
        
        # Network flow features
        X_engineered['bytes_ratio'] = X_engineered['src_bytes'] / (X_engineered['dst_bytes'] + 1)
        X_engineered['connection_rate'] = X_engineered['count'] / (X_engineered['duration'] + 1)
        
        # Statistical features
        X_engineered['error_rate_total'] = X_engineered['serror_rate'] + X_engineered['rerror_rate']
        X_engineered['srv_error_rate_total'] = X_engineered['srv_serror_rate'] + X_engineered['srv_rerror_rate']
        
        # Host-based features
        X_engineered['host_diversity'] = X_engineered['dst_host_diff_srv_rate'] * X_engineered['dst_host_srv_count']
        
        return X_engineered

    def prepare_training_data(self, dataset_name: str = 'kdd99') -> Dict[str, Any]:
        """Prepare complete training dataset with professional preprocessing"""
        if dataset_name == 'kdd99':
            X, y = self.load_kdd99()
        else:
            raise ValueError(f"Dataset {dataset_name} not implemented")
        
        # Feature engineering
        X_engineered = self.create_feature_engineering_pipeline(X)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_engineered)
        X_scaled = pd.DataFrame(X_scaled, columns=X_engineered.columns)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        return {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test,
            'scaler': scaler,
            'feature_names': X_engineered.columns.tolist(),
            'attack_types': y.unique().tolist()
        }
