#!/usr/bin/env python3
"""
Machine Learning Engine for Anomaly Detection
Author: Nithin Bonagiri (X24137430)
Implements Isolation Forest as described in the project report.
"""

import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from typing import Dict, List, Any, Tuple

class AnomalyDetector:
    def __init__(self, model_path: str = "security_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.encoders = {}
        self.is_trained = False
        
        # Define features based on NSL-KDD (simplified for PoC)
        self.feature_columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes']
        self._load_model()

    def _load_model(self):
        """Load trained model if exists"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.scaler = data['scaler']
                    self.encoders = data['encoders']
                    self.is_trained = True
            except Exception as e:
                print(f"Error loading model: {e}")

    def train(self, data: List[Dict[str, Any]] = None):
        """
        Train the Isolation Forest model.
        If data is None, generates synthetic 'normal' traffic to simulate training.
        """
        if data is None:
            # Generate synthetic "normal" behavior for baseline
            # Simulating 1000 normal traffic records
            X_train = self._generate_synthetic_data(n_samples=1000, anomaly_ratio=0.01)
        else:
            X_train = self._preprocess(data, training=True)

        # Isolation Forest implementation as specified in report Section 3.2.3
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05, # Expect 5% anomalies
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train)
        self.is_trained = True
        
        # Save model
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'encoders': self.encoders
            }, f)
            
        return {"status": "trained", "n_samples": len(X_train)}

    def predict(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if a single traffic record is anomalous.
        Returns -1 for anomaly, 1 for normal.
        """
        if not self.is_trained:
            self.train() # Auto-train if needed

        try:
            # Preprocess single record
            features = self._preprocess_single(traffic_data)
            
            # Predict
            # Isolation Forest returns -1 for outliers (anomalies) and 1 for inliers
            prediction = self.model.predict(features)[0]
            score = self.model.decision_function(features)[0]
            
            is_anomaly = True if prediction == -1 else False
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": float(score), # Lower score = more anomalous
                "risk_level": "CRITICAL" if score < -0.2 else ("HIGH" if score < 0 else "LOW")
            }
        except Exception as e:
            return {"error": str(e), "is_anomaly": False, "risk_level": "UNKNOWN"}

    def _generate_synthetic_data(self, n_samples=1000, anomaly_ratio=0.0):
        """Generates synthetic network traffic data"""
        rng = np.random.RandomState(42)
        
        # Generate 'Normal' components
        duration = rng.exponential(scale=2.0, size=n_samples) # Short connections
        src_bytes = rng.normal(loc=1000, scale=200, size=n_samples)
        dst_bytes = rng.normal(loc=5000, scale=1000, size=n_samples)
        
        # Categorical features (mapped to int for this generator)
        # Protocol: TCP=0, UDP=1, ICMP=2
        protocol = rng.choice([0, 1], size=n_samples, p=[0.9, 0.1]) 
        # Service: HTTP=0, SSH=1, FTP=2
        service = rng.choice([0, 1, 2], size=n_samples, p=[0.8, 0.1, 0.1])
        # Flag: SF=0, S0=1, REJ=2
        flag = np.zeros(n_samples) # Mostly normal flags
        
        X = np.column_stack([duration, protocol, service, flag, src_bytes, dst_bytes])
        
        # Add some random noise/anomalies training
        if anomaly_ratio > 0:
            n_outliers = int(n_samples * anomaly_ratio)
            # Create outliers: Long duration, huge bytes, rare protocols
            outliers = rng.uniform(low=-4, high=4, size=(n_outliers, 6))
            outliers[:, 4] = outliers[:, 4] * 10000 # Massive data transfer
            X[-n_outliers:] = outliers
            
        return X

    def _preprocess_single(self, data: Dict[str, Any]):
        """Convert dict input to array for prediction"""
        # Simple mapping for PoC - in real prod use saved LabelEncoders
        protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        service_map = {'http': 0, 'ssh': 1, 'ftp': 2, 'smtp': 3, 'other': 4}
        flag_map = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTO': 3}

        vec = [
            float(data.get('duration', 0)),
            protocol_map.get(data.get('protocol_type', 'tcp'), 0),
            service_map.get(data.get('service', 'http'), 4),
            flag_map.get(data.get('flag', 'SF'), 0),
            float(data.get('src_bytes', 0)),
            float(data.get('dst_bytes', 0))
        ]
        return np.array([vec])
        
    def _preprocess(self, data_list, training=False):
        """Placeholder for full preprocessing pipeline"""
        # For this PoC, we rely on the synthetic generator
        pass

# Global instance
anomaly_detector = AnomalyDetector()
