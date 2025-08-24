import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
import hashlib

class AIThreatAnalyzer:
    """AI-powered threat analysis using multiple machine learning models"""
    
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.sensitivity = 0.7
        self.monitored_threats = []
        self.model_stats = {
            'accuracy': 0.94,
            'false_positive_rate': 0.06,
            'last_trained': '2024-08-20'
        }
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize and train AI models"""
        # Random Forest for classification
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Isolation Forest for anomaly detection
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        # Train with synthetic data for demo
        self._train_models()
    
    def _train_models(self):
        """Train models with synthetic threat data"""
        # Generate synthetic training data
        X_train, y_train = self._generate_training_data()
        
        # Train Random Forest
        self.models['random_forest'].fit(X_train, y_train)
        
        # Train Isolation Forest (unsupervised)
        self.models['isolation_forest'].fit(X_train)
        
        # Fit scaler
        self.scaler.fit(X_train)
    
    def _generate_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for threat detection"""
        np.random.seed(42)
        
        # Features: [packet_size, connection_count, cpu_usage, memory_usage, 
        #           file_operations, network_connections, process_count, login_attempts]
        
        # Normal traffic patterns
        normal_samples = 1000
        normal_data = np.random.normal(loc=[1024, 50, 30, 40, 10, 5, 20, 1], 
                                     scale=[200, 10, 10, 15, 3, 2, 5, 1], 
                                     size=(normal_samples, 8))
        normal_labels = np.zeros(normal_samples)
        
        # Malicious traffic patterns
        malicious_samples = 200
        
        # DDoS attacks - high packet count, connections
        ddos_data = np.random.normal(loc=[512, 500, 80, 60, 5, 100, 15, 1],
                                   scale=[100, 100, 20, 20, 2, 20, 3, 1],
                                   size=(malicious_samples//4, 8))
        
        # Malware - high CPU, memory, file operations
        malware_data = np.random.normal(loc=[2048, 30, 90, 85, 100, 10, 50, 1],
                                      scale=[500, 5, 10, 15, 20, 3, 10, 1],
                                      size=(malicious_samples//4, 8))
        
        # Brute force - high login attempts
        bruteforce_data = np.random.normal(loc=[1024, 20, 25, 30, 5, 3, 15, 50],
                                         scale=[200, 5, 5, 10, 2, 1, 3, 20],
                                         size=(malicious_samples//4, 8))
        
        # Data exfiltration - large packets, high network activity
        exfiltration_data = np.random.normal(loc=[8192, 100, 50, 70, 200, 50, 25, 2],
                                           scale=[2000, 20, 15, 20, 50, 15, 5, 1],
                                           size=(malicious_samples//4, 8))
        
        # Combine malicious data
        malicious_data = np.vstack([ddos_data, malware_data, bruteforce_data, exfiltration_data])
        malicious_labels = np.ones(malicious_samples)
        
        # Combine all data
        X = np.vstack([normal_data, malicious_data])
        y = np.hstack([normal_labels, malicious_labels])
        
        # Ensure non-negative values
        X = np.abs(X)
        
        return X, y
    
    def analyze_real_time(self) -> List[Dict[str, Any]]:
        """Analyze real-time data for threats"""
        # Simulate real-time data
        current_data = self._generate_current_data()
        
        threats = []
        
        for data_point in current_data:
            # Extract features
            features = self._extract_features(data_point)
            
            # Predict using ensemble of models
            threat_prediction = self._predict_threat(features)
            
            if threat_prediction['is_threat']:
                threat = {
                    'type': threat_prediction['threat_type'],
                    'confidence': threat_prediction['confidence'],
                    'target': data_point.get('target', 'Unknown'),
                    'description': self._generate_threat_description(threat_prediction),
                    'action': self._get_recommended_action(threat_prediction),
                    'timestamp': datetime.now(),
                    'features': features.tolist()
                }
                threats.append(threat)
        
        return threats
    
    def _generate_current_data(self) -> List[Dict[str, Any]]:
        """Generate simulated current system data"""
        data_points = []
        
        # Simulate different types of current activity
        activity_types = ['normal', 'suspicious', 'malicious']
        
        for _ in range(random.randint(1, 5)):
            activity_type = random.choices(activity_types, weights=[0.7, 0.2, 0.1])[0]
            
            if activity_type == 'normal':
                data_point = {
                    'packet_size': random.randint(500, 1500),
                    'connection_count': random.randint(10, 100),
                    'cpu_usage': random.randint(10, 50),
                    'memory_usage': random.randint(20, 60),
                    'file_operations': random.randint(5, 20),
                    'network_connections': random.randint(1, 10),
                    'process_count': random.randint(15, 30),
                    'login_attempts': random.randint(0, 3),
                    'target': f'server-{random.randint(1, 10)}'
                }
            elif activity_type == 'suspicious':
                data_point = {
                    'packet_size': random.randint(1000, 3000),
                    'connection_count': random.randint(80, 200),
                    'cpu_usage': random.randint(60, 80),
                    'memory_usage': random.randint(70, 90),
                    'file_operations': random.randint(30, 60),
                    'network_connections': random.randint(15, 30),
                    'process_count': random.randint(25, 40),
                    'login_attempts': random.randint(5, 15),
                    'target': f'workstation-{random.randint(1, 50)}'
                }
            else:  # malicious
                data_point = {
                    'packet_size': random.randint(500, 10000),
                    'connection_count': random.randint(200, 1000),
                    'cpu_usage': random.randint(80, 100),
                    'memory_usage': random.randint(85, 100),
                    'file_operations': random.randint(80, 200),
                    'network_connections': random.randint(40, 100),
                    'process_count': random.randint(40, 80),
                    'login_attempts': random.randint(20, 100),
                    'target': f'server-{random.randint(1, 10)}'
                }
            
            data_points.append(data_point)
        
        return data_points
    
    def _extract_features(self, data_point: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from data point"""
        features = [
            data_point.get('packet_size', 0),
            data_point.get('connection_count', 0),
            data_point.get('cpu_usage', 0),
            data_point.get('memory_usage', 0),
            data_point.get('file_operations', 0),
            data_point.get('network_connections', 0),
            data_point.get('process_count', 0),
            data_point.get('login_attempts', 0)
        ]
        
        return np.array(features).reshape(1, -1)
    
    def _predict_threat(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict threat using ensemble of models"""
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Random Forest prediction
        rf_prediction = self.models['random_forest'].predict(features_scaled)[0]
        rf_proba = self.models['random_forest'].predict_proba(features_scaled)[0]
        
        # Isolation Forest prediction (anomaly detection)
        iso_prediction = self.models['isolation_forest'].predict(features_scaled)[0]
        iso_score = self.models['isolation_forest'].decision_function(features_scaled)[0]
        
        # Ensemble decision
        rf_confidence = max(rf_proba)
        iso_anomaly = iso_prediction == -1
        
        # Combine predictions
        is_threat = (rf_prediction == 1 and rf_confidence > self.sensitivity) or iso_anomaly
        
        # Determine threat type based on feature patterns
        threat_type = self._classify_threat_type(features[0])
        
        # Calculate overall confidence
        confidence = self._calculate_ensemble_confidence(rf_confidence, iso_score, is_threat)
        
        return {
            'is_threat': is_threat,
            'threat_type': threat_type,
            'confidence': confidence,
            'rf_prediction': rf_prediction,
            'rf_confidence': rf_confidence,
            'iso_anomaly': iso_anomaly,
            'iso_score': iso_score
        }
    
    def _classify_threat_type(self, features: np.ndarray) -> str:
        """Classify specific threat type based on feature patterns"""
        packet_size, conn_count, cpu, memory, file_ops, net_conns, processes, logins = features
        
        # DDoS characteristics
        if conn_count > 300 and net_conns > 50:
            return "DDoS Attack"
        
        # Brute force characteristics
        elif logins > 20:
            return "Brute Force Attack"
        
        # Malware characteristics
        elif cpu > 85 and memory > 80 and file_ops > 50:
            return "Malware Activity"
        
        # Data exfiltration characteristics
        elif packet_size > 5000 and net_conns > 30:
            return "Data Exfiltration"
        
        # Ransomware characteristics
        elif file_ops > 80 and cpu > 70:
            return "Ransomware Activity"
        
        # Default
        else:
            return "Suspicious Activity"
    
    def _calculate_ensemble_confidence(self, rf_confidence: float, iso_score: float, is_threat: bool) -> float:
        """Calculate ensemble confidence score"""
        if not is_threat:
            return 0.0
        
        # Normalize isolation forest score to 0-1 range
        normalized_iso_score = max(0, min(1, (iso_score + 0.5) / 1.0))
        
        # Weighted ensemble
        ensemble_confidence = 0.7 * rf_confidence + 0.3 * normalized_iso_score
        
        return min(1.0, ensemble_confidence)
    
    def _generate_threat_description(self, prediction: Dict[str, Any]) -> str:
        """Generate human-readable threat description"""
        threat_type = prediction['threat_type']
        confidence = prediction['confidence']
        
        descriptions = {
            "DDoS Attack": f"Distributed Denial of Service attack detected with {confidence:.1%} confidence. High connection volume indicates attempt to overwhelm system resources.",
            "Brute Force Attack": f"Brute force authentication attack detected with {confidence:.1%} confidence. Excessive login attempts suggest credential compromise attempt.",
            "Malware Activity": f"Malicious software activity detected with {confidence:.1%} confidence. High resource usage patterns consistent with malware execution.",
            "Data Exfiltration": f"Data exfiltration attempt detected with {confidence:.1%} confidence. Large data transfers suggest unauthorized information theft.",
            "Ransomware Activity": f"Ransomware activity detected with {confidence:.1%} confidence. File system modifications consistent with encryption malware.",
            "Suspicious Activity": f"Suspicious system behavior detected with {confidence:.1%} confidence. Activity patterns deviate from normal baseline."
        }
        
        return descriptions.get(threat_type, f"Unknown threat type detected with {confidence:.1%} confidence.")
    
    def _get_recommended_action(self, prediction: Dict[str, Any]) -> str:
        """Get recommended action for detected threat"""
        threat_type = prediction['threat_type']
        confidence = prediction['confidence']
        
        if confidence > 0.9:
            severity = "immediate"
        elif confidence > 0.7:
            severity = "urgent"
        else:
            severity = "normal"
        
        actions = {
            "DDoS Attack": {
                "immediate": "Activate DDoS mitigation, rate limit connections",
                "urgent": "Monitor traffic patterns, prepare mitigation",
                "normal": "Analyze traffic and increase monitoring"
            },
            "Brute Force Attack": {
                "immediate": "Block source IP, force password reset",
                "urgent": "Increase account lockout thresholds",
                "normal": "Monitor authentication logs"
            },
            "Malware Activity": {
                "immediate": "Isolate system, run full antivirus scan",
                "urgent": "Quarantine suspicious processes",
                "normal": "Increase endpoint monitoring"
            },
            "Data Exfiltration": {
                "immediate": "Block external connections, investigate data flows",
                "urgent": "Monitor network traffic for anomalies",
                "normal": "Review data access patterns"
            },
            "Ransomware Activity": {
                "immediate": "Isolate system, restore from clean backups",
                "urgent": "Terminate suspicious processes",
                "normal": "Verify backup integrity"
            }
        }
        
        return actions.get(threat_type, {}).get(severity, "Monitor and investigate")
    
    def set_sensitivity(self, sensitivity: float):
        """Set detection sensitivity threshold"""
        self.sensitivity = max(0.1, min(1.0, sensitivity))
    
    def set_monitored_threats(self, threats: List[str]):
        """Set list of monitored threat types"""
        self.monitored_threats = threats
    
    def get_attack_vectors(self) -> Dict[str, int]:
        """Get distribution of attack vectors from recent detections"""
        # Simulate attack vector data
        return {
            'Network-based': 45,
            'Endpoint-based': 32,
            'Email-based': 18,
            'Web-based': 23,
            'Physical': 5,
            'Social Engineering': 12
        }
    
    def get_confidence_distribution(self) -> List[float]:
        """Get distribution of confidence scores"""
        # Simulate confidence distribution
        return [random.uniform(0.6, 1.0) for _ in range(100)]
    
    def get_model_statistics(self) -> Dict[str, Any]:
        """Get AI model performance statistics"""
        return self.model_stats
    
    def retrain_models(self):
        """Retrain AI models with updated data"""
        # Simulate model retraining
        self.model_stats['last_trained'] = datetime.now().strftime('%Y-%m-%d')
        self.model_stats['accuracy'] = random.uniform(0.92, 0.97)
        self.model_stats['false_positive_rate'] = random.uniform(0.03, 0.08)
    
    def update_model_config(self, selected_models: List[str], ensemble_weight: float, confidence_threshold: float):
        """Update model configuration"""
        self.sensitivity = confidence_threshold
        # Additional model configuration logic would go here
    
    def get_threat_predictions(self) -> Dict[str, Any]:
        """Get predictive threat analysis"""
        # Simulate threat predictions
        base_date = datetime.now()
        dates = [(base_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
        
        # Generate predicted threat volumes
        predicted_threats = [random.randint(15, 45) for _ in range(7)]
        
        # High-risk periods
        high_risk_periods = [
            {
                'date': dates[2],
                'risk_level': 'High',
                'confidence': 0.78
            },
            {
                'date': dates[5],
                'risk_level': 'Medium',
                'confidence': 0.65
            }
        ]
        
        return {
            'dates': dates,
            'predicted_threats': predicted_threats,
            'high_risk_periods': high_risk_periods
        }
