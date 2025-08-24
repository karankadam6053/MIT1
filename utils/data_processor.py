import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import json
import hashlib
from collections import defaultdict, Counter
import statistics
import random

class DataProcessor:
    """Advanced data processing utilities for security analytics"""
    
    def __init__(self):
        self.historical_data = defaultdict(list)
        self.metrics_cache = {}
        self.cache_expiry = {}
        self.baseline_data = {}
        self.anomaly_thresholds = self._initialize_anomaly_thresholds()
        self.correlation_rules = self._initialize_correlation_rules()
        
    def _initialize_anomaly_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Initialize anomaly detection thresholds"""
        return {
            'network_traffic': {
                'packets_per_second': {'min': 100, 'max': 10000, 'std_dev_multiplier': 3.0},
                'bytes_per_second': {'min': 1000, 'max': 100000000, 'std_dev_multiplier': 3.0},
                'connection_rate': {'min': 1, 'max': 1000, 'std_dev_multiplier': 2.5}
            },
            'endpoint_behavior': {
                'cpu_usage': {'min': 0, 'max': 100, 'std_dev_multiplier': 2.0},
                'memory_usage': {'min': 0, 'max': 100, 'std_dev_multiplier': 2.0},
                'process_count': {'min': 10, 'max': 500, 'std_dev_multiplier': 2.5},
                'file_operations': {'min': 0, 'max': 10000, 'std_dev_multiplier': 3.0}
            },
            'user_behavior': {
                'login_frequency': {'min': 0, 'max': 10, 'std_dev_multiplier': 2.0},
                'data_access_rate': {'min': 0, 'max': 1000, 'std_dev_multiplier': 2.5},
                'failed_attempts': {'min': 0, 'max': 5, 'std_dev_multiplier': 1.5}
            }
        }
    
    def _initialize_correlation_rules(self) -> List[Dict[str, Any]]:
        """Initialize correlation rules for cross-system analysis"""
        return [
            {
                'name': 'Coordinated Attack Pattern',
                'description': 'Multiple systems showing similar attack indicators',
                'conditions': {
                    'time_window': 1800,  # 30 minutes
                    'min_systems': 3,
                    'similarity_threshold': 0.8
                },
                'severity': 'Critical'
            },
            {
                'name': 'Lateral Movement Detection',
                'description': 'Sequential compromise across network segments',
                'conditions': {
                    'time_window': 3600,  # 1 hour
                    'min_hops': 2,
                    'progression_pattern': 'sequential'
                },
                'severity': 'High'
            },
            {
                'name': 'Data Exfiltration Chain',
                'description': 'File access followed by network transfer',
                'conditions': {
                    'time_window': 900,  # 15 minutes
                    'sequence': ['file_access', 'network_transfer'],
                    'data_threshold': 100  # MB
                },
                'severity': 'Critical'
            }
        ]
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics and KPIs"""
        cache_key = 'security_metrics'
        
        # Check cache
        if self._is_cache_valid(cache_key):
            return self.metrics_cache[cache_key]
        
        # Calculate metrics
        current_time = datetime.now()
        
        # Mean Time to Detection (MTTD)
        mttd = self._calculate_mttd()
        mttd_trend = self._calculate_trend('mttd', mttd)
        
        # Mean Time to Response (MTTR)
        mttr = self._calculate_mttr()
        mttr_trend = self._calculate_trend('mttr', mttr)
        
        # Security Score
        security_score = self._calculate_security_score()
        score_trend = self._calculate_trend('security_score', security_score)
        
        # Threat Volume
        threat_volume = self._calculate_threat_volume()
        volume_trend = self._calculate_trend('threat_volume', threat_volume)
        
        # False Positive Rate
        fp_rate = self._calculate_false_positive_rate()
        fp_trend = self._calculate_trend('false_positive_rate', fp_rate)
        
        metrics = {
            'mttd': mttd,
            'mttd_trend': mttd_trend,
            'mttr': mttr,
            'mttr_trend': mttr_trend,
            'security_score': security_score,
            'score_trend': score_trend,
            'threat_volume': threat_volume,
            'volume_trend': volume_trend,
            'false_positive_rate': fp_rate,
            'fp_trend': fp_trend,
            'last_updated': current_time
        }
        
        # Cache results
        self.metrics_cache[cache_key] = metrics
        self.cache_expiry[cache_key] = current_time + timedelta(minutes=5)
        
        return metrics
    
    def get_threat_heatmap(self) -> Dict[str, Any]:
        """Generate threat activity heatmap data"""
        cache_key = 'threat_heatmap'
        
        if self._is_cache_valid(cache_key):
            return self.metrics_cache[cache_key]
        
        # Generate 7 days x 24 hours heatmap
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        hours = [f'{i:02d}:00' for i in range(24)]
        
        # Simulate threat activity patterns
        # Higher activity during business hours and weekdays
        data = []
        for day_idx, day in enumerate(days):
            day_data = []
            for hour_idx, hour in enumerate(hours):
                # Base activity level
                base_activity = 10
                
                # Business hours boost (9 AM - 5 PM)
                if 9 <= hour_idx <= 17:
                    base_activity += 20
                
                # Weekday boost
                if day_idx < 5:  # Monday to Friday
                    base_activity += 15
                
                # Add random variation
                activity = max(0, base_activity + random.randint(-10, 25))
                day_data.append(activity)
            
            data.append(day_data)
        
        heatmap_data = {
            'data': data,
            'days': days,
            'hours': hours,
            'max_value': max(max(row) for row in data),
            'min_value': min(min(row) for row in data)
        }
        
        # Cache results
        self.metrics_cache[cache_key] = heatmap_data
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        
        return heatmap_data
    
    def get_attack_vector_analysis(self) -> Dict[str, int]:
        """Analyze and return attack vector distribution"""
        cache_key = 'attack_vectors'
        
        if self._is_cache_valid(cache_key):
            return self.metrics_cache[cache_key]
        
        # Simulate attack vector data based on current threat landscape
        attack_vectors = {
            'Email/Phishing': random.randint(150, 300),
            'Web Applications': random.randint(100, 200),
            'Network Services': random.randint(80, 150),
            'Malware': random.randint(60, 120),
            'Social Engineering': random.randint(40, 80),
            'Physical Access': random.randint(10, 30),
            'Supply Chain': random.randint(5, 20),
            'Cloud Services': random.randint(70, 140),
            'Mobile Devices': random.randint(30, 70),
            'IoT Devices': random.randint(25, 60),
            'Insider Threats': random.randint(5, 25),
            'API Abuse': random.randint(40, 90)
        }
        
        # Cache results
        self.metrics_cache[cache_key] = attack_vectors
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=6)
        
        return attack_vectors
    
    def detect_anomalies(self, data_stream: List[Dict[str, Any]], metric_type: str) -> List[Dict[str, Any]]:
        """Detect anomalies in data streams using statistical methods"""
        anomalies = []
        
        if not data_stream or metric_type not in self.anomaly_thresholds:
            return anomalies
        
        thresholds = self.anomaly_thresholds[metric_type]
        
        for metric_name, threshold_config in thresholds.items():
            # Extract metric values from data stream
            values = []
            for data_point in data_stream:
                if metric_name in data_point:
                    values.append(data_point[metric_name])
            
            if len(values) < 3:  # Need minimum data points
                continue
            
            # Calculate statistical measures
            mean_val = statistics.mean(values)
            std_dev = statistics.stdev(values) if len(values) > 1 else 0
            
            # Check for anomalies
            for i, value in enumerate(values):
                is_anomaly = False
                anomaly_type = None
                
                # Check against absolute thresholds
                if value < threshold_config['min'] or value > threshold_config['max']:
                    is_anomaly = True
                    anomaly_type = 'threshold_violation'
                
                # Check against statistical thresholds
                elif std_dev > 0:
                    z_score = abs(value - mean_val) / std_dev
                    if z_score > threshold_config['std_dev_multiplier']:
                        is_anomaly = True
                        anomaly_type = 'statistical_outlier'
                
                if is_anomaly:
                    anomaly = {
                        'timestamp': data_stream[i].get('timestamp', datetime.now()),
                        'metric_type': metric_type,
                        'metric_name': metric_name,
                        'value': value,
                        'expected_range': {
                            'min': mean_val - (std_dev * threshold_config['std_dev_multiplier']),
                            'max': mean_val + (std_dev * threshold_config['std_dev_multiplier'])
                        },
                        'anomaly_type': anomaly_type,
                        'severity': self._calculate_anomaly_severity(value, mean_val, std_dev),
                        'confidence': self._calculate_anomaly_confidence(z_score if std_dev > 0 else 0)
                    }
                    anomalies.append(anomaly)
        
        return anomalies
    
    def correlate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate security events across different systems"""
        correlations = []
        
        if len(events) < 2:
            return correlations
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', datetime.now()))
        
        for rule in self.correlation_rules:
            correlation_result = self._apply_correlation_rule(sorted_events, rule)
            if correlation_result:
                correlations.append(correlation_result)
        
        return correlations
    
    def calculate_risk_score(self, asset_data: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score for assets"""
        # Asset criticality weight (0.0 - 1.0)
        criticality_weights = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.6,
            'Low': 0.4
        }
        
        asset_criticality = asset_data.get('criticality', 'Medium')
        criticality_weight = criticality_weights.get(asset_criticality, 0.6)
        
        # Threat likelihood (0.0 - 1.0)
        threat_likelihood = threat_data.get('likelihood', 0.5)
        
        # Vulnerability score (0.0 - 10.0, normalize to 0.0 - 1.0)
        vulnerability_score = asset_data.get('vulnerability_score', 5.0) / 10.0
        
        # Impact score based on asset type and data sensitivity
        impact_multipliers = {
            'financial_data': 1.0,
            'personal_data': 0.9,
            'intellectual_property': 0.85,
            'operational_data': 0.7,
            'public_data': 0.3
        }
        
        data_sensitivity = asset_data.get('data_sensitivity', 'operational_data')
        impact_multiplier = impact_multipliers.get(data_sensitivity, 0.7)
        
        # Calculate base risk score
        base_risk = (threat_likelihood * vulnerability_score * criticality_weight * impact_multiplier) * 10
        
        # Adjust for mitigating factors
        mitigation_factor = 1.0
        
        # Security controls
        security_controls = asset_data.get('security_controls', [])
        mitigation_factor -= len(security_controls) * 0.05  # 5% reduction per control
        
        # Monitoring coverage
        if asset_data.get('monitoring_enabled', False):
            mitigation_factor -= 0.1
        
        # Update frequency
        days_since_update = asset_data.get('days_since_update', 30)
        if days_since_update > 30:
            mitigation_factor += 0.1  # Increase risk for outdated systems
        
        # Calculate final risk score
        final_risk_score = max(0.0, min(10.0, base_risk * max(0.1, mitigation_factor)))
        
        # Determine risk level
        if final_risk_score >= 8.0:
            risk_level = 'Critical'
        elif final_risk_score >= 6.0:
            risk_level = 'High'
        elif final_risk_score >= 4.0:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'risk_score': round(final_risk_score, 2),
            'risk_level': risk_level,
            'components': {
                'threat_likelihood': threat_likelihood,
                'vulnerability_score': vulnerability_score,
                'asset_criticality': criticality_weight,
                'impact_multiplier': impact_multiplier,
                'mitigation_factor': mitigation_factor
            },
            'recommendations': self._generate_risk_recommendations(final_risk_score, asset_data)
        }
    
    def generate_executive_summary(self, time_period: str = 'last_7_days') -> Dict[str, Any]:
        """Generate executive summary of security posture"""
        current_time = datetime.now()
        
        # Define time range
        if time_period == 'last_24_hours':
            start_time = current_time - timedelta(days=1)
        elif time_period == 'last_7_days':
            start_time = current_time - timedelta(days=7)
        elif time_period == 'last_30_days':
            start_time = current_time - timedelta(days=30)
        else:
            start_time = current_time - timedelta(days=7)
        
        # Simulate executive metrics
        summary = {
            'time_period': time_period,
            'generated_at': current_time,
            'overall_security_posture': self._calculate_security_posture(),
            'key_metrics': {
                'incidents_resolved': random.randint(15, 45),
                'mean_resolution_time': f'{random.randint(2, 8)} hours',
                'false_positive_rate': f'{random.uniform(2.0, 8.0):.1f}%',
                'system_uptime': f'{random.uniform(99.0, 99.9):.2f}%',
                'compliance_score': f'{random.uniform(85.0, 98.0):.1f}%'
            },
            'threat_landscape': {
                'total_threats_detected': random.randint(100, 500),
                'critical_threats': random.randint(2, 8),
                'threats_blocked': random.randint(95, 490),
                'new_threat_types': random.randint(1, 5)
            },
            'top_threats': [
                {'name': 'Phishing Campaigns', 'count': random.randint(50, 150), 'trend': 'increasing'},
                {'name': 'Malware Attempts', 'count': random.randint(30, 100), 'trend': 'stable'},
                {'name': 'Network Intrusions', 'count': random.randint(10, 50), 'trend': 'decreasing'},
                {'name': 'Data Exfiltration', 'count': random.randint(5, 25), 'trend': 'stable'}
            ],
            'recommendations': [
                'Increase user security awareness training frequency',
                'Update endpoint protection policies',
                'Review and strengthen network segmentation',
                'Implement additional monitoring for cloud services'
            ],
            'investments_roi': {
                'security_tools': f'{random.randint(150, 300)}% ROI',
                'staff_training': f'{random.randint(200, 400)}% ROI',
                'threat_intelligence': f'{random.randint(180, 350)}% ROI'
            }
        }
        
        return summary
    
    def _calculate_mttd(self) -> float:
        """Calculate Mean Time to Detection"""
        # Simulate MTTD calculation
        detection_times = [random.uniform(5.0, 45.0) for _ in range(20)]
        return round(statistics.mean(detection_times), 1)
    
    def _calculate_mttr(self) -> float:
        """Calculate Mean Time to Response"""
        # Simulate MTTR calculation
        response_times = [random.uniform(15.0, 120.0) for _ in range(20)]
        return round(statistics.mean(response_times), 1)
    
    def _calculate_security_score(self) -> float:
        """Calculate overall security score"""
        # Simulate security score based on multiple factors
        base_score = 8.5
        
        # Random variations
        score_adjustment = random.uniform(-1.0, 1.0)
        
        return round(max(0.0, min(10.0, base_score + score_adjustment)), 1)
    
    def _calculate_threat_volume(self) -> int:
        """Calculate current threat volume"""
        # Simulate threat volume
        base_volume = 75
        daily_variation = random.randint(-20, 30)
        
        return max(0, base_volume + daily_variation)
    
    def _calculate_false_positive_rate(self) -> float:
        """Calculate false positive rate"""
        # Simulate FP rate
        return round(random.uniform(0.02, 0.08), 3)
    
    def _calculate_trend(self, metric_name: str, current_value: float) -> float:
        """Calculate trend for a metric"""
        # Store current value in historical data
        self.historical_data[metric_name].append({
            'timestamp': datetime.now(),
            'value': current_value
        })
        
        # Keep only last 30 data points
        self.historical_data[metric_name] = self.historical_data[metric_name][-30:]
        
        # Calculate trend
        if len(self.historical_data[metric_name]) < 2:
            return 0.0
        
        recent_values = [point['value'] for point in self.historical_data[metric_name][-5:]]
        older_values = [point['value'] for point in self.historical_data[metric_name][-10:-5]]
        
        if not older_values:
            return 0.0
        
        recent_avg = statistics.mean(recent_values)
        older_avg = statistics.mean(older_values)
        
        trend = recent_avg - older_avg
        return round(trend, 2)
    
    def _calculate_anomaly_severity(self, value: float, mean_val: float, std_dev: float) -> str:
        """Calculate severity of detected anomaly"""
        if std_dev == 0:
            return 'Medium'
        
        z_score = abs(value - mean_val) / std_dev
        
        if z_score > 4.0:
            return 'Critical'
        elif z_score > 3.0:
            return 'High'
        elif z_score > 2.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_anomaly_confidence(self, z_score: float) -> float:
        """Calculate confidence level for anomaly detection"""
        # Higher z-score = higher confidence
        confidence = min(0.95, 0.5 + (z_score * 0.1))
        return round(confidence, 3)
    
    def _apply_correlation_rule(self, events: List[Dict[str, Any]], rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Apply correlation rule to event list"""
        rule_name = rule['name']
        conditions = rule['conditions']
        
        if rule_name == 'Coordinated Attack Pattern':
            return self._check_coordinated_attack(events, conditions)
        elif rule_name == 'Lateral Movement Detection':
            return self._check_lateral_movement(events, conditions)
        elif rule_name == 'Data Exfiltration Chain':
            return self._check_exfiltration_chain(events, conditions)
        
        return None
    
    def _check_coordinated_attack(self, events: List[Dict[str, Any]], conditions: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for coordinated attack patterns"""
        time_window = conditions['time_window']
        min_systems = conditions['min_systems']
        
        # Group events by time windows
        current_time = datetime.now()
        window_start = current_time - timedelta(seconds=time_window)
        
        recent_events = [e for e in events if e.get('timestamp', datetime.now()) > window_start]
        
        if len(recent_events) < min_systems:
            return None
        
        # Check for similar attack patterns
        attack_types = [e.get('attack_type', 'unknown') for e in recent_events]
        most_common = Counter(attack_types).most_common(1)
        
        if most_common and most_common[0][1] >= min_systems:
            return {
                'rule_name': 'Coordinated Attack Pattern',
                'confidence': 0.85,
                'affected_systems': len(set(e.get('system', 'unknown') for e in recent_events)),
                'attack_type': most_common[0][0],
                'event_count': len(recent_events),
                'time_span': f'{time_window} seconds'
            }
        
        return None
    
    def _check_lateral_movement(self, events: List[Dict[str, Any]], conditions: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for lateral movement patterns"""
        time_window = conditions['time_window']
        min_hops = conditions['min_hops']
        
        # Look for sequential system compromises
        compromise_events = [e for e in events if e.get('event_type') == 'system_compromise']
        
        if len(compromise_events) < min_hops:
            return None
        
        # Check temporal sequence
        systems_compromised = []
        for event in compromise_events:
            system = event.get('system')
            if system and system not in systems_compromised:
                systems_compromised.append(system)
        
        if len(systems_compromised) >= min_hops:
            return {
                'rule_name': 'Lateral Movement Detection',
                'confidence': 0.78,
                'systems_compromised': systems_compromised,
                'hop_count': len(systems_compromised),
                'time_span': f'{time_window} seconds'
            }
        
        return None
    
    def _check_exfiltration_chain(self, events: List[Dict[str, Any]], conditions: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for data exfiltration chains"""
        time_window = conditions['time_window']
        sequence = conditions['sequence']
        
        # Look for file access followed by network transfer
        file_events = [e for e in events if e.get('event_type') == 'file_access']
        network_events = [e for e in events if e.get('event_type') == 'network_transfer']
        
        for file_event in file_events:
            file_time = file_event.get('timestamp', datetime.now())
            
            # Look for network events within time window
            for network_event in network_events:
                network_time = network_event.get('timestamp', datetime.now())
                
                if abs((network_time - file_time).total_seconds()) <= time_window:
                    data_size = network_event.get('data_size_mb', 0)
                    
                    if data_size >= conditions['data_threshold']:
                        return {
                            'rule_name': 'Data Exfiltration Chain',
                            'confidence': 0.92,
                            'file_accessed': file_event.get('file_path', 'unknown'),
                            'data_transferred_mb': data_size,
                            'destination': network_event.get('destination', 'unknown'),
                            'time_span': f'{abs((network_time - file_time).total_seconds())} seconds'
                        }
        
        return None
    
    def _calculate_security_posture(self) -> Dict[str, Any]:
        """Calculate overall security posture"""
        # Simulate security posture calculation
        posture_score = random.uniform(7.5, 9.2)
        
        if posture_score >= 9.0:
            posture_level = 'Excellent'
            posture_color = 'green'
        elif posture_score >= 8.0:
            posture_level = 'Good'
            posture_color = 'lightgreen'
        elif posture_score >= 7.0:
            posture_level = 'Fair'
            posture_color = 'yellow'
        else:
            posture_level = 'Poor'
            posture_color = 'red'
        
        return {
            'score': round(posture_score, 1),
            'level': posture_level,
            'color': posture_color,
            'trend': random.choice(['improving', 'stable', 'declining'])
        }
    
    def _generate_risk_recommendations(self, risk_score: float, asset_data: Dict[str, Any]) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        if risk_score >= 8.0:
            recommendations.extend([
                'Immediate isolation and incident response required',
                'Deploy additional monitoring and protection',
                'Conduct thorough security assessment'
            ])
        elif risk_score >= 6.0:
            recommendations.extend([
                'Increase monitoring frequency',
                'Apply security patches immediately',
                'Review and update security controls'
            ])
        elif risk_score >= 4.0:
            recommendations.extend([
                'Schedule security update within 48 hours',
                'Review access controls and permissions',
                'Consider additional security controls'
            ])
        else:
            recommendations.append('Continue regular monitoring and maintenance')
        
        # Asset-specific recommendations
        if not asset_data.get('monitoring_enabled', False):
            recommendations.append('Enable continuous monitoring')
        
        if asset_data.get('days_since_update', 0) > 30:
            recommendations.append('Update system and apply security patches')
        
        if len(asset_data.get('security_controls', [])) < 3:
            recommendations.append('Implement additional security controls')
        
        return recommendations
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid"""
        if cache_key not in self.cache_expiry:
            return False
        
        return datetime.now() < self.cache_expiry[cache_key]
