import random
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import json
import hashlib
import uuid
from collections import defaultdict

class IoTMonitor:
    """IoT device security monitoring and management system"""
    
    def __init__(self):
        self.iot_devices = []
        self.device_profiles = {}
        self.vulnerability_database = self._load_vulnerability_database()
        self.device_baselines = {}
        self.security_policies = self._load_security_policies()
        self.monitoring_active = False
        self.threat_patterns = self._load_iot_threat_patterns()
        self.device_manufacturers = self._load_device_manufacturers()
        self._initialize_iot_devices()
        
    def _load_vulnerability_database(self) -> Dict[str, Dict[str, Any]]:
        """Load IoT vulnerability database"""
        return {
            'default_credentials': {
                'severity': 'Critical',
                'cvss_score': 9.8,
                'description': 'Device uses default username/password',
                'remediation': 'Change default credentials immediately',
                'affected_devices': ['cameras', 'routers', 'printers', 'smart_locks']
            },
            'unencrypted_communication': {
                'severity': 'High',
                'cvss_score': 7.5,
                'description': 'Device communicates without encryption',
                'remediation': 'Enable encryption or use VPN',
                'affected_devices': ['sensors', 'controllers', 'older_cameras']
            },
            'firmware_outdated': {
                'severity': 'High',
                'cvss_score': 8.1,
                'description': 'Device firmware is outdated and vulnerable',
                'remediation': 'Update firmware to latest version',
                'affected_devices': ['all']
            },
            'weak_authentication': {
                'severity': 'Medium',
                'cvss_score': 6.5,
                'description': 'Device uses weak authentication mechanisms',
                'remediation': 'Implement strong authentication',
                'affected_devices': ['smart_home', 'wearables']
            },
            'open_ports': {
                'severity': 'Medium',
                'cvss_score': 5.3,
                'description': 'Unnecessary ports are open on device',
                'remediation': 'Close unused ports and services',
                'affected_devices': ['routers', 'cameras', 'servers']
            },
            'buffer_overflow': {
                'severity': 'Critical',
                'cvss_score': 9.0,
                'description': 'Device vulnerable to buffer overflow attacks',
                'remediation': 'Apply security patch or replace device',
                'affected_devices': ['cameras', 'routers', 'smart_tvs']
            },
            'insecure_update_mechanism': {
                'severity': 'High',
                'cvss_score': 7.8,
                'description': 'Device update mechanism is insecure',
                'remediation': 'Implement secure update mechanism',
                'affected_devices': ['smart_home', 'industrial']
            }
        }
    
    def _load_security_policies(self) -> Dict[str, Any]:
        """Load IoT security policies"""
        return {
            'password_policy': {
                'min_length': 12,
                'require_complexity': True,
                'change_interval_days': 90,
                'no_default_passwords': True
            },
            'network_policy': {
                'require_encryption': True,
                'allowed_protocols': ['HTTPS', 'SSH', 'SFTP'],
                'blocked_protocols': ['HTTP', 'Telnet', 'FTP'],
                'network_segmentation': True
            },
            'firmware_policy': {
                'auto_update': False,  # Manual approval required
                'max_days_outdated': 30,
                'require_signed_updates': True,
                'test_before_deploy': True
            },
            'monitoring_policy': {
                'continuous_monitoring': True,
                'anomaly_detection': True,
                'traffic_analysis': True,
                'behavioral_profiling': True
            },
            'access_policy': {
                'principle_of_least_privilege': True,
                'regular_access_review': True,
                'multi_factor_authentication': True,
                'session_timeout_minutes': 30
            }
        }
    
    def _load_iot_threat_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load IoT-specific threat patterns"""
        return {
            'botnet_recruitment': {
                'indicators': ['unusual_outbound_traffic', 'c2_communication', 'port_scanning'],
                'description': 'Device recruited into botnet',
                'severity': 'Critical',
                'mitigation': ['isolate_device', 'firmware_update', 'factory_reset']
            },
            'credential_brute_force': {
                'indicators': ['multiple_failed_logins', 'dictionary_attacks', 'timing_attacks'],
                'description': 'Brute force attack against device credentials',
                'severity': 'High',
                'mitigation': ['enable_lockout', 'strong_passwords', 'monitoring']
            },
            'firmware_tampering': {
                'indicators': ['checksum_mismatch', 'unauthorized_changes', 'boot_anomalies'],
                'description': 'Device firmware has been tampered with',
                'severity': 'Critical',
                'mitigation': ['firmware_verification', 'secure_boot', 'device_replacement']
            },
            'data_exfiltration': {
                'indicators': ['large_data_transfers', 'unusual_destinations', 'encrypted_traffic'],
                'description': 'Sensitive data being exfiltrated from device',
                'severity': 'High',
                'mitigation': ['network_monitoring', 'data_classification', 'access_controls']
            },
            'denial_of_service': {
                'indicators': ['resource_exhaustion', 'flooding_attacks', 'crash_patterns'],
                'description': 'Device under denial of service attack',
                'severity': 'Medium',
                'mitigation': ['rate_limiting', 'resource_monitoring', 'failover']
            },
            'physical_tampering': {
                'indicators': ['hardware_changes', 'debug_port_access', 'case_opening'],
                'description': 'Physical tampering detected on device',
                'severity': 'High',
                'mitigation': ['tamper_detection', 'secure_housing', 'alarm_systems']
            },
            'man_in_the_middle': {
                'indicators': ['certificate_anomalies', 'traffic_interception', 'ssl_downgrade'],
                'description': 'MITM attack against device communications',
                'severity': 'High',
                'mitigation': ['certificate_pinning', 'encryption', 'vpn_tunnel']
            }
        }
    
    def _load_device_manufacturers(self) -> Dict[str, Dict[str, Any]]:
        """Load device manufacturer information"""
        return {
            'Hikvision': {
                'security_score': 6.5,
                'common_vulnerabilities': ['default_credentials', 'firmware_outdated'],
                'products': ['IP Cameras', 'NVRs', 'Access Control'],
                'update_frequency': 'Quarterly'
            },
            'Dahua': {
                'security_score': 6.8,
                'common_vulnerabilities': ['default_credentials', 'unencrypted_communication'],
                'products': ['IP Cameras', 'Video Intercom', 'Thermal Cameras'],
                'update_frequency': 'Bi-annually'
            },
            'Cisco': {
                'security_score': 8.5,
                'common_vulnerabilities': ['firmware_outdated'],
                'products': ['Network Equipment', 'IP Phones', 'Security Appliances'],
                'update_frequency': 'Monthly'
            },
            'Nest': {
                'security_score': 7.8,
                'common_vulnerabilities': ['weak_authentication'],
                'products': ['Smart Thermostats', 'Cameras', 'Doorbells'],
                'update_frequency': 'Monthly'
            },
            'Philips': {
                'security_score': 7.2,
                'common_vulnerabilities': ['unencrypted_communication', 'open_ports'],
                'products': ['Smart Lighting', 'Health Devices', 'Smart TVs'],
                'update_frequency': 'Quarterly'
            },
            'Generic': {
                'security_score': 4.5,
                'common_vulnerabilities': ['default_credentials', 'firmware_outdated', 'weak_authentication'],
                'products': ['Various IoT Devices'],
                'update_frequency': 'Rarely'
            }
        }
    
    def _initialize_iot_devices(self):
        """Initialize IoT device inventory"""
        device_types = [
            'IP Camera', 'Smart Thermostat', 'Smart Lock', 'Industrial Sensor',
            'Smart Light', 'Network Printer', 'Smart TV', 'Wireless Router',
            'Smart Speaker', 'Security System', 'Environmental Monitor', 'Smart Plug'
        ]
        
        manufacturers = list(self.device_manufacturers.keys())
        
        for i in range(35):
            device_type = random.choice(device_types)
            manufacturer = random.choice(manufacturers)
            
            device = {
                'id': str(uuid.uuid4()),
                'name': f'{device_type.replace(" ", "_").lower()}_{i+1:02d}',
                'type': device_type,
                'manufacturer': manufacturer,
                'model': f'{manufacturer}-{random.randint(100, 999)}',
                'ip': f'192.168.1.{random.randint(100, 254)}',
                'mac_address': self._generate_mac_address(),
                'firmware_version': f'{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}',
                'last_seen': datetime.now() - timedelta(minutes=random.randint(0, 60)),
                'security_status': random.choices(['secure', 'warning', 'vulnerable', 'unknown'], 
                                                weights=[0.4, 0.3, 0.2, 0.1])[0],
                'security_score': random.uniform(1.0, 10.0),
                'vulnerabilities': [],
                'open_ports': random.sample([22, 23, 80, 443, 8080, 1900, 5353], random.randint(1, 4)),
                'protocols': random.sample(['HTTP', 'HTTPS', 'SSH', 'Telnet', 'MQTT', 'CoAP'], random.randint(1, 3)),
                'data_sensitivity': random.choice(['Low', 'Medium', 'High', 'Critical']),
                'network_segment': random.choice(['IoT_VLAN', 'Guest_Network', 'Main_Network', 'DMZ']),
                'last_update': datetime.now() - timedelta(days=random.randint(0, 365)),
                'authentication_method': random.choice(['Password', 'Certificate', 'None', 'Multi-factor']),
                'encryption_status': random.choice(['Encrypted', 'Unencrypted', 'Partial']),
                'configuration_status': random.choice(['Default', 'Hardened', 'Custom']),
                'compliance_status': random.choice(['Compliant', 'Non-compliant', 'Unknown']),
                'criticality': random.choice(['Low', 'Medium', 'High', 'Critical']),
                'location': random.choice(['Office', 'Warehouse', 'Reception', 'Server Room', 'Parking Lot']),
                'operational_status': random.choice(['Online', 'Offline', 'Maintenance', 'Error'])
            }
            
            # Assign vulnerabilities based on manufacturer and device type
            device['vulnerabilities'] = self._assign_device_vulnerabilities(device)
            
            # Calculate final security score
            device['security_score'] = self._calculate_device_security_score(device)
            
            # Set security status based on score
            if device['security_score'] >= 8.0:
                device['security_status'] = 'secure'
            elif device['security_score'] >= 6.0:
                device['security_status'] = 'warning'
            else:
                device['security_status'] = 'vulnerable'
            
            self.iot_devices.append(device)
            
            # Create device baseline
            self.device_baselines[device['id']] = {
                'normal_traffic_volume': random.uniform(1.0, 100.0),  # MB/day
                'typical_connections': random.randint(1, 20),
                'standard_ports': device['open_ports'].copy(),
                'baseline_cpu_usage': random.uniform(5.0, 30.0),
                'baseline_memory_usage': random.uniform(20.0, 60.0),
                'normal_update_frequency': random.randint(30, 180),  # days
                'expected_protocols': device['protocols'].copy()
            }
    
    def _assign_device_vulnerabilities(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Assign vulnerabilities to device based on type and manufacturer"""
        vulnerabilities = []
        manufacturer_info = self.device_manufacturers.get(device['manufacturer'], {})
        common_vulns = manufacturer_info.get('common_vulnerabilities', [])
        
        # Assign common vulnerabilities for manufacturer
        for vuln_key in common_vulns:
            if vuln_key in self.vulnerability_database:
                vuln_info = self.vulnerability_database[vuln_key]
                
                if (vuln_info['affected_devices'] == ['all'] or 
                    any(dev_type in device['type'].lower() for dev_type in vuln_info['affected_devices'])):
                    
                    vulnerability = {
                        'cve': f'CVE-2024-{random.randint(1000, 9999)}',
                        'name': vuln_key.replace('_', ' ').title(),
                        'description': vuln_info['description'],
                        'severity': vuln_info['severity'],
                        'cvss_score': vuln_info['cvss_score'],
                        'remediation': vuln_info['remediation'],
                        'discovered_date': datetime.now() - timedelta(days=random.randint(0, 90)),
                        'patch_available': random.choice([True, False]),
                        'exploitability': random.choice(['Low', 'Medium', 'High'])
                    }
                    vulnerabilities.append(vulnerability)
        
        # Random chance of additional vulnerabilities
        for vuln_key, vuln_info in self.vulnerability_database.items():
            if vuln_key not in common_vulns and random.random() < 0.1:  # 10% chance
                if (vuln_info['affected_devices'] == ['all'] or 
                    any(dev_type in device['type'].lower() for dev_type in vuln_info['affected_devices'])):
                    
                    vulnerability = {
                        'cve': f'CVE-2024-{random.randint(1000, 9999)}',
                        'name': vuln_key.replace('_', ' ').title(),
                        'description': vuln_info['description'],
                        'severity': vuln_info['severity'],
                        'cvss_score': vuln_info['cvss_score'],
                        'remediation': vuln_info['remediation'],
                        'discovered_date': datetime.now() - timedelta(days=random.randint(0, 90)),
                        'patch_available': random.choice([True, False]),
                        'exploitability': random.choice(['Low', 'Medium', 'High'])
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _calculate_device_security_score(self, device: Dict[str, Any]) -> float:
        """Calculate security score for device"""
        base_score = self.device_manufacturers.get(device['manufacturer'], {}).get('security_score', 5.0)
        
        # Adjust for vulnerabilities
        vuln_penalty = 0
        for vuln in device['vulnerabilities']:
            if vuln['severity'] == 'Critical':
                vuln_penalty += 2.0
            elif vuln['severity'] == 'High':
                vuln_penalty += 1.5
            elif vuln['severity'] == 'Medium':
                vuln_penalty += 1.0
            else:
                vuln_penalty += 0.5
        
        # Adjust for configuration
        config_bonus = 0
        if device['configuration_status'] == 'Hardened':
            config_bonus += 1.0
        elif device['configuration_status'] == 'Custom':
            config_bonus += 0.5
        elif device['configuration_status'] == 'Default':
            config_bonus -= 1.0
        
        # Adjust for encryption
        if device['encryption_status'] == 'Encrypted':
            config_bonus += 1.0
        elif device['encryption_status'] == 'Unencrypted':
            config_bonus -= 1.5
        
        # Adjust for authentication
        auth_bonus = 0
        if device['authentication_method'] == 'Multi-factor':
            auth_bonus += 1.5
        elif device['authentication_method'] == 'Certificate':
            auth_bonus += 1.0
        elif device['authentication_method'] == 'None':
            auth_bonus -= 2.0
        
        # Calculate final score
        final_score = base_score - vuln_penalty + config_bonus + auth_bonus
        return max(0.0, min(10.0, final_score))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get IoT monitoring statistics"""
        total_devices = len(self.iot_devices)
        
        # Count by security status
        secure_count = len([d for d in self.iot_devices if d['security_status'] == 'secure'])
        warning_count = len([d for d in self.iot_devices if d['security_status'] == 'warning'])
        vulnerable_count = len([d for d in self.iot_devices if d['security_status'] == 'vulnerable'])
        
        # Calculate average security score
        if total_devices > 0:
            avg_security_score = sum(d['security_score'] for d in self.iot_devices) / total_devices
        else:
            avg_security_score = 0.0
        
        # Count online/offline devices
        online_count = len([d for d in self.iot_devices if d['operational_status'] == 'Online'])
        offline_count = len([d for d in self.iot_devices if d['operational_status'] == 'Offline'])
        
        return {
            'total_devices': total_devices,
            'secure': secure_count,
            'warning': warning_count,
            'vulnerable': vulnerable_count,
            'unknown': total_devices - secure_count - warning_count - vulnerable_count,
            'security_score': round(avg_security_score, 1),
            'online': online_count,
            'offline': offline_count,
            'maintenance': len([d for d in self.iot_devices if d['operational_status'] == 'Maintenance']),
            'error': len([d for d in self.iot_devices if d['operational_status'] == 'Error']),
            'critical_vulns': sum(len([v for v in d['vulnerabilities'] if v['severity'] == 'Critical']) 
                                for d in self.iot_devices),
            'high_vulns': sum(len([v for v in d['vulnerabilities'] if v['severity'] == 'High']) 
                            for d in self.iot_devices),
            'devices_need_update': len([d for d in self.iot_devices 
                                      if (datetime.now() - d['last_update']).days > 30])
        }
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """Get all IoT devices"""
        return self.iot_devices
    
    def scan_for_threats(self) -> Dict[str, Any]:
        """Scan IoT devices for security threats"""
        threats = []
        scan_start_time = datetime.now()
        
        for device in self.iot_devices:
            # Check each threat pattern
            for pattern_name, pattern_info in self.threat_patterns.items():
                # Simulate threat detection
                detection_probability = self._calculate_iot_threat_probability(device, pattern_name)
                
                if random.random() < detection_probability:
                    threat = {
                        'device_id': device['id'],
                        'device_name': device['name'],
                        'device_type': device['type'],
                        'device_ip': device['ip'],
                        'threat_pattern': pattern_name,
                        'type': pattern_info['description'],
                        'severity': pattern_info['severity'],
                        'confidence': random.uniform(0.7, 0.95),
                        'detection_time': datetime.now(),
                        'indicators': pattern_info['indicators'],
                        'mitigation_steps': pattern_info['mitigation'],
                        'risk_score': self._calculate_threat_risk_score(device, pattern_info),
                        'recommended_actions': self._get_threat_recommendations(device, pattern_info)
                    }
                    threats.append(threat)
        
        return {
            'scan_time': scan_start_time,
            'devices_scanned': len(self.iot_devices),
            'threats': threats,
            'threat_count': len(threats),
            'critical_threats': len([t for t in threats if t['severity'] == 'Critical']),
            'high_threats': len([t for t in threats if t['severity'] == 'High']),
            'medium_threats': len([t for t in threats if t['severity'] == 'Medium']),
            'scan_duration': (datetime.now() - scan_start_time).total_seconds()
        }
    
    def get_compliance_data(self) -> Dict[str, int]:
        """Get device compliance distribution"""
        compliance_counts = defaultdict(int)
        
        for device in self.iot_devices:
            compliance_counts[device['compliance_status']] += 1
        
        return dict(compliance_counts)
    
    def get_device_by_id(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get specific device by ID"""
        return next((d for d in self.iot_devices if d['id'] == device_id), None)
    
    def update_device_firmware(self, device_id: str) -> Dict[str, Any]:
        """Update device firmware"""
        device = self.get_device_by_id(device_id)
        
        if not device:
            return {'success': False, 'error': 'Device not found'}
        
        try:
            # Simulate firmware update
            old_version = device['firmware_version']
            version_parts = old_version.split('.')
            version_parts[-1] = str(int(version_parts[-1]) + 1)
            new_version = '.'.join(version_parts)
            
            device['firmware_version'] = new_version
            device['last_update'] = datetime.now()
            
            # Remove some vulnerabilities after update
            if device['vulnerabilities']:
                vulnerabilities_to_remove = random.randint(0, len(device['vulnerabilities']) // 2)
                device['vulnerabilities'] = device['vulnerabilities'][vulnerabilities_to_remove:]
            
            # Recalculate security score
            device['security_score'] = self._calculate_device_security_score(device)
            
            return {
                'success': True,
                'old_version': old_version,
                'new_version': new_version,
                'update_time': datetime.now(),
                'vulnerabilities_fixed': vulnerabilities_to_remove
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def quarantine_device(self, device_id: str, reason: str) -> Dict[str, Any]:
        """Quarantine suspicious IoT device"""
        device = self.get_device_by_id(device_id)
        
        if not device:
            return {'success': False, 'error': 'Device not found'}
        
        try:
            device['operational_status'] = 'Quarantined'
            device['quarantine_reason'] = reason
            device['quarantine_time'] = datetime.now()
            device['network_segment'] = 'QUARANTINE_VLAN'
            
            return {
                'success': True,
                'device_name': device['name'],
                'quarantine_reason': reason,
                'quarantine_time': datetime.now()
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_continuous_monitoring(self):
        """Run continuous IoT monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        
        def monitoring_loop():
            while self.monitoring_active:
                try:
                    # Update device status
                    for device in self.iot_devices:
                        self._update_device_status(device)
                    
                    # Check for new threats
                    self._check_for_anomalies()
                    
                    # Update compliance status
                    self._update_compliance_status()
                    
                    time.sleep(120)  # Check every 2 minutes
                    
                except Exception as e:
                    print(f"IoT monitoring error: {e}")
                    time.sleep(300)
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
    
    def _calculate_iot_threat_probability(self, device: Dict[str, Any], threat_pattern: str) -> float:
        """Calculate probability of specific threat for device"""
        base_probabilities = {
            'botnet_recruitment': 0.05,
            'credential_brute_force': 0.08,
            'firmware_tampering': 0.02,
            'data_exfiltration': 0.03,
            'denial_of_service': 0.06,
            'physical_tampering': 0.01,
            'man_in_the_middle': 0.04
        }
        
        base_prob = base_probabilities.get(threat_pattern, 0.02)
        
        # Adjust based on device security score
        security_factor = (10.0 - device['security_score']) / 10.0
        
        # Adjust based on device type (some are more targeted)
        type_multipliers = {
            'IP Camera': 1.5,
            'Smart Lock': 1.3,
            'Wireless Router': 1.4,
            'Industrial Sensor': 1.2,
            'Smart Thermostat': 0.8
        }
        
        type_multiplier = type_multipliers.get(device['type'], 1.0)
        
        final_probability = min(0.3, base_prob * security_factor * type_multiplier)
        
        return final_probability
    
    def _calculate_threat_risk_score(self, device: Dict[str, Any], pattern_info: Dict[str, Any]) -> float:
        """Calculate risk score for detected threat"""
        severity_scores = {
            'Critical': 10.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        }
        
        base_score = severity_scores.get(pattern_info['severity'], 5.0)
        
        # Adjust for device criticality
        criticality_multipliers = {
            'Critical': 1.5,
            'High': 1.3,
            'Medium': 1.0,
            'Low': 0.8
        }
        
        criticality_multiplier = criticality_multipliers.get(device['criticality'], 1.0)
        
        # Adjust for data sensitivity
        sensitivity_multipliers = {
            'Critical': 1.4,
            'High': 1.2,
            'Medium': 1.0,
            'Low': 0.9
        }
        
        sensitivity_multiplier = sensitivity_multipliers.get(device['data_sensitivity'], 1.0)
        
        final_score = min(10.0, base_score * criticality_multiplier * sensitivity_multiplier)
        
        return round(final_score, 1)
    
    def _get_threat_recommendations(self, device: Dict[str, Any], pattern_info: Dict[str, Any]) -> List[str]:
        """Get recommendations for addressing threat"""
        recommendations = pattern_info['mitigation'].copy()
        
        # Add device-specific recommendations
        if device['configuration_status'] == 'Default':
            recommendations.append('Change device default configuration')
        
        if device['authentication_method'] == 'None':
            recommendations.append('Enable authentication on device')
        
        if device['encryption_status'] == 'Unencrypted':
            recommendations.append('Enable encryption for device communications')
        
        if (datetime.now() - device['last_update']).days > 90:
            recommendations.append('Update device firmware')
        
        return recommendations
    
    def _update_device_status(self, device: Dict[str, Any]):
        """Update individual device status"""
        # Simulate status changes
        if random.random() < 0.03:  # 3% chance of status change
            current_status = device['operational_status']
            
            if current_status == 'Online':
                device['operational_status'] = random.choices(
                    ['Offline', 'Maintenance', 'Error'], 
                    weights=[0.5, 0.3, 0.2]
                )[0]
            elif current_status == 'Offline':
                device['operational_status'] = random.choices(
                    ['Online', 'Maintenance'], 
                    weights=[0.8, 0.2]
                )[0]
            elif current_status in ['Maintenance', 'Error']:
                device['operational_status'] = random.choices(
                    ['Online', 'Offline'], 
                    weights=[0.7, 0.3]
                )[0]
        
        # Update last seen time for online devices
        if device['operational_status'] == 'Online':
            device['last_seen'] = datetime.now()
    
    def _check_for_anomalies(self):
        """Check for behavioral anomalies"""
        for device in self.iot_devices:
            baseline = self.device_baselines.get(device['id'])
            if not baseline:
                continue
            
            # Check for traffic anomalies
            if random.random() < 0.02:  # 2% chance of anomaly
                device['security_status'] = 'warning'
                print(f"Anomaly detected on device {device['name']}")
    
    def _update_compliance_status(self):
        """Update device compliance status"""
        for device in self.iot_devices:
            # Check compliance factors
            compliance_score = 1.0
            
            if device['configuration_status'] == 'Default':
                compliance_score -= 0.3
            
            if device['authentication_method'] == 'None':
                compliance_score -= 0.4
            
            if device['encryption_status'] == 'Unencrypted':
                compliance_score -= 0.3
            
            if (datetime.now() - device['last_update']).days > 90:
                compliance_score -= 0.2
            
            if compliance_score >= 0.8:
                device['compliance_status'] = 'Compliant'
            elif compliance_score >= 0.6:
                device['compliance_status'] = 'Partially Compliant'
            else:
                device['compliance_status'] = 'Non-compliant'
    
    def _generate_mac_address(self) -> str:
        """Generate random MAC address"""
        return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])
    
    def get_status(self) -> Dict[str, Any]:
        """Get current IoT monitoring status"""
        total_devices = len(self.iot_devices)
        vulnerable_devices = len([d for d in self.iot_devices 
                                if d.get('security_status') in ['vulnerable', 'critical']])
        
        return {
            'devices': total_devices,
            'vulnerable_devices': vulnerable_devices,
            'monitoring_active': self.monitoring_active,
            'compliant_devices': len([d for d in self.iot_devices 
                                    if d.get('compliance_status') == 'Compliant'])
        }
