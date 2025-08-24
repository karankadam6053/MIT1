import random
import time
import threading
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import json
from collections import defaultdict
import os

class MobileMonitor:
    """Mobile device security monitoring and management system"""
    
    def __init__(self):
        self.mobile_devices = []
        self.device_policies = self._load_security_policies()
        self.threat_signatures = self._load_mobile_threat_signatures()
        self.app_risk_database = self._load_app_risk_database()
        self.compliance_rules = self._load_compliance_rules()
        self.monitoring_active = False
        self.device_baselines = {}
        self.threat_feed = []
        self.mdm_policies = self._load_mdm_policies()
        self._initialize_mobile_devices()
        
    def _load_security_policies(self) -> Dict[str, Dict[str, Any]]:
        """Load mobile security policies"""
        return {
            'device_encryption': {
                'required': True,
                'algorithm': 'AES-256',
                'enforcement': 'mandatory'
            },
            'passcode_policy': {
                'min_length': 8,
                'complexity_required': True,
                'max_failed_attempts': 5,
                'auto_lock_time': 300  # 5 minutes
            },
            'app_installation': {
                'require_app_store_only': True,
                'block_unknown_sources': True,
                'app_reputation_check': True
            },
            'network_security': {
                'block_untrusted_wifi': True,
                'require_vpn': True,
                'certificate_pinning': True
            },
            'data_protection': {
                'prevent_screenshots': True,
                'disable_clipboard_sharing': True,
                'remote_wipe_enabled': True
            },
            'jailbreak_detection': {
                'enabled': True,
                'action': 'block_access',
                'reporting': True
            }
        }
    
    def _load_mobile_threat_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load mobile-specific threat signatures"""
        return {
            'malicious_app': {
                'indicators': ['suspicious_permissions', 'code_obfuscation', 'known_malware_signature'],
                'severity': 'Critical',
                'description': 'Malicious application detected on device',
                'mitigation': ['remove_app', 'scan_device', 'update_policies']
            },
            'data_exfiltration': {
                'indicators': ['large_data_uploads', 'unauthorized_api_calls', 'suspicious_network_traffic'],
                'severity': 'Critical',
                'description': 'Unauthorized data exfiltration detected',
                'mitigation': ['block_network', 'investigate_app', 'notify_security_team']
            },
            'phishing_attempt': {
                'indicators': ['fake_login_pages', 'credential_harvesting', 'suspicious_urls'],
                'severity': 'High',
                'description': 'Phishing attempt targeting mobile user',
                'mitigation': ['block_url', 'user_education', 'update_filters']
            },
            'device_compromise': {
                'indicators': ['jailbreak_detected', 'root_access', 'system_modification'],
                'severity': 'Critical',
                'description': 'Device security compromise detected',
                'mitigation': ['isolate_device', 'remote_wipe', 'security_assessment']
            },
            'rogue_wifi': {
                'indicators': ['evil_twin_ap', 'ssl_downgrade', 'dns_manipulation'],
                'severity': 'High',
                'description': 'Connection to rogue WiFi access point',
                'mitigation': ['disconnect_wifi', 'vpn_enforcement', 'network_scanning']
            },
            'malicious_profile': {
                'indicators': ['unauthorized_mdm', 'certificate_manipulation', 'policy_bypass'],
                'severity': 'High',
                'description': 'Malicious configuration profile installed',
                'mitigation': ['remove_profile', 'verify_certificates', 'policy_audit']
            },
            'sms_phishing': {
                'indicators': ['suspicious_links', 'credential_requests', 'urgency_tactics'],
                'severity': 'Medium',
                'description': 'SMS phishing attack detected',
                'mitigation': ['block_sender', 'user_alert', 'security_training']
            },
            'app_side_loading': {
                'indicators': ['unknown_source_install', 'unsigned_app', 'developer_mode'],
                'severity': 'Medium',
                'description': 'Unauthorized app installation from unknown source',
                'mitigation': ['remove_app', 'disable_unknown_sources', 'policy_enforcement']
            }
        }
    
    def _load_app_risk_database(self) -> Dict[str, Dict[str, Any]]:
        """Load application risk assessment database"""
        return {
            'high_risk_categories': {
                'file_sharing': {
                    'risk_score': 8.0,
                    'concerns': ['data_leakage', 'unauthorized_sharing', 'malware_vector'],
                    'examples': ['BitTorrent', 'P2P apps']
                },
                'remote_access': {
                    'risk_score': 9.0,
                    'concerns': ['unauthorized_access', 'data_theft', 'backdoor'],
                    'examples': ['TeamViewer', 'Remote desktop apps']
                },
                'social_media': {
                    'risk_score': 6.0,
                    'concerns': ['privacy_leak', 'social_engineering', 'phishing'],
                    'examples': ['Facebook', 'Twitter', 'Instagram']
                },
                'messaging': {
                    'risk_score': 5.0,
                    'concerns': ['data_interception', 'malicious_links', 'spam'],
                    'examples': ['WhatsApp', 'Telegram', 'Signal']
                }
            },
            'permission_risks': {
                'camera': {'risk_level': 'Medium', 'justification_required': True},
                'microphone': {'risk_level': 'Medium', 'justification_required': True},
                'location': {'risk_level': 'High', 'justification_required': True},
                'contacts': {'risk_level': 'High', 'justification_required': True},
                'sms': {'risk_level': 'High', 'justification_required': True},
                'phone': {'risk_level': 'Medium', 'justification_required': False},
                'storage': {'risk_level': 'Medium', 'justification_required': False},
                'admin': {'risk_level': 'Critical', 'justification_required': True}
            },
            'trusted_publishers': {
                'Apple': {'trust_score': 9.5, 'verification_required': False},
                'Google': {'trust_score': 9.0, 'verification_required': False},
                'Microsoft': {'trust_score': 9.0, 'verification_required': False},
                'Adobe': {'trust_score': 8.5, 'verification_required': False},
                'Unknown': {'trust_score': 2.0, 'verification_required': True}
            }
        }
    
    def _load_compliance_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance requirements"""
        return {
            'gdpr': {
                'data_encryption': 'required',
                'user_consent': 'explicit',
                'data_retention': '24_months_max',
                'breach_notification': '72_hours'
            },
            'hipaa': {
                'device_encryption': 'required',
                'access_logging': 'mandatory',
                'data_segregation': 'required',
                'audit_trail': 'comprehensive'
            },
            'pci_dss': {
                'payment_app_security': 'validated',
                'network_encryption': 'required',
                'access_control': 'strict',
                'regular_testing': 'quarterly'
            },
            'sox': {
                'financial_data_protection': 'required',
                'change_management': 'documented',
                'access_reviews': 'regular',
                'audit_preparation': 'continuous'
            }
        }
    
    def _load_mdm_policies(self) -> Dict[str, Any]:
        """Load Mobile Device Management policies"""
        return {
            'enrollment': {
                'automatic': True,
                'user_initiated': True,
                'bulk_enrollment': True,
                'zero_touch': True
            },
            'security': {
                'enforce_encryption': True,
                'require_passcode': True,
                'detect_jailbreak': True,
                'app_whitelisting': True,
                'remote_wipe': True
            },
            'compliance': {
                'policy_enforcement': 'strict',
                'violation_actions': ['warn', 'restrict', 'wipe'],
                'reporting_frequency': 'daily',
                'audit_logging': True
            },
            'app_management': {
                'app_distribution': 'managed',
                'app_updates': 'automatic',
                'app_removal': 'remote',
                'app_configuration': 'centralized'
            }
        }
    
    def _initialize_mobile_devices(self):
        """Initialize mobile device inventory"""
        platforms = ['iOS', 'Android', 'Windows Mobile']
        device_types = ['iPhone', 'iPad', 'Android Phone', 'Android Tablet', 'Windows Phone']
        os_versions = {
            'iOS': ['16.0', '16.1', '16.2', '15.7', '15.6'],
            'Android': ['13.0', '12.0', '11.0', '10.0', '9.0'],
            'Windows Mobile': ['10.0', '8.1']
        }
        
        users = [f'user{i:03d}' for i in range(1, 151)]
        departments = ['Sales', 'Marketing', 'Engineering', 'HR', 'Finance', 'Operations', 'Legal']
        
        for i in range(45):
            platform = random.choice(platforms)
            device_type = random.choice([dt for dt in device_types if platform.lower() in dt.lower() or 'Phone' in dt or 'Tablet' in dt])
            
            device = {
                'id': str(uuid.uuid4()),
                'name': f'{device_type.replace(" ", "_").lower()}_{i+1:02d}',
                'platform': platform,
                'device_type': device_type,
                'os_version': random.choice(os_versions.get(platform, ['Unknown'])),
                'model': f'{platform}-{random.randint(100, 999)}',
                'serial_number': f'SN{random.randint(100000, 999999)}',
                'imei': f'{random.randint(100000000000000, 999999999999999)}',
                'user': random.choice(users),
                'department': random.choice(departments),
                'enrollment_date': datetime.now() - timedelta(days=random.randint(0, 365)),
                'last_checkin': datetime.now() - timedelta(minutes=random.randint(0, 1440)),
                'compliance_status': random.choices(['compliant', 'non_compliant', 'unknown'], 
                                                  weights=[0.7, 0.2, 0.1])[0],
                'security_score': random.uniform(3.0, 10.0),
                'is_jailbroken': random.choices([True, False], weights=[0.05, 0.95])[0],
                'is_supervised': random.choices([True, False], weights=[0.8, 0.2])[0],
                'passcode_enabled': random.choices([True, False], weights=[0.9, 0.1])[0],
                'encryption_enabled': random.choices([True, False], weights=[0.85, 0.15])[0],
                'location_services': random.choices([True, False], weights=[0.7, 0.3])[0],
                'vpn_configured': random.choices([True, False], weights=[0.6, 0.4])[0],
                'wifi_networks': random.randint(1, 10),
                'installed_apps': [],
                'threat_count': random.randint(0, 3),
                'data_usage_mb': random.randint(100, 5000),
                'battery_level': random.randint(10, 100),
                'storage_used_gb': random.randint(5, 64),
                'storage_total_gb': random.choice([32, 64, 128, 256, 512]),
                'last_backup': datetime.now() - timedelta(days=random.randint(0, 30)),
                'mdm_enrolled': random.choices([True, False], weights=[0.9, 0.1])[0],
                'certificate_count': random.randint(2, 8),
                'profile_count': random.randint(1, 5),
                'location': random.choice(['Office', 'Remote', 'Travel', 'Home', 'Unknown']),
                'network_type': random.choice(['WiFi', 'Cellular', 'VPN', 'Unknown'])
            }
            
            # Generate installed apps
            device['installed_apps'] = self._generate_installed_apps(device['platform'])
            
            # Adjust security score based on device configuration
            device['security_score'] = self._calculate_device_security_score(device)
            
            # Set compliance status based on security score and policies
            device['compliance_status'] = self._determine_compliance_status(device)
            
            self.mobile_devices.append(device)
            
            # Create device baseline
            self.device_baselines[device['id']] = {
                'normal_data_usage': device['data_usage_mb'],
                'typical_app_count': len(device['installed_apps']),
                'expected_location': device['location'],
                'baseline_security_score': device['security_score'],
                'normal_checkin_frequency': 24,  # hours
                'expected_network_type': device['network_type']
            }
    
    def _generate_installed_apps(self, platform: str) -> List[Dict[str, Any]]:
        """Generate realistic installed apps for device"""
        apps = []
        
        # Common apps by platform
        common_apps = {
            'iOS': [
                {'name': 'Safari', 'category': 'Browser', 'risk_level': 'low'},
                {'name': 'Mail', 'category': 'Email', 'risk_level': 'low'},
                {'name': 'Messages', 'category': 'Messaging', 'risk_level': 'low'},
                {'name': 'Calendar', 'category': 'Productivity', 'risk_level': 'low'},
                {'name': 'WhatsApp', 'category': 'Messaging', 'risk_level': 'medium'},
                {'name': 'Slack', 'category': 'Business', 'risk_level': 'low'},
                {'name': 'Zoom', 'category': 'Business', 'risk_level': 'medium'},
                {'name': 'Dropbox', 'category': 'File Storage', 'risk_level': 'medium'},
                {'name': 'Banking App', 'category': 'Finance', 'risk_level': 'high'},
                {'name': 'VPN Client', 'category': 'Security', 'risk_level': 'low'}
            ],
            'Android': [
                {'name': 'Chrome', 'category': 'Browser', 'risk_level': 'low'},
                {'name': 'Gmail', 'category': 'Email', 'risk_level': 'low'},
                {'name': 'Messages', 'category': 'Messaging', 'risk_level': 'low'},
                {'name': 'Google Calendar', 'category': 'Productivity', 'risk_level': 'low'},
                {'name': 'WhatsApp', 'category': 'Messaging', 'risk_level': 'medium'},
                {'name': 'Slack', 'category': 'Business', 'risk_level': 'low'},
                {'name': 'Microsoft Teams', 'category': 'Business', 'risk_level': 'low'},
                {'name': 'Google Drive', 'category': 'File Storage', 'risk_level': 'medium'},
                {'name': 'Banking App', 'category': 'Finance', 'risk_level': 'high'},
                {'name': 'NordVPN', 'category': 'Security', 'risk_level': 'low'}
            ]
        }
        
        # Risky apps that might be installed
        risky_apps = [
            {'name': 'File Sharing App', 'category': 'File Sharing', 'risk_level': 'high'},
            {'name': 'Remote Access Tool', 'category': 'Remote Access', 'risk_level': 'high'},
            {'name': 'Unknown Publisher App', 'category': 'Utility', 'risk_level': 'high'},
            {'name': 'Suspicious Game', 'category': 'Game', 'risk_level': 'medium'},
            {'name': 'Ad-Supported App', 'category': 'Utility', 'risk_level': 'medium'}
        ]
        
        # Select apps for this device
        platform_apps = common_apps.get(platform, common_apps['iOS'])
        
        # Add common apps (most devices have these)
        for app in platform_apps:
            if random.random() < 0.8:  # 80% chance of having common apps
                app_instance = app.copy()
                app_instance.update({
                    'version': f'{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}',
                    'install_date': datetime.now() - timedelta(days=random.randint(0, 365)),
                    'last_used': datetime.now() - timedelta(hours=random.randint(0, 168)),
                    'permissions': self._generate_app_permissions(),
                    'data_usage_mb': random.randint(1, 500),
                    'risk_reason': self._get_risk_reason(app['risk_level'])
                })
                apps.append(app_instance)
        
        # Occasionally add risky apps
        for risky_app in risky_apps:
            if random.random() < 0.1:  # 10% chance of risky apps
                app_instance = risky_app.copy()
                app_instance.update({
                    'version': f'{random.randint(1, 3)}.{random.randint(0, 9)}',
                    'install_date': datetime.now() - timedelta(days=random.randint(0, 30)),
                    'last_used': datetime.now() - timedelta(hours=random.randint(0, 24)),
                    'permissions': self._generate_app_permissions(high_risk=True),
                    'data_usage_mb': random.randint(50, 1000),
                    'risk_reason': self._get_risk_reason(risky_app['risk_level'])
                })
                apps.append(app_instance)
        
        return apps
    
    def _generate_app_permissions(self, high_risk: bool = False) -> List[str]:
        """Generate app permissions"""
        all_permissions = [
            'camera', 'microphone', 'location', 'contacts', 'sms', 'phone',
            'storage', 'calendar', 'network', 'bluetooth', 'notifications'
        ]
        
        if high_risk:
            # High-risk apps tend to request more permissions
            return random.sample(all_permissions, random.randint(5, len(all_permissions)))
        else:
            # Normal apps request fewer permissions
            return random.sample(all_permissions, random.randint(1, 4))
    
    def _get_risk_reason(self, risk_level: str) -> str:
        """Get risk reason based on risk level"""
        risk_reasons = {
            'low': 'Trusted publisher, standard permissions',
            'medium': 'Some elevated permissions required',
            'high': 'Extensive permissions, potential security concerns'
        }
        return risk_reasons.get(risk_level, 'Unknown risk level')
    
    def _calculate_device_security_score(self, device: Dict[str, Any]) -> float:
        """Calculate security score for mobile device"""
        score = 10.0  # Start with perfect score
        
        # Deduct for security issues
        if device['is_jailbroken']:
            score -= 4.0
        
        if not device['passcode_enabled']:
            score -= 2.0
        
        if not device['encryption_enabled']:
            score -= 2.0
        
        if not device['mdm_enrolled']:
            score -= 1.5
        
        if not device['vpn_configured']:
            score -= 1.0
        
        # Check for risky apps
        risky_apps = [app for app in device['installed_apps'] if app['risk_level'] == 'high']
        score -= len(risky_apps) * 0.5
        
        # OS version penalty (older versions are less secure)
        os_version = device['os_version']
        if os_version:
            major_version = float(os_version.split('.')[0])
            if device['platform'] == 'iOS' and major_version < 15:
                score -= 1.0
            elif device['platform'] == 'Android' and major_version < 12:
                score -= 1.0
        
        return max(0.0, min(10.0, round(score, 1)))
    
    def _determine_compliance_status(self, device: Dict[str, Any]) -> str:
        """Determine compliance status based on policies"""
        compliance_score = 1.0
        
        # Check against security policies
        if not device['encryption_enabled']:
            compliance_score -= 0.3
        
        if not device['passcode_enabled']:
            compliance_score -= 0.2
        
        if device['is_jailbroken']:
            compliance_score -= 0.4
        
        if not device['mdm_enrolled']:
            compliance_score -= 0.2
        
        # Check app compliance
        risky_apps = [app for app in device['installed_apps'] if app['risk_level'] == 'high']
        compliance_score -= len(risky_apps) * 0.1
        
        if compliance_score >= 0.8:
            return 'compliant'
        elif compliance_score >= 0.6:
            return 'partially_compliant'
        else:
            return 'non_compliant'
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get mobile device statistics"""
        total_devices = len(self.mobile_devices)
        
        if total_devices == 0:
            return {
                'total_devices': 0,
                'compliant': 0,
                'non_compliant': 0,
                'vulnerable': 0,
                'security_score': 0.0
            }
        
        # Count by compliance status
        compliant_count = len([d for d in self.mobile_devices if d['compliance_status'] == 'compliant'])
        non_compliant_count = len([d for d in self.mobile_devices if d['compliance_status'] in ['non_compliant', 'partially_compliant']])
        
        # Count vulnerable devices (jailbroken or low security score)
        vulnerable_count = len([d for d in self.mobile_devices 
                              if d['is_jailbroken'] or d['security_score'] < 5.0])
        
        # Calculate average security score
        avg_security_score = sum(d['security_score'] for d in self.mobile_devices) / total_devices
        
        # Platform distribution
        platform_counts = defaultdict(int)
        for device in self.mobile_devices:
            platform_counts[device['platform']] += 1
        
        return {
            'total_devices': total_devices,
            'compliant': compliant_count,
            'non_compliant': non_compliant_count,
            'vulnerable': vulnerable_count,
            'security_score': round(avg_security_score, 1),
            'mdm_enrolled': len([d for d in self.mobile_devices if d['mdm_enrolled']]),
            'jailbroken': len([d for d in self.mobile_devices if d['is_jailbroken']]),
            'encryption_enabled': len([d for d in self.mobile_devices if d['encryption_enabled']]),
            'vpn_configured': len([d for d in self.mobile_devices if d['vpn_configured']]),
            'platform_distribution': dict(platform_counts),
            'online': len([d for d in self.mobile_devices 
                         if (datetime.now() - d['last_checkin']).total_seconds() < 3600]),
            'offline': len([d for d in self.mobile_devices 
                          if (datetime.now() - d['last_checkin']).total_seconds() >= 3600])
        }
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """Get all mobile devices"""
        return self.mobile_devices
    
    def get_threat_count(self, category: str) -> int:
        """Get threat count for specific category"""
        # Simulate threat counts for different categories
        threat_counts = {
            'Malicious Apps': random.randint(0, 5),
            'Phishing Attempts': random.randint(0, 10),
            'Network Attacks': random.randint(0, 3),
            'Data Leakage': random.randint(0, 2),
            'Device Compromise': random.randint(0, 1)
        }
        
        return threat_counts.get(category, 0)
    
    def update_security_policies(self) -> bool:
        """Update mobile security policies"""
        try:
            # Simulate policy update
            self.device_policies['last_updated'] = datetime.now()
            
            # Apply policies to all devices
            for device in self.mobile_devices:
                self._apply_policies_to_device(device)
            
            return True
        except Exception as e:
            print(f"Failed to update security policies: {e}")
            return False
    
    def get_compliance_data(self) -> Dict[str, int]:
        """Get device compliance distribution"""
        compliance_counts = defaultdict(int)
        
        for device in self.mobile_devices:
            compliance_counts[device['compliance_status']] += 1
        
        return dict(compliance_counts)
    
    def scan_device_for_threats(self, device_id: str) -> Dict[str, Any]:
        """Scan specific device for threats"""
        device = next((d for d in self.mobile_devices if d['id'] == device_id), None)
        
        if not device:
            return {'error': 'Device not found'}
        
        scan_results = {
            'device_id': device_id,
            'device_name': device['name'],
            'scan_time': datetime.now(),
            'threats_found': [],
            'apps_scanned': len(device['installed_apps']),
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Check for threats based on signatures
        for signature_name, signature in self.threat_signatures.items():
            if self._check_threat_signature(device, signature_name, signature):
                threat = {
                    'type': signature_name.replace('_', ' ').title(),
                    'description': signature['description'],
                    'severity': signature['severity'],
                    'confidence': random.uniform(0.7, 0.95),
                    'indicators': signature['indicators'],
                    'mitigation': signature['mitigation']
                }
                scan_results['threats_found'].append(threat)
        
        # Check app risks
        for app in device['installed_apps']:
            if app['risk_level'] == 'high':
                threat = {
                    'type': 'High-Risk Application',
                    'description': f'High-risk app detected: {app["name"]}',
                    'severity': 'Medium',
                    'confidence': 0.8,
                    'app_name': app['name'],
                    'risk_reason': app['risk_reason']
                }
                scan_results['threats_found'].append(threat)
        
        # Generate recommendations
        scan_results['recommendations'] = self._generate_security_recommendations(device)
        
        return scan_results
    
    def run_continuous_monitoring(self):
        """Run continuous mobile device monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        
        def monitoring_loop():
            while self.monitoring_active:
                try:
                    # Update device status
                    for device in self.mobile_devices:
                        self._update_device_status(device)
                    
                    # Check for policy violations
                    self._check_policy_violations()
                    
                    # Update threat intelligence
                    self._update_threat_feed()
                    
                    time.sleep(180)  # Check every 3 minutes
                    
                except Exception as e:
                    print(f"Mobile monitoring error: {e}")
                    time.sleep(300)
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
    
    def _check_threat_signature(self, device: Dict[str, Any], signature_name: str, signature: Dict[str, Any]) -> bool:
        """Check if device matches threat signature"""
        # Simulate threat detection based on device characteristics
        detection_probability = 0.05  # 5% base chance
        
        if signature_name == 'device_compromise' and device['is_jailbroken']:
            return True
        
        if signature_name == 'malicious_app':
            risky_apps = [app for app in device['installed_apps'] if app['risk_level'] == 'high']
            return len(risky_apps) > 0
        
        if signature_name == 'data_exfiltration' and device['data_usage_mb'] > 3000:
            return random.random() < 0.3
        
        return random.random() < detection_probability
    
    def _generate_security_recommendations(self, device: Dict[str, Any]) -> List[str]:
        """Generate security recommendations for device"""
        recommendations = []
        
        if device['is_jailbroken']:
            recommendations.append('Device is jailbroken - consider replacement or additional monitoring')
        
        if not device['encryption_enabled']:
            recommendations.append('Enable device encryption')
        
        if not device['passcode_enabled']:
            recommendations.append('Enable device passcode/PIN')
        
        if not device['vpn_configured']:
            recommendations.append('Configure VPN for secure network access')
        
        if not device['mdm_enrolled']:
            recommendations.append('Enroll device in Mobile Device Management (MDM)')
        
        if device['security_score'] < 6.0:
            recommendations.append('Device security score is low - review security settings')
        
        risky_apps = [app for app in device['installed_apps'] if app['risk_level'] == 'high']
        if risky_apps:
            recommendations.append(f'Remove or review {len(risky_apps)} high-risk applications')
        
        # Check OS version
        if device['platform'] == 'iOS':
            major_version = float(device['os_version'].split('.')[0])
            if major_version < 15:
                recommendations.append('Update iOS to latest version')
        elif device['platform'] == 'Android':
            major_version = float(device['os_version'].split('.')[0])
            if major_version < 12:
                recommendations.append('Update Android to latest version')
        
        return recommendations
    
    def _apply_policies_to_device(self, device: Dict[str, Any]):
        """Apply security policies to device"""
        # Simulate policy enforcement
        policies = self.device_policies
        
        # Encryption policy
        if policies['device_encryption']['required'] and not device['encryption_enabled']:
            device['compliance_status'] = 'non_compliant'
        
        # Passcode policy
        if not device['passcode_enabled']:
            device['compliance_status'] = 'non_compliant'
        
        # Jailbreak detection
        if policies['jailbreak_detection']['enabled'] and device['is_jailbroken']:
            device['compliance_status'] = 'non_compliant'
    
    def _update_device_status(self, device: Dict[str, Any]):
        """Update individual device status"""
        # Simulate device check-ins
        if random.random() < 0.1:  # 10% chance of check-in
            device['last_checkin'] = datetime.now()
        
        # Simulate security score changes
        if random.random() < 0.05:  # 5% chance of score change
            device['security_score'] = max(0.0, min(10.0, 
                device['security_score'] + random.uniform(-0.5, 0.5)))
        
        # Update compliance status
        device['compliance_status'] = self._determine_compliance_status(device)
    
    def _check_policy_violations(self):
        """Check for policy violations across all devices"""
        for device in self.mobile_devices:
            violations = []
            
            if device['is_jailbroken']:
                violations.append('Device jailbreak detected')
            
            if not device['encryption_enabled']:
                violations.append('Device encryption not enabled')
            
            if not device['passcode_enabled']:
                violations.append('Device passcode not set')
            
            if violations:
                device['policy_violations'] = violations
                device['compliance_status'] = 'non_compliant'
    
    def _update_threat_feed(self):
        """Update mobile threat intelligence feed"""
        # Simulate threat feed updates
        new_threats = [
            f'Mobile malware variant {random.randint(1000, 9999)} detected',
            f'Phishing campaign targeting {random.choice(["banking", "social media", "corporate"])} users',
            f'Zero-day vulnerability in {random.choice(["iOS", "Android"])} version {random.randint(10, 16)}'
        ]
        
        if random.random() < 0.1:  # 10% chance of new threat
            self.threat_feed.append({
                'timestamp': datetime.now(),
                'threat': random.choice(new_threats),
                'severity': random.choice(['Low', 'Medium', 'High', 'Critical'])
            })
        
        # Keep only recent threats (last 24 hours)
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.threat_feed = [t for t in self.threat_feed if t['timestamp'] > cutoff_time]
