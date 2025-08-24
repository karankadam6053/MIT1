import os
import random
import hashlib
import threading
import time
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import json
from collections import defaultdict
import uuid

class EndpointMonitor:
    """Advanced endpoint security monitoring and protection system"""
    
    def __init__(self):
        self.monitored_endpoints = []
        self.scan_results = {}
        self.behavioral_baselines = {}
        self.threat_signatures = self._load_threat_signatures()
        self.quarantine_directory = "quarantine/"
        self.monitoring_active = False
        self.file_integrity_database = {}
        self.process_whitelist = self._load_process_whitelist()
        self.malware_families = self._load_malware_families()
        self._initialize_endpoints()
        
    def _load_threat_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load endpoint threat signatures"""
        return {
            'ransomware': {
                'file_extensions': ['.encrypted', '.locked', '.crypto', '.vault', '.crypt', '.wncry'],
                'processes': ['wannacry.exe', 'tasksche.exe', 'disk.exe', 'locky.exe'],
                'registry_keys': [
                    'HKEY_LOCAL_MACHINE\\SOFTWARE\\WanaCrypt0r',
                    'HKEY_CURRENT_USER\\Software\\Bitcoin'
                ],
                'behaviors': [
                    'rapid_file_encryption', 'shadow_copy_deletion', 'ransom_note_creation'
                ],
                'network_indicators': ['*.onion', 'tor2web.org', 'bitcoin payment']
            },
            'trojan': {
                'processes': ['trojan.exe', 'backdoor.exe', 'rat.exe'],
                'network_behaviors': ['keylogger_traffic', 'screenshot_upload', 'remote_access'],
                'file_behaviors': ['credential_theft', 'system_information_collection'],
                'persistence': ['startup_registry', 'scheduled_task', 'service_installation']
            },
            'rootkit': {
                'behaviors': ['process_hiding', 'file_hiding', 'registry_hiding'],
                'kernel_modifications': ['hook_installation', 'driver_injection'],
                'evasion_techniques': ['anti_debugging', 'vm_detection', 'sandbox_evasion']
            },
            'spyware': {
                'behaviors': ['keylogging', 'screen_capture', 'microphone_access', 'camera_access'],
                'data_collection': ['browser_data', 'email_data', 'document_access'],
                'communication': ['http_post', 'email_exfiltration', 'ftp_upload']
            },
            'adware': {
                'behaviors': ['browser_hijacking', 'popup_generation', 'search_redirection'],
                'modifications': ['homepage_change', 'search_engine_change', 'proxy_settings']
            },
            'botnet': {
                'network_behaviors': ['c2_communication', 'peer_communication', 'ddos_participation'],
                'processes': ['bot.exe', 'agent.exe', 'client.exe'],
                'behaviors': ['command_execution', 'file_download', 'update_mechanism']
            }
        }
    
    def _load_process_whitelist(self) -> List[str]:
        """Load whitelist of legitimate processes"""
        return [
            'explorer.exe', 'winlogon.exe', 'csrss.exe', 'lsass.exe', 'services.exe',
            'svchost.exe', 'taskmgr.exe', 'dwm.exe', 'chrome.exe', 'firefox.exe',
            'outlook.exe', 'word.exe', 'excel.exe', 'powerpnt.exe', 'notepad.exe',
            'calc.exe', 'mspaint.exe', 'cmd.exe', 'powershell.exe', 'conhost.exe',
            'system', 'registry', 'memory compression', 'secure system'
        ]
    
    def _load_malware_families(self) -> Dict[str, Dict[str, Any]]:
        """Load known malware families"""
        return {
            'WannaCry': {
                'type': 'Ransomware',
                'variants': ['WannaCry 1.0', 'WannaCry 2.0'],
                'signatures': ['@WanaDecryptor@', 'wannacry'],
                'behavior': 'File encryption, SMB exploitation'
            },
            'Locky': {
                'type': 'Ransomware',
                'variants': ['Locky', 'Lukitus', 'Diablo6'],
                'signatures': ['.locky', '.lukitus', '.diablo6'],
                'behavior': 'Email-based infection, file encryption'
            },
            'Zeus': {
                'type': 'Banking Trojan',
                'variants': ['Zeus', 'ZeuS', 'Zbot'],
                'signatures': ['zeus', 'zbot'],
                'behavior': 'Credential theft, web injection'
            },
            'Emotet': {
                'type': 'Trojan Downloader',
                'variants': ['Emotet', 'Epoch 1', 'Epoch 2'],
                'signatures': ['emotet'],
                'behavior': 'Email spreading, payload delivery'
            },
            'Stuxnet': {
                'type': 'Worm',
                'variants': ['Stuxnet'],
                'signatures': ['stuxnet', '.stub'],
                'behavior': 'Industrial system targeting, PLC manipulation'
            }
        }
    
    def _initialize_endpoints(self):
        """Initialize monitored endpoints with sample data"""
        endpoint_types = ['workstation', 'server', 'laptop', 'tablet']
        os_types = ['Windows 10', 'Windows 11', 'Windows Server 2019', 'Windows Server 2022', 
                   'Ubuntu 20.04', 'Ubuntu 22.04', 'macOS Monterey', 'macOS Ventura']
        
        for i in range(25):
            endpoint = {
                'id': str(uuid.uuid4()),
                'name': f'{random.choice(endpoint_types)}-{i+1:02d}',
                'type': random.choice(endpoint_types),
                'os': random.choice(os_types),
                'ip_address': f'192.168.1.{random.randint(10, 250)}',
                'mac_address': self._generate_mac_address(),
                'status': random.choices(['healthy', 'warning', 'critical', 'offline'], 
                                       weights=[0.7, 0.2, 0.05, 0.05])[0],
                'last_scan': datetime.now() - timedelta(hours=random.randint(0, 24)),
                'threat_count': random.randint(0, 5),
                'antivirus_status': random.choice(['enabled', 'disabled', 'outdated']),
                'firewall_status': random.choice(['enabled', 'disabled']),
                'last_boot': datetime.now() - timedelta(days=random.randint(0, 30)),
                'cpu_usage': random.uniform(5.0, 95.0),
                'memory_usage': random.uniform(30.0, 85.0),
                'disk_usage': random.uniform(40.0, 90.0),
                'network_activity': random.uniform(1.0, 100.0),  # Mbps
                'running_processes': random.randint(50, 200),
                'installed_software': random.randint(50, 300),
                'vulnerability_score': random.uniform(1.0, 10.0),
                'compliance_score': random.uniform(0.6, 1.0),
                'last_update': datetime.now() - timedelta(days=random.randint(0, 30)),
                'user': f'user{random.randint(1, 100)}',
                'domain': random.choice(['CORP', 'LOCAL', 'WORKGROUP'])
            }
            
            self.monitored_endpoints.append(endpoint)
            
            # Initialize behavioral baseline
            self.behavioral_baselines[endpoint['id']] = {
                'normal_cpu_usage': random.uniform(10.0, 30.0),
                'normal_memory_usage': random.uniform(40.0, 60.0),
                'normal_network_activity': random.uniform(5.0, 25.0),
                'normal_process_count': random.randint(80, 120),
                'normal_file_operations': random.randint(100, 500),
                'typical_login_hours': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                'common_applications': random.sample(self.process_whitelist, 10)
            }
    
    def get_endpoint_statistics(self) -> Dict[str, Any]:
        """Get endpoint protection statistics"""
        total_endpoints = len(self.monitored_endpoints)
        protected_endpoints = len([e for e in self.monitored_endpoints 
                                 if e['antivirus_status'] == 'enabled'])
        
        threats_detected = sum(e['threat_count'] for e in self.monitored_endpoints)
        quarantined_files = random.randint(50, 500)
        
        # Calculate compliance score
        compliance_scores = [e['compliance_score'] for e in self.monitored_endpoints]
        avg_compliance = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 0
        
        return {
            'total_endpoints': total_endpoints,
            'protected': protected_endpoints,
            'unprotected': total_endpoints - protected_endpoints,
            'threats_detected': threats_detected,
            'quarantined': quarantined_files,
            'compliance_score': avg_compliance,
            'online': len([e for e in self.monitored_endpoints if e['status'] != 'offline']),
            'offline': len([e for e in self.monitored_endpoints if e['status'] == 'offline']),
            'critical_alerts': len([e for e in self.monitored_endpoints if e['status'] == 'critical']),
            'pending_updates': len([e for e in self.monitored_endpoints 
                                  if (datetime.now() - e['last_update']).days > 7])
        }
    
    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        """Get all monitored endpoints"""
        return self.monitored_endpoints
    
    def run_scan(self, endpoint_name: str, scan_type: str) -> Dict[str, Any]:
        """Run security scan on specific endpoint"""
        endpoint = next((e for e in self.monitored_endpoints if e['name'] == endpoint_name), None)
        
        if not endpoint:
            return {'error': f'Endpoint {endpoint_name} not found'}
        
        scan_start_time = datetime.now()
        scan_id = str(uuid.uuid4())[:8]
        
        # Simulate scan based on type and intensity
        scan_results = {
            'scan_id': scan_id,
            'endpoint_name': endpoint_name,
            'endpoint_id': endpoint['id'],
            'scan_type': scan_type,
            'start_time': scan_start_time,
            'threats_found': [],
            'files_scanned': 0,
            'processes_analyzed': 0,
            'registry_entries_checked': 0,
            'network_connections_analyzed': 0,
            'vulnerabilities_found': [],
            'performance_impact': 'Low',
            'scan_duration': 0
        }
        
        if scan_type == "Quick Scan":
            scan_results.update(self._perform_quick_scan(endpoint))
        elif scan_type == "Full System Scan":
            scan_results.update(self._perform_full_scan(endpoint))
        elif scan_type == "Custom Scan":
            scan_results.update(self._perform_custom_scan(endpoint))
        elif scan_type == "Memory Scan":
            scan_results.update(self._perform_memory_scan(endpoint))
        
        # Calculate scan duration
        scan_end_time = datetime.now()
        scan_results['end_time'] = scan_end_time
        scan_results['scan_duration'] = (scan_end_time - scan_start_time).total_seconds()
        
        # Update endpoint scan information
        endpoint['last_scan'] = scan_end_time
        endpoint['threat_count'] = len(scan_results['threats_found'])
        
        # Store scan results
        self.scan_results[scan_id] = scan_results
        
        return scan_results
    
    def _perform_quick_scan(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Perform quick scan of critical system areas"""
        time.sleep(2)  # Simulate scan time
        
        results = {
            'files_scanned': random.randint(1000, 5000),
            'processes_analyzed': random.randint(20, 50),
            'registry_entries_checked': random.randint(100, 500),
            'performance_impact': 'Low'
        }
        
        # Generate potential threats
        threat_probability = 0.1  # 10% chance of finding threats in quick scan
        if random.random() < threat_probability:
            results['threats_found'] = self._generate_sample_threats(random.randint(1, 3))
        
        return results
    
    def _perform_full_scan(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive full system scan"""
        time.sleep(5)  # Simulate longer scan time
        
        results = {
            'files_scanned': random.randint(50000, 200000),
            'processes_analyzed': random.randint(50, 150),
            'registry_entries_checked': random.randint(5000, 20000),
            'network_connections_analyzed': random.randint(20, 100),
            'performance_impact': 'High'
        }
        
        # Higher chance of finding threats in full scan
        threat_probability = 0.25
        if random.random() < threat_probability:
            results['threats_found'] = self._generate_sample_threats(random.randint(1, 8))
        
        # Check for vulnerabilities
        vuln_probability = 0.3
        if random.random() < vuln_probability:
            results['vulnerabilities_found'] = self._generate_sample_vulnerabilities()
        
        return results
    
    def _perform_custom_scan(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Perform custom targeted scan"""
        time.sleep(3)  # Simulate scan time
        
        results = {
            'files_scanned': random.randint(10000, 50000),
            'processes_analyzed': random.randint(30, 80),
            'registry_entries_checked': random.randint(1000, 10000),
            'performance_impact': 'Medium'
        }
        
        threat_probability = 0.15
        if random.random() < threat_probability:
            results['threats_found'] = self._generate_sample_threats(random.randint(1, 5))
        
        return results
    
    def _perform_memory_scan(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Perform memory-focused scan for active threats"""
        time.sleep(1)  # Fast memory scan
        
        results = {
            'files_scanned': 0,  # Memory scan doesn't scan files
            'processes_analyzed': random.randint(80, 150),
            'memory_regions_scanned': random.randint(1000, 5000),
            'performance_impact': 'Low'
        }
        
        # Memory scans are good at finding active malware
        threat_probability = 0.2
        if random.random() < threat_probability:
            threats = self._generate_sample_threats(random.randint(1, 4))
            # Mark as memory-resident
            for threat in threats:
                threat['location'] = 'Memory'
                threat['action_taken'] = 'Process terminated'
            results['threats_found'] = threats
        
        return results
    
    def _generate_sample_threats(self, count: int) -> List[Dict[str, Any]]:
        """Generate sample threats for demonstration"""
        threats = []
        threat_types = ['Trojan', 'Virus', 'Spyware', 'Adware', 'Rootkit', 'Ransomware']
        actions = ['Quarantined', 'Deleted', 'Cleaned', 'Access denied']
        
        for _ in range(count):
            threat_type = random.choice(threat_types)
            
            threat = {
                'name': f'{threat_type}.{random.choice(["Win32", "Gen", "Agent"])}.{random.randint(1000, 9999)}',
                'type': threat_type,
                'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
                'file_path': self._generate_file_path(),
                'file_size': random.randint(1024, 10485760),  # 1KB to 10MB
                'md5_hash': hashlib.md5(f'threat_{random.randint(1000, 9999)}'.encode()).hexdigest(),
                'sha256_hash': hashlib.sha256(f'threat_{random.randint(1000, 9999)}'.encode()).hexdigest(),
                'detection_time': datetime.now(),
                'action_taken': random.choice(actions),
                'confidence': random.uniform(0.8, 0.99),
                'infected_since': datetime.now() - timedelta(days=random.randint(1, 30)),
                'source': random.choice(['Email attachment', 'Web download', 'USB device', 'Network share', 'Unknown'])
            }
            
            threats.append(threat)
        
        return threats
    
    def _generate_sample_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Generate sample vulnerabilities"""
        vulnerabilities = []
        vuln_types = ['Missing patch', 'Weak password', 'Open port', 'Outdated software', 'Configuration issue']
        
        for _ in range(random.randint(1, 5)):
            vuln = {
                'cve_id': f'CVE-2024-{random.randint(1000, 9999)}',
                'title': f'{random.choice(vuln_types)} in {random.choice(["Windows", "Chrome", "Office", "Java", "Adobe Reader"])}',
                'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
                'cvss_score': random.uniform(1.0, 10.0),
                'description': 'Security vulnerability that could allow remote code execution',
                'solution': 'Apply security update or patch',
                'published_date': datetime.now() - timedelta(days=random.randint(1, 365)),
                'exploitability': random.choice(['Low', 'Medium', 'High']),
                'patch_available': random.choice([True, False])
            }
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_behavioral_analysis(self) -> Dict[str, Any]:
        """Get behavioral analysis results"""
        suspicious_processes = []
        network_anomalies = []
        
        # Generate suspicious processes
        for _ in range(random.randint(0, 5)):
            process = {
                'name': f'suspicious_process_{random.randint(100, 999)}.exe',
                'pid': random.randint(1000, 9999),
                'cpu_usage': random.uniform(50.0, 95.0),
                'memory_usage': random.uniform(100.0, 1000.0),  # MB
                'risk_score': random.uniform(0.7, 0.95),
                'behaviors': random.sample([
                    'High network activity', 'Unusual file access', 'Registry modification',
                    'Process injection', 'Keylogger activity', 'Screen capture'
                ], random.randint(1, 3)),
                'parent_process': random.choice(['explorer.exe', 'svchost.exe', 'winlogon.exe']),
                'command_line': f'suspicious_process_{random.randint(100, 999)}.exe -h -s -q',
                'start_time': datetime.now() - timedelta(minutes=random.randint(5, 120))
            }
            suspicious_processes.append(process)
        
        # Generate network anomalies
        for _ in range(random.randint(0, 3)):
            anomaly = {
                'process': f'anomalous_app_{random.randint(10, 99)}.exe',
                'destination': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
                'port': random.choice([443, 80, 8080, 9999, 4444]),
                'protocol': random.choice(['TCP', 'UDP']),
                'data_transferred': random.uniform(1.0, 100.0),  # MB
                'risk_score': random.uniform(0.6, 0.9),
                'country': random.choice(['CN', 'RU', 'KP', 'IR', 'Unknown']),
                'duration': random.randint(60, 3600),  # seconds
                'connection_type': random.choice(['Persistent', 'Periodic', 'Burst'])
            }
            network_anomalies.append(anomaly)
        
        return {
            'suspicious_processes': suspicious_processes,
            'network_anomalies': network_anomalies,
            'file_system_changes': random.randint(50, 500),
            'registry_modifications': random.randint(10, 100),
            'unusual_login_attempts': random.randint(0, 20),
            'analysis_time': datetime.now(),
            'baseline_deviations': {
                'cpu_usage': random.uniform(-20.0, 50.0),
                'memory_usage': random.uniform(-10.0, 30.0),
                'network_activity': random.uniform(-5.0, 100.0),
                'process_count': random.randint(-10, 50)
            }
        }
    
    def analyze_file(self, uploaded_file) -> Dict[str, Any]:
        """Analyze uploaded file for malware"""
        file_content = uploaded_file.getvalue()
        file_size = len(file_content)
        
        # Calculate file hashes
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        
        # Simulate malware analysis
        analysis_results = {
            'file_name': uploaded_file.name,
            'file_size': file_size,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'file_type': self._detect_file_type(uploaded_file.name),
            'analysis_time': datetime.now(),
            'scan_engines': {},
            'threat_score': 0.0,
            'is_malicious': False,
            'threat_type': None,
            'malware_family': None,
            'engine_results': {}
        }
        
        # Simulate multiple AV engine results
        engines = ['VirusTotal', 'Windows Defender', 'McAfee', 'Norton', 'Kaspersky', 
                  'Avast', 'AVG', 'ESET', 'Bitdefender', 'Trend Micro']
        
        detection_count = 0
        for engine in engines:
            # Simulate detection (small chance of detection for demo purposes)
            detected = random.random() < 0.1  # 10% chance of detection
            
            if detected:
                detection_count += 1
                threat_name = f'{random.choice(["Trojan", "Virus", "Spyware"])}.{random.choice(["Win32", "Gen"])}.{random.randint(1000, 9999)}'
            else:
                threat_name = None
            
            analysis_results['engine_results'][engine] = {
                'detected': detected,
                'threat_name': threat_name,
                'last_updated': datetime.now() - timedelta(days=random.randint(0, 7))
            }
        
        # Calculate threat score based on detections
        if detection_count > 0:
            analysis_results['is_malicious'] = True
            analysis_results['threat_score'] = min(1.0, detection_count / len(engines) * 2)
            analysis_results['threat_type'] = random.choice(['Trojan', 'Virus', 'Spyware', 'Adware'])
            
            # Try to identify malware family
            for family_name, family_info in self.malware_families.items():
                if any(sig in uploaded_file.name.lower() for sig in family_info['signatures']):
                    analysis_results['malware_family'] = family_name
                    break
            
            if not analysis_results['malware_family']:
                analysis_results['malware_family'] = 'Unknown'
        
        return analysis_results
    
    def run_continuous_monitoring(self):
        """Run continuous endpoint monitoring"""
        if self.monitoring_active:
            return  # Already running
        
        self.monitoring_active = True
        
        def monitoring_loop():
            while self.monitoring_active:
                try:
                    # Update endpoint status
                    for endpoint in self.monitored_endpoints:
                        self._update_endpoint_status(endpoint)
                    
                    # Run behavioral analysis
                    self._run_behavioral_analysis()
                    
                    # Check for new threats
                    self._check_for_new_threats()
                    
                    # Sleep for monitoring interval
                    time.sleep(60)  # Check every minute
                    
                except Exception as e:
                    print(f"Endpoint monitoring error: {e}")
                    time.sleep(300)  # Wait longer on error
        
        # Start monitoring in separate thread
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
    
    def _update_endpoint_status(self, endpoint: Dict[str, Any]):
        """Update individual endpoint status"""
        # Simulate status changes
        if random.random() < 0.05:  # 5% chance of status change
            current_status = endpoint['status']
            
            if current_status == 'healthy':
                endpoint['status'] = random.choices(['warning', 'critical'], weights=[0.8, 0.2])[0]
            elif current_status == 'warning':
                endpoint['status'] = random.choices(['healthy', 'critical'], weights=[0.7, 0.3])[0]
            elif current_status == 'critical':
                endpoint['status'] = random.choices(['warning', 'healthy'], weights=[0.6, 0.4])[0]
        
        # Update system metrics
        endpoint['cpu_usage'] = max(0, min(100, endpoint['cpu_usage'] + random.uniform(-10, 10)))
        endpoint['memory_usage'] = max(0, min(100, endpoint['memory_usage'] + random.uniform(-5, 5)))
        endpoint['network_activity'] = max(0, endpoint['network_activity'] + random.uniform(-20, 20))
    
    def _run_behavioral_analysis(self):
        """Run behavioral analysis on all endpoints"""
        for endpoint in self.monitored_endpoints:
            baseline = self.behavioral_baselines.get(endpoint['id'])
            if not baseline:
                continue
            
            # Check for behavioral anomalies
            cpu_deviation = abs(endpoint['cpu_usage'] - baseline['normal_cpu_usage'])
            memory_deviation = abs(endpoint['memory_usage'] - baseline['normal_memory_usage'])
            
            # Flag significant deviations
            if cpu_deviation > 30 or memory_deviation > 25:
                endpoint['status'] = 'warning'
                endpoint['threat_count'] += 1
    
    def _check_for_new_threats(self):
        """Check for new threats across endpoints"""
        for endpoint in self.monitored_endpoints:
            # Small chance of new threat detection
            if random.random() < 0.02:  # 2% chance
                endpoint['threat_count'] += 1
                if endpoint['threat_count'] > 3:
                    endpoint['status'] = 'critical'
    
    def _generate_file_path(self) -> str:
        """Generate realistic file path"""
        paths = [
            'C:\\Windows\\System32\\malware.exe',
            'C:\\Users\\Public\\Downloads\\suspicious.exe',
            'C:\\Temp\\threat.dll',
            'C:\\Program Files\\BadSoftware\\agent.exe',
            'C:\\Windows\\Temp\\dropper.exe',
            '%APPDATA%\\malicious.exe',
            '%TEMP%\\payload.exe'
        ]
        return random.choice(paths)
    
    def _detect_file_type(self, filename: str) -> str:
        """Detect file type from filename"""
        extension = filename.split('.')[-1].lower()
        
        file_types = {
            'exe': 'Executable',
            'dll': 'Dynamic Link Library',
            'bat': 'Batch File',
            'cmd': 'Command Script',
            'scr': 'Screen Saver',
            'com': 'Command File',
            'pif': 'Program Information File',
            'vbs': 'VBScript',
            'js': 'JavaScript',
            'jar': 'Java Archive',
            'zip': 'Archive',
            'rar': 'Archive',
            'pdf': 'PDF Document',
            'doc': 'Word Document',
            'docx': 'Word Document',
            'xls': 'Excel Document',
            'xlsx': 'Excel Document'
        }
        
        return file_types.get(extension, 'Unknown')
    
    def _generate_mac_address(self) -> str:
        """Generate random MAC address"""
        return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])
