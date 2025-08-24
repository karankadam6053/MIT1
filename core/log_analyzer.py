import re
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import hashlib
import random

class LogAnalyzer:
    """Advanced log analysis and digital forensics engine"""
    
    def __init__(self):
        self.log_sources = {
            'Windows Event Logs': {'path': '/var/log/windows/', 'format': 'evtx'},
            'Linux Syslogs': {'path': '/var/log/syslog/', 'format': 'syslog'},
            'Network Devices': {'path': '/var/log/network/', 'format': 'cisco'},
            'Web Servers': {'path': '/var/log/apache/', 'format': 'apache'},
            'Database Logs': {'path': '/var/log/database/', 'format': 'mysql'},
            'Cloud Audit Logs': {'path': '/var/log/cloud/', 'format': 'json'},
            'IoT Device Logs': {'path': '/var/log/iot/', 'format': 'custom'},
            'Mobile Device Logs': {'path': '/var/log/mobile/', 'format': 'mobile'}
        }
        
        self.log_patterns = self._initialize_log_patterns()
        self.correlation_rules = self._initialize_correlation_rules()
    
    def _initialize_log_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize log parsing patterns for different sources"""
        return {
            'failed_login': {
                'pattern': r'authentication failure|login failed|invalid user|bad password',
                'severity': 'Medium',
                'category': 'Authentication'
            },
            'privilege_escalation': {
                'pattern': r'sudo|su |runas|privilege|elevation',
                'severity': 'High',
                'category': 'Privilege Escalation'
            },
            'suspicious_process': {
                'pattern': r'powershell.*-enc|cmd\.exe.*\/c|rundll32|regsvr32',
                'severity': 'High',
                'category': 'Process Execution'
            },
            'network_scan': {
                'pattern': r'port scan|nmap|masscan|connect\(\) to .* failed',
                'severity': 'Medium',
                'category': 'Network Activity'
            },
            'file_access': {
                'pattern': r'file access denied|permission denied|unauthorized access',
                'severity': 'Medium',
                'category': 'File System'
            },
            'malware_signature': {
                'pattern': r'virus detected|malware|trojan|backdoor|rootkit',
                'severity': 'Critical',
                'category': 'Malware'
            },
            'data_exfiltration': {
                'pattern': r'large file transfer|ftp upload|data export|backup to external',
                'severity': 'High',
                'category': 'Data Exfiltration'
            },
            'system_shutdown': {
                'pattern': r'system shutdown|service stopped|process terminated',
                'severity': 'Low',
                'category': 'System Events'
            }
        }
    
    def _initialize_correlation_rules(self) -> List[Dict[str, Any]]:
        """Initialize correlation rules for cross-platform analysis"""
        return [
            {
                'name': 'Coordinated Attack',
                'description': 'Multiple failed logins followed by privilege escalation',
                'conditions': [
                    {'category': 'Authentication', 'count': '>= 5', 'timeframe': '5 minutes'},
                    {'category': 'Privilege Escalation', 'count': '>= 1', 'timeframe': '10 minutes'}
                ],
                'severity': 'Critical',
                'confidence': 0.9
            },
            {
                'name': 'Lateral Movement',
                'description': 'Process execution across multiple systems',
                'conditions': [
                    {'category': 'Process Execution', 'systems': '>= 3', 'timeframe': '30 minutes'}
                ],
                'severity': 'High',
                'confidence': 0.8
            },
            {
                'name': 'Data Breach Sequence',
                'description': 'File access followed by data exfiltration',
                'conditions': [
                    {'category': 'File System', 'count': '>= 10', 'timeframe': '1 hour'},
                    {'category': 'Data Exfiltration', 'count': '>= 1', 'timeframe': '2 hours'}
                ],
                'severity': 'Critical',
                'confidence': 0.95
            }
        ]
    
    def analyze_logs(self, sources: List[str], time_range: str, analysis_type: str) -> Dict[str, Any]:
        """Analyze logs from specified sources and time range"""
        
        # Generate simulated log analysis results
        analysis_results = {
            'events': self._generate_security_events(sources, time_range),
            'findings': [],
            'timeline': None,
            'raw_logs': []
        }
        
        # Analyze events for security findings
        analysis_results['findings'] = self._analyze_security_events(analysis_results['events'])
        
        # Create timeline
        analysis_results['timeline'] = self._create_event_timeline(analysis_results['events'])
        
        # Generate raw log samples
        analysis_results['raw_logs'] = self._generate_raw_log_samples(sources, time_range)
        
        return analysis_results
    
    def _generate_security_events(self, sources: List[str], time_range: str) -> List[Dict[str, Any]]:
        """Generate simulated security events from log sources"""
        events = []
        
        # Determine number of events based on time range
        event_counts = {
            'Last Hour': random.randint(10, 50),
            'Last 24h': random.randint(100, 500),
            'Last 7 days': random.randint(500, 2000),
            'Custom Range': random.randint(200, 1000)
        }
        
        num_events = event_counts.get(time_range, 100)
        
        # Generate events for each source
        for source in sources:
            source_events = num_events // len(sources)
            
            for _ in range(source_events):
                # Choose random pattern
                pattern_name = random.choice(list(self.log_patterns.keys()))
                pattern_info = self.log_patterns[pattern_name]
                
                event = {
                    'id': self._generate_event_id(),
                    'timestamp': self._generate_random_timestamp(time_range),
                    'source': source,
                    'pattern': pattern_name,
                    'category': pattern_info['category'],
                    'severity': pattern_info['severity'],
                    'description': self._generate_event_description(pattern_name, source),
                    'raw_log': self._generate_raw_log_entry(pattern_name, source),
                    'ip_address': self._generate_random_ip(),
                    'user': self._generate_random_user(),
                    'system': self._generate_random_system()
                }
                
                events.append(event)
        
        # Sort events by timestamp
        events.sort(key=lambda x: x['timestamp'])
        
        return events
    
    def _analyze_security_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze security events to identify threats and patterns"""
        findings = []
        
        # Group events by category and time
        event_groups = {}
        for event in events:
            category = event['category']
            if category not in event_groups:
                event_groups[category] = []
            event_groups[category].append(event)
        
        # Analyze each category
        for category, category_events in event_groups.items():
            # Check for high frequency events
            if len(category_events) > 20:
                finding = {
                    'title': f'High Volume {category} Activity',
                    'severity': 'High',
                    'confidence': 0.8,
                    'description': f'Detected {len(category_events)} {category.lower()} events, which exceeds normal baseline.',
                    'event_count': len(category_events),
                    'time_span': self._calculate_time_span(category_events),
                    'affected_systems': list(set([e['system'] for e in category_events])),
                    'recommendations': [
                        f'Investigate {category.lower()} patterns',
                        'Review affected systems for compromise',
                        'Consider implementing additional monitoring'
                    ]
                }
                findings.append(finding)
        
        # Check for critical severity events
        critical_events = [e for e in events if e['severity'] == 'Critical']
        if critical_events:
            finding = {
                'title': 'Critical Security Events Detected',
                'severity': 'Critical',
                'confidence': 0.95,
                'description': f'Detected {len(critical_events)} critical security events requiring immediate attention.',
                'event_count': len(critical_events),
                'affected_systems': list(set([e['system'] for e in critical_events])),
                'recommendations': [
                    'Immediately investigate all critical events',
                    'Isolate affected systems if necessary',
                    'Activate incident response procedures'
                ]
            }
            findings.append(finding)
        
        # Check for authentication failures
        auth_failures = [e for e in events if e['category'] == 'Authentication']
        if len(auth_failures) > 10:
            # Group by user and IP
            user_failures = {}
            ip_failures = {}
            
            for event in auth_failures:
                user = event['user']
                ip = event['ip_address']
                
                user_failures[user] = user_failures.get(user, 0) + 1
                ip_failures[ip] = ip_failures.get(ip, 0) + 1
            
            # Check for brute force attacks
            suspicious_users = [user for user, count in user_failures.items() if count > 5]
            suspicious_ips = [ip for ip, count in ip_failures.items() if count > 10]
            
            if suspicious_users or suspicious_ips:
                finding = {
                    'title': 'Potential Brute Force Attack',
                    'severity': 'High',
                    'confidence': 0.85,
                    'description': f'Multiple authentication failures detected from suspicious sources.',
                    'suspicious_users': suspicious_users,
                    'suspicious_ips': suspicious_ips,
                    'total_attempts': len(auth_failures),
                    'recommendations': [
                        'Block suspicious IP addresses',
                        'Force password reset for targeted accounts',
                        'Implement account lockout policies',
                        'Enable multi-factor authentication'
                    ]
                }
                findings.append(finding)
        
        # Sort findings by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return findings
    
    def _create_event_timeline(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create timeline visualization data"""
        if not events:
            return None
        
        timestamps = [event['timestamp'] for event in events]
        sources = [event['source'] for event in events]
        severities = [event['severity'] for event in events]
        
        return {
            'timestamps': timestamps,
            'sources': sources,
            'severities': severities
        }
    
    def _generate_raw_log_samples(self, sources: List[str], time_range: str) -> List[Dict[str, Any]]:
        """Generate sample raw log entries"""
        raw_logs = []
        
        log_templates = {
            'Windows Event Logs': [
                'EventID 4625: An account failed to log on. Account Name: {user} Source IP: {ip}',
                'EventID 4648: A logon was attempted using explicit credentials. Account: {user}',
                'EventID 4720: A user account was created. Account Name: {user}'
            ],
            'Linux Syslogs': [
                'sshd[1234]: Failed password for {user} from {ip} port 22 ssh2',
                'sudo: {user} : command not allowed ; TTY=pts/0 ; PWD=/home/{user}',
                'kernel: [12345.678] TCP: Possible SYN flooding on port 80'
            ],
            'Network Devices': [
                '%SEC-6-IPACCESSLOGP: list 101 denied tcp {ip}(3389) -> 10.1.1.1(80)',
                '%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down',
                '%SYS-5-CONFIG_I: Configured from console by {user}'
            ],
            'Web Servers': [
                '{ip} - - [timestamp] "GET /admin HTTP/1.1" 403 512 "-" "curl/7.68.0"',
                '{ip} - {user} [timestamp] "POST /login HTTP/1.1" 401 256',
                '{ip} - - [timestamp] "GET /../../../etc/passwd HTTP/1.1" 404 162'
            ]
        }
        
        for source in sources:
            if source in log_templates:
                templates = log_templates[source]
                
                for _ in range(random.randint(5, 15)):
                    template = random.choice(templates)
                    
                    log_entry = {
                        'timestamp': self._generate_random_timestamp(time_range),
                        'source': source,
                        'message': template.format(
                            user=self._generate_random_user(),
                            ip=self._generate_random_ip(),
                            system=self._generate_random_system()
                        ),
                        'level': random.choice(['INFO', 'WARN', 'ERROR', 'DEBUG'])
                    }
                    
                    raw_logs.append(log_entry)
        
        # Sort by timestamp
        raw_logs.sort(key=lambda x: x['timestamp'])
        
        return raw_logs
    
    def run_correlation_analysis(self) -> List[Dict[str, Any]]:
        """Run cross-platform log correlation analysis"""
        correlations = []
        
        # Simulate correlation findings
        correlation_patterns = [
            {
                'pattern': 'Multi-stage Attack Campaign',
                'confidence': 0.87,
                'systems': ['web-server-01', 'db-server-02', 'workstation-15'],
                'timespan': '2 hours 15 minutes',
                'description': 'Coordinated attack sequence detected across multiple systems involving initial compromise, lateral movement, and data access.',
                'timeline': [
                    'T+0: Web application exploit on web-server-01',
                    'T+45m: Lateral movement to db-server-02',
                    'T+1h30m: Database access and potential data exfiltration',
                    'T+2h: Suspicious activity on workstation-15'
                ]
            },
            {
                'pattern': 'Credential Stuffing Campaign',
                'confidence': 0.74,
                'systems': ['auth-server-01', 'mail-server-01', 'vpn-gateway'],
                'timespan': '45 minutes',
                'description': 'Automated credential testing across multiple authentication systems from distributed source IPs.',
                'timeline': [
                    'T+0: Failed login attempts on auth-server-01',
                    'T+15m: Similar patterns on mail-server-01',
                    'T+30m: VPN brute force attempts detected'
                ]
            },
            {
                'pattern': 'Insider Threat Activity',
                'confidence': 0.65,
                'systems': ['file-server-03', 'backup-server-01'],
                'timespan': '3 hours',
                'description': 'Unusual data access patterns by privileged user outside normal business hours.',
                'timeline': [
                    'T+0: After-hours login by privileged user',
                    'T+1h: Large file downloads from sensitive directories',
                    'T+2h30m: Backup system access and data transfer'
                ]
            }
        ]
        
        # Randomly select correlations to return
        num_correlations = random.randint(1, len(correlation_patterns))
        correlations = random.sample(correlation_patterns, num_correlations)
        
        return correlations
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        timestamp = str(datetime.now().timestamp())
        return hashlib.md5(timestamp.encode()).hexdigest()[:8].upper()
    
    def _generate_random_timestamp(self, time_range: str) -> datetime:
        """Generate random timestamp within specified range"""
        now = datetime.now()
        
        if time_range == 'Last Hour':
            start_time = now - timedelta(hours=1)
        elif time_range == 'Last 24h':
            start_time = now - timedelta(days=1)
        elif time_range == 'Last 7 days':
            start_time = now - timedelta(days=7)
        else:  # Custom Range or default
            start_time = now - timedelta(days=3)
        
        # Generate random timestamp between start_time and now
        time_diff = now - start_time
        random_seconds = random.randint(0, int(time_diff.total_seconds()))
        
        return start_time + timedelta(seconds=random_seconds)
    
    def _generate_event_description(self, pattern_name: str, source: str) -> str:
        """Generate human-readable event description"""
        descriptions = {
            'failed_login': f'Authentication failure detected in {source}',
            'privilege_escalation': f'Privilege escalation attempt detected in {source}',
            'suspicious_process': f'Suspicious process execution detected in {source}',
            'network_scan': f'Network scanning activity detected in {source}',
            'file_access': f'Unauthorized file access attempt in {source}',
            'malware_signature': f'Malware signature detected in {source}',
            'data_exfiltration': f'Potential data exfiltration detected in {source}',
            'system_shutdown': f'System shutdown event recorded in {source}'
        }
        
        return descriptions.get(pattern_name, f'Security event detected in {source}')
    
    def _generate_raw_log_entry(self, pattern_name: str, source: str) -> str:
        """Generate realistic raw log entry"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip = self._generate_random_ip()
        user = self._generate_random_user()
        
        log_formats = {
            'failed_login': f'{timestamp} {source}: Authentication failure for user {user} from {ip}',
            'privilege_escalation': f'{timestamp} {source}: User {user} attempted privilege escalation',
            'suspicious_process': f'{timestamp} {source}: Suspicious process execution by {user}',
            'network_scan': f'{timestamp} {source}: Port scan detected from {ip}',
            'file_access': f'{timestamp} {source}: Unauthorized file access by {user}',
            'malware_signature': f'{timestamp} {source}: Malware detected in file, user: {user}',
            'data_exfiltration': f'{timestamp} {source}: Large data transfer by {user} to {ip}',
            'system_shutdown': f'{timestamp} {source}: System shutdown initiated by {user}'
        }
        
        return log_formats.get(pattern_name, f'{timestamp} {source}: Generic security event')
    
    def _generate_random_ip(self) -> str:
        """Generate random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    def _generate_random_user(self) -> str:
        """Generate random username"""
        users = ['admin', 'administrator', 'root', 'guest', 'service', 'backup', 'monitor', 'user1', 'jdoe', 'asmith']
        return random.choice(users)
    
    def _generate_random_system(self) -> str:
        """Generate random system name"""
        systems = ['web-server-01', 'db-server-02', 'mail-server-01', 'file-server-03', 'backup-server-01', 
                  'workstation-15', 'workstation-23', 'domain-controller', 'firewall-01', 'proxy-server']
        return random.choice(systems)
    
    def _calculate_time_span(self, events: List[Dict[str, Any]]) -> str:
        """Calculate time span of events"""
        if not events:
            return "Unknown"
        
        timestamps = [event['timestamp'] for event in events]
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        duration = end_time - start_time
        
        if duration.total_seconds() < 3600:  # Less than 1 hour
            minutes = int(duration.total_seconds() / 60)
            return f"{minutes} minutes"
        elif duration.total_seconds() < 86400:  # Less than 1 day
            hours = int(duration.total_seconds() / 3600)
            return f"{hours} hours"
        else:
            days = int(duration.total_seconds() / 86400)
            return f"{days} days"
