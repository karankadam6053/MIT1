import random
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
import re

class ThreatDetectionEngine:
    """Main threat detection engine coordinating all security modules"""
    
    def __init__(self):
        self.active_threats = []
        self.threat_signatures = self._load_threat_signatures()
        self.detection_rules = self._initialize_detection_rules()
        self.system_health = {
            'score': 8.5,
            'trend': 0.2,
            'protected_assets': 1247,
            'new_assets': 15
        }
    
    def _load_threat_signatures(self) -> Dict[str, Any]:
        """Load threat signatures and IOCs"""
        return {
            'ransomware': {
                'file_extensions': ['.encrypted', '.locked', '.crypto', '.vault', '.crypt'],
                'registry_keys': [
                    'HKEY_LOCAL_MACHINE\\SOFTWARE\\WanaCrypt0r',
                    'HKEY_CURRENT_USER\\Software\\Bitcoin'
                ],
                'processes': ['wannacry.exe', 'tasksche.exe', 'disk.exe'],
                'network_indicators': ['*.onion', 'tor2web.org', 'bitcoin']
            },
            'apt': {
                'lateral_movement': ['psexec', 'wmiexec', 'smbexec', 'rdp_login'],
                'persistence': ['schtasks', 'sc create', 'reg add', 'wmic'],
                'exfiltration': ['ftp', 'sftp', 'http_post', 'dns_tunnel'],
                'c2_patterns': ['base64_encoded', 'periodic_beacon', 'encrypted_traffic']
            },
            'malware': {
                'suspicious_processes': ['powershell -enc', 'cmd /c', 'rundll32', 'regsvr32'],
                'file_behaviors': ['file_encryption', 'registry_modification', 'privilege_escalation'],
                'network_behaviors': ['c2_communication', 'data_exfiltration', 'port_scanning']
            }
        }
    
    def _initialize_detection_rules(self) -> List[Dict[str, Any]]:
        """Initialize behavioral detection rules"""
        return [
            {
                'name': 'Mass File Encryption',
                'category': 'Ransomware',
                'pattern': r'.*\.(encrypted|locked|crypto)$',
                'threshold': 10,
                'severity': 'Critical'
            },
            {
                'name': 'Suspicious PowerShell',
                'category': 'Malware',
                'pattern': r'powershell.*-enc.*',
                'threshold': 1,
                'severity': 'High'
            },
            {
                'name': 'Port Scanning',
                'category': 'Network Intrusion',
                'pattern': r'connect_attempts > 100',
                'threshold': 100,
                'severity': 'Medium'
            },
            {
                'name': 'Privilege Escalation',
                'category': 'Endpoint Attack',
                'pattern': r'.*SeDebugPrivilege.*',
                'threshold': 1,
                'severity': 'High'
            }
        ]
    
    def detect_threats(self, log_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Main threat detection function"""
        detected_threats = []
        
        for log_entry in log_data:
            threats = self._analyze_log_entry(log_entry)
            detected_threats.extend(threats)
        
        # Update active threats
        self.active_threats.extend(detected_threats)
        
        # Remove old threats (older than 24 hours)
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.active_threats = [
            threat for threat in self.active_threats 
            if threat['timestamp'] > cutoff_time
        ]
        
        return detected_threats
    
    def _analyze_log_entry(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze individual log entry for threats"""
        threats = []
        
        # Check against detection rules
        for rule in self.detection_rules:
            if self._matches_rule(log_entry, rule):
                threat = {
                    'id': self._generate_threat_id(),
                    'type': rule['category'],
                    'name': rule['name'],
                    'severity': rule['severity'],
                    'confidence': self._calculate_confidence(log_entry, rule),
                    'timestamp': datetime.now(),
                    'source': log_entry.get('source', 'Unknown'),
                    'target': log_entry.get('target', 'Unknown'),
                    'description': self._generate_threat_description(rule, log_entry),
                    'indicators': self._extract_indicators(log_entry),
                    'recommended_action': self._get_recommended_action(rule['severity'])
                }
                threats.append(threat)
        
        # Check for specific threat patterns
        threats.extend(self._detect_ransomware_patterns(log_entry))
        threats.extend(self._detect_apt_patterns(log_entry))
        threats.extend(self._detect_zero_day_patterns(log_entry))
        
        return threats
    
    def _matches_rule(self, log_entry: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if log entry matches detection rule"""
        pattern = rule['pattern']
        
        # Simple pattern matching for demo
        log_text = str(log_entry)
        return bool(re.search(pattern, log_text, re.IGNORECASE))
    
    def _calculate_confidence(self, log_entry: Dict[str, Any], rule: Dict[str, Any]) -> float:
        """Calculate confidence score for threat detection"""
        base_confidence = 0.7
        
        # Increase confidence based on multiple indicators
        indicators_count = len(self._extract_indicators(log_entry))
        confidence_boost = min(indicators_count * 0.1, 0.3)
        
        return min(base_confidence + confidence_boost, 1.0)
    
    def _generate_threat_description(self, rule: Dict[str, Any], log_entry: Dict[str, Any]) -> str:
        """Generate human-readable threat description"""
        descriptions = {
            'Ransomware': f"Potential ransomware activity detected. Rule '{rule['name']}' triggered by suspicious file operations.",
            'Malware': f"Malicious software behavior detected. Rule '{rule['name']}' indicates potential malware execution.",
            'Network Intrusion': f"Network intrusion attempt detected. Rule '{rule['name']}' shows suspicious network activity.",
            'Endpoint Attack': f"Endpoint compromise detected. Rule '{rule['name']}' indicates system-level attack."
        }
        
        return descriptions.get(rule['category'], f"Security rule '{rule['name']}' triggered.")
    
    def _extract_indicators(self, log_entry: Dict[str, Any]) -> List[str]:
        """Extract indicators of compromise from log entry"""
        indicators = []
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        indicators.extend(re.findall(ip_pattern, str(log_entry)))
        
        # Extract file hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        indicators.extend(re.findall(hash_pattern, str(log_entry)))
        
        # Extract domain names
        domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b'
        indicators.extend(re.findall(domain_pattern, str(log_entry)))
        
        return list(set(indicators))  # Remove duplicates
    
    def _get_recommended_action(self, severity: str) -> str:
        """Get recommended action based on threat severity"""
        actions = {
            'Critical': 'Immediate isolation and incident response required',
            'High': 'Investigate immediately and consider containment',
            'Medium': 'Schedule investigation within 4 hours',
            'Low': 'Monitor and investigate during normal business hours'
        }
        
        return actions.get(severity, 'Monitor and assess')
    
    def _detect_ransomware_patterns(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect ransomware-specific patterns"""
        threats = []
        log_text = str(log_entry).lower()
        
        # Check for file encryption patterns
        if any(ext in log_text for ext in self.threat_signatures['ransomware']['file_extensions']):
            threats.append({
                'id': self._generate_threat_id(),
                'type': 'Ransomware',
                'name': 'File Encryption Activity',
                'severity': 'Critical',
                'confidence': 0.9,
                'timestamp': datetime.now(),
                'source': log_entry.get('source', 'Unknown'),
                'target': log_entry.get('target', 'Unknown'),
                'description': 'Suspicious file encryption activity detected. Multiple files with ransomware-associated extensions found.',
                'indicators': self._extract_indicators(log_entry),
                'recommended_action': 'Immediate system isolation and backup restoration'
            })
        
        # Check for ransomware processes
        if any(proc in log_text for proc in self.threat_signatures['ransomware']['processes']):
            threats.append({
                'id': self._generate_threat_id(),
                'type': 'Ransomware',
                'name': 'Known Ransomware Process',
                'severity': 'Critical',
                'confidence': 0.95,
                'timestamp': datetime.now(),
                'source': log_entry.get('source', 'Unknown'),
                'target': log_entry.get('target', 'Unknown'),
                'description': 'Known ransomware process detected in system execution logs.',
                'indicators': self._extract_indicators(log_entry),
                'recommended_action': 'Immediate process termination and system isolation'
            })
        
        return threats
    
    def _detect_apt_patterns(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect Advanced Persistent Threat patterns"""
        threats = []
        log_text = str(log_entry).lower()
        
        # Check for lateral movement
        if any(tool in log_text for tool in self.threat_signatures['apt']['lateral_movement']):
            threats.append({
                'id': self._generate_threat_id(),
                'type': 'APT',
                'name': 'Lateral Movement',
                'severity': 'High',
                'confidence': 0.8,
                'timestamp': datetime.now(),
                'source': log_entry.get('source', 'Unknown'),
                'target': log_entry.get('target', 'Unknown'),
                'description': 'Potential lateral movement activity detected. Attacker may be spreading through the network.',
                'indicators': self._extract_indicators(log_entry),
                'recommended_action': 'Investigate network traffic and isolate affected systems'
            })
        
        # Check for data exfiltration
        if any(method in log_text for method in self.threat_signatures['apt']['exfiltration']):
            threats.append({
                'id': self._generate_threat_id(),
                'type': 'APT',
                'name': 'Data Exfiltration',
                'severity': 'Critical',
                'confidence': 0.85,
                'timestamp': datetime.now(),
                'source': log_entry.get('source', 'Unknown'),
                'target': log_entry.get('target', 'Unknown'),
                'description': 'Potential data exfiltration detected. Sensitive data may be leaving the network.',
                'indicators': self._extract_indicators(log_entry),
                'recommended_action': 'Block external connections and investigate data flows'
            })
        
        return threats
    
    def _detect_zero_day_patterns(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect potential zero-day exploit patterns"""
        threats = []
        log_text = str(log_entry).lower()
        
        # Look for unusual process behavior
        suspicious_patterns = [
            'buffer overflow', 'heap spray', 'rop chain', 'shellcode',
            'memory corruption', 'arbitrary code execution'
        ]
        
        if any(pattern in log_text for pattern in suspicious_patterns):
            threats.append({
                'id': self._generate_threat_id(),
                'type': 'Zero-Day Exploit',
                'name': 'Memory Corruption Attack',
                'severity': 'Critical',
                'confidence': 0.75,
                'timestamp': datetime.now(),
                'source': log_entry.get('source', 'Unknown'),
                'target': log_entry.get('target', 'Unknown'),
                'description': 'Potential zero-day exploit detected. Memory corruption patterns indicate advanced attack.',
                'indicators': self._extract_indicators(log_entry),
                'recommended_action': 'Immediate system isolation and forensic analysis'
            })
        
        return threats
    
    def _generate_threat_id(self) -> str:
        """Generate unique threat ID"""
        timestamp = str(datetime.now().timestamp())
        return hashlib.md5(timestamp.encode()).hexdigest()[:8].upper()
    
    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Get list of currently active threats"""
        return sorted(self.active_threats, key=lambda x: x['timestamp'], reverse=True)
    
    def get_threat_distribution(self) -> Dict[str, int]:
        """Get distribution of threat types"""
        distribution = {}
        for threat in self.active_threats:
            threat_type = threat['type']
            distribution[threat_type] = distribution.get(threat_type, 0) + 1
        
        # Add some baseline data if no threats
        if not distribution:
            distribution = {
                'Network Intrusion': 5,
                'Malware': 3,
                'Phishing': 2,
                'Data Breach': 1
            }
        
        return distribution
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health metrics"""
        return self.system_health
    
    def update_system_health(self, threats_count: int):
        """Update system health based on current threat landscape"""
        if threats_count > 10:
            self.system_health['score'] = max(5.0, self.system_health['score'] - 0.5)
        elif threats_count < 3:
            self.system_health['score'] = min(10.0, self.system_health['score'] + 0.1)
        
        # Simulate trend
        self.system_health['trend'] = random.uniform(-0.5, 0.5)
