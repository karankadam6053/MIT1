import random
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List
from enum import Enum
import json

class AttackCategory(Enum):
    RANSOMWARE = "Ransomware Simulation"
    NETWORK_INTRUSION = "Network Intrusion"
    ENDPOINT_ATTACKS = "Endpoint Attacks"
    SOCIAL_ENGINEERING = "Social Engineering"
    APT = "Advanced Persistent Threats"

class AttackSimulator:
    """Advanced attack simulation framework for testing security defenses"""
    
    def __init__(self):
        self.simulation_history = []
        self.active_simulations = {}
        self.detection_callbacks = []
        self.attack_templates = self._initialize_attack_templates()
        
    def _initialize_attack_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize attack simulation templates"""
        return {
            AttackCategory.RANSOMWARE.value: {
                "File Encryption Simulation": {
                    "description": "Simulate ransomware file encryption behavior",
                    "techniques": ["file_modification", "registry_changes", "network_communication"],
                    "indicators": ["suspicious_file_extensions", "high_file_operations", "crypto_api_calls"],
                    "duration_range": (60, 300),  # 1-5 minutes
                    "intensity_scaling": True
                },
                "Registry Modification": {
                    "description": "Simulate ransomware registry modifications",
                    "techniques": ["registry_persistence", "security_settings_change", "bootup_modifications"],
                    "indicators": ["registry_keys_modified", "security_policy_changes"],
                    "duration_range": (30, 120),
                    "intensity_scaling": True
                },
                "Network Share Encryption": {
                    "description": "Simulate network share encryption attacks",
                    "techniques": ["network_enumeration", "share_access", "remote_encryption"],
                    "indicators": ["network_scanning", "smb_traffic", "file_operations"],
                    "duration_range": (120, 600),
                    "intensity_scaling": True
                }
            },
            AttackCategory.NETWORK_INTRUSION.value: {
                "Port Scanning": {
                    "description": "Simulate network port scanning activity",
                    "techniques": ["tcp_scan", "udp_scan", "stealth_scan"],
                    "indicators": ["connection_attempts", "icmp_traffic", "failed_connections"],
                    "duration_range": (60, 300),
                    "intensity_scaling": True
                },
                "DDoS Simulation": {
                    "description": "Simulate distributed denial of service attack",
                    "techniques": ["connection_flooding", "bandwidth_consumption", "resource_exhaustion"],
                    "indicators": ["high_connection_count", "bandwidth_spikes", "response_time_degradation"],
                    "duration_range": (120, 600),
                    "intensity_scaling": True
                },
                "Man-in-the-Middle": {
                    "description": "Simulate MITM attack scenarios",
                    "techniques": ["arp_spoofing", "dns_poisoning", "ssl_interception"],
                    "indicators": ["arp_anomalies", "certificate_warnings", "traffic_redirection"],
                    "duration_range": (300, 900),
                    "intensity_scaling": False
                }
            },
            AttackCategory.ENDPOINT_ATTACKS.value: {
                "Malware Simulation": {
                    "description": "Simulate malware execution patterns",
                    "techniques": ["process_injection", "api_hooking", "file_system_changes"],
                    "indicators": ["suspicious_processes", "memory_anomalies", "file_modifications"],
                    "duration_range": (180, 600),
                    "intensity_scaling": True
                },
                "Process Injection": {
                    "description": "Simulate process injection techniques",
                    "techniques": ["dll_injection", "process_hollowing", "thread_execution_hijacking"],
                    "indicators": ["unusual_process_behavior", "memory_modifications", "api_calls"],
                    "duration_range": (60, 240),
                    "intensity_scaling": False
                },
                "Privilege Escalation": {
                    "description": "Simulate privilege escalation attempts",
                    "techniques": ["token_manipulation", "exploit_vulnerabilities", "bypass_uac"],
                    "indicators": ["privilege_changes", "system_calls", "security_log_events"],
                    "duration_range": (30, 120),
                    "intensity_scaling": False
                }
            },
            AttackCategory.SOCIAL_ENGINEERING.value: {
                "Phishing Simulation": {
                    "description": "Simulate phishing attack campaigns",
                    "techniques": ["email_spoofing", "credential_harvesting", "malicious_attachments"],
                    "indicators": ["suspicious_emails", "credential_submissions", "file_downloads"],
                    "duration_range": (1800, 3600),  # 30-60 minutes
                    "intensity_scaling": False
                },
                "USB Drop Attack": {
                    "description": "Simulate USB-based attack vectors",
                    "techniques": ["autorun_exploitation", "payload_execution", "lateral_movement"],
                    "indicators": ["usb_device_connections", "autorun_execution", "file_transfers"],
                    "duration_range": (300, 900),
                    "intensity_scaling": False
                },
                "Physical Breach": {
                    "description": "Simulate physical security breaches",
                    "techniques": ["unauthorized_access", "device_tampering", "information_gathering"],
                    "indicators": ["access_card_usage", "camera_blind_spots", "device_connections"],
                    "duration_range": (600, 1800),
                    "intensity_scaling": False
                }
            },
            AttackCategory.APT.value: {
                "Lateral Movement": {
                    "description": "Simulate advanced persistent threat lateral movement",
                    "techniques": ["credential_theft", "remote_execution", "persistence_mechanisms"],
                    "indicators": ["cross_system_logins", "unusual_network_traffic", "persistence_artifacts"],
                    "duration_range": (1800, 7200),  # 30 minutes to 2 hours
                    "intensity_scaling": False
                },
                "Data Exfiltration": {
                    "description": "Simulate covert data exfiltration",
                    "techniques": ["data_compression", "encryption", "covert_channels"],
                    "indicators": ["large_data_transfers", "encrypted_traffic", "unusual_protocols"],
                    "duration_range": (3600, 10800),  # 1-3 hours
                    "intensity_scaling": True
                },
                "Command & Control": {
                    "description": "Simulate C2 communication channels",
                    "techniques": ["encrypted_communication", "domain_fronting", "steganography"],
                    "indicators": ["periodic_network_beacons", "encrypted_payloads", "dns_queries"],
                    "duration_range": (7200, 28800),  # 2-8 hours
                    "intensity_scaling": False
                }
            }
        }
    
    def run_simulation(self, 
                      category: str,
                      attack_type: str, 
                      target: str,
                      intensity: int,
                      duration: str,
                      safe_mode: bool = True) -> Dict[str, Any]:
        """Run attack simulation and return results"""
        
        simulation_id = self._generate_simulation_id()
        start_time = datetime.now()
        
        # Get attack template
        if category not in self.attack_templates or attack_type not in self.attack_templates[category]:
            raise ValueError(f"Unknown attack type: {category}/{attack_type}")
        
        template = self.attack_templates[category][attack_type]
        
        # Parse duration
        duration_seconds = self._parse_duration(duration)
        
        # Create simulation context
        simulation_context = {
            'id': simulation_id,
            'category': category,
            'attack_type': attack_type,
            'target': target,
            'intensity': intensity,
            'duration_seconds': duration_seconds,
            'safe_mode': safe_mode,
            'start_time': start_time,
            'template': template
        }
        
        # Register active simulation
        self.active_simulations[simulation_id] = simulation_context
        
        try:
            # Execute simulation
            results = self._execute_simulation(simulation_context)
            
            # Record simulation results
            simulation_record = {
                'simulation_id': simulation_id,
                'timestamp': start_time,
                'category': category,
                'attack_type': attack_type,
                'target': target,
                'intensity': intensity,
                'duration': duration,
                'safe_mode': safe_mode,
                'attacks_launched': results['attacks_launched'],
                'attacks_detected': results['attacks_detected'],
                'attacks_blocked': results['attacks_blocked'],
                'detection_rate': results['detection_rate'],
                'avg_detection_time': results['avg_detection_time'],
                'fastest_response': results['fastest_response'],
                'slowest_response': results['slowest_response'],
                'missed_attacks': results['missed_attacks'],
                'response_actions': results['response_actions'],
                'false_positives': results.get('false_positives', 0),
                'true_positives': results.get('true_positives', 0),
                'avg_response_time': results['avg_detection_time']  # For compatibility
            }
            
            self.simulation_history.append(simulation_record)
            
            return results
            
        finally:
            # Clean up active simulation
            if simulation_id in self.active_simulations:
                del self.active_simulations[simulation_id]
    
    def _execute_simulation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the actual simulation"""
        template = context['template']
        intensity = context['intensity']
        duration_seconds = context['duration_seconds']
        safe_mode = context['safe_mode']
        
        # Calculate number of attack vectors based on intensity
        base_attacks = len(template['techniques'])
        attack_multiplier = max(1, intensity // 2)
        total_attacks = base_attacks * attack_multiplier
        
        # Simulate attack execution
        attacks_launched = 0
        attacks_detected = 0
        attacks_blocked = 0
        detection_times = []
        response_actions = []
        missed_attacks = []
        
        attack_interval = duration_seconds / total_attacks if total_attacks > 0 else 1
        
        for i in range(total_attacks):
            technique = template['techniques'][i % len(template['techniques'])]
            
            # Launch attack
            attacks_launched += 1
            attack_result = self._simulate_attack_technique(
                context['attack_type'], 
                technique, 
                intensity, 
                safe_mode
            )
            
            # Simulate detection
            detection_result = self._simulate_detection(attack_result, template)
            
            if detection_result['detected']:
                attacks_detected += 1
                detection_times.append(detection_result['detection_time'])
                
                # Simulate response
                response_result = self._simulate_response(attack_result, detection_result)
                
                if response_result['blocked']:
                    attacks_blocked += 1
                
                if response_result['actions']:
                    response_actions.extend(response_result['actions'])
            else:
                missed_attacks.append(technique)
            
            # Sleep between attacks (shortened for simulation)
            if not safe_mode and i < total_attacks - 1:
                time.sleep(min(attack_interval, 0.1))  # Cap at 0.1 seconds for demo
        
        # Calculate metrics
        detection_rate = (attacks_detected / attacks_launched * 100) if attacks_launched > 0 else 0
        avg_detection_time = sum(detection_times) / len(detection_times) if detection_times else 0
        fastest_response = min(detection_times) if detection_times else 0
        slowest_response = max(detection_times) if detection_times else 0
        
        # Remove duplicates from response actions
        response_actions = list(set(response_actions))
        
        return {
            'attacks_launched': attacks_launched,
            'attacks_detected': attacks_detected,
            'attacks_blocked': attacks_blocked,
            'detection_rate': round(detection_rate, 1),
            'avg_detection_time': f"{avg_detection_time:.1f}s",
            'fastest_response': f"{fastest_response:.1f}s",
            'slowest_response': f"{slowest_response:.1f}s",
            'missed_attacks': missed_attacks,
            'response_actions': response_actions,
            'true_positives': attacks_detected,
            'false_positives': max(0, attacks_detected - attacks_blocked)
        }
    
    def _simulate_attack_technique(self, attack_type: str, technique: str, intensity: int, safe_mode: bool) -> Dict[str, Any]:
        """Simulate individual attack technique"""
        
        # Base attack characteristics
        attack_result = {
            'attack_type': attack_type,
            'technique': technique,
            'intensity': intensity,
            'safe_mode': safe_mode,
            'timestamp': datetime.now(),
            'success_probability': self._calculate_success_probability(technique, intensity),
            'stealth_level': self._calculate_stealth_level(technique),
            'impact_level': self._calculate_impact_level(attack_type, technique),
            'artifacts': self._generate_attack_artifacts(technique)
        }
        
        # Technique-specific simulation
        if technique == "file_modification":
            attack_result.update(self._simulate_file_operations(intensity, safe_mode))
        elif technique == "network_communication":
            attack_result.update(self._simulate_network_activity(intensity, safe_mode))
        elif technique == "process_injection":
            attack_result.update(self._simulate_process_operations(intensity, safe_mode))
        elif technique == "registry_changes":
            attack_result.update(self._simulate_registry_operations(intensity, safe_mode))
        elif technique == "credential_theft":
            attack_result.update(self._simulate_credential_operations(intensity, safe_mode))
        
        return attack_result
    
    def _simulate_detection(self, attack_result: Dict[str, Any], template: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate security system detection of attack"""
        
        # Base detection probability based on attack characteristics
        base_detection_prob = 0.7  # 70% base detection rate
        
        # Adjust based on stealth level
        stealth_penalty = attack_result['stealth_level'] * 0.2
        detection_prob = max(0.1, base_detection_prob - stealth_penalty)
        
        # Adjust based on attack intensity (higher intensity = easier to detect)
        intensity_bonus = (attack_result['intensity'] - 5) * 0.05
        detection_prob = min(0.95, detection_prob + intensity_bonus)
        
        # Random detection decision
        detected = random.random() < detection_prob
        
        # Calculate detection time (in seconds)
        if detected:
            base_time = random.uniform(1.0, 30.0)  # 1-30 seconds base
            
            # Faster detection for high-intensity attacks
            intensity_factor = max(0.1, 1.0 - (attack_result['intensity'] - 1) * 0.1)
            detection_time = base_time * intensity_factor
            
            # Add some randomness
            detection_time += random.uniform(-5.0, 5.0)
            detection_time = max(0.1, detection_time)
        else:
            detection_time = 0
        
        return {
            'detected': detected,
            'detection_time': detection_time,
            'detection_probability': detection_prob,
            'detection_method': self._get_detection_method(attack_result['technique']),
            'confidence': random.uniform(0.6, 0.95) if detected else 0.0
        }
    
    def _simulate_response(self, attack_result: Dict[str, Any], detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate security system response to detected attack"""
        
        if not detection_result['detected']:
            return {'blocked': False, 'actions': []}
        
        # Determine response actions based on attack type and severity
        attack_type = attack_result['attack_type']
        technique = attack_result['technique']
        impact_level = attack_result['impact_level']
        
        possible_actions = []
        
        # File-based attacks
        if technique in ['file_modification', 'file_encryption']:
            possible_actions.extend(['Quarantine file', 'Block file operations', 'Restore from backup'])
        
        # Network-based attacks
        elif technique in ['network_communication', 'connection_flooding']:
            possible_actions.extend(['Block IP address', 'Rate limit connections', 'Activate DDoS protection'])
        
        # Process-based attacks
        elif technique in ['process_injection', 'suspicious_processes']:
            possible_actions.extend(['Terminate process', 'Isolate system', 'Memory dump'])
        
        # Registry-based attacks
        elif technique in ['registry_changes', 'persistence_mechanisms']:
            possible_actions.extend(['Revert registry changes', 'Block registry access', 'System restore'])
        
        # Credential-based attacks
        elif technique in ['credential_theft', 'credential_harvesting']:
            possible_actions.extend(['Force password reset', 'Disable account', 'Enable MFA'])
        
        # Generic actions
        possible_actions.extend(['Generate alert', 'Log incident', 'Notify security team'])
        
        # Determine which actions are taken
        actions_taken = []
        block_probability = 0.8 if impact_level == 'High' else 0.6 if impact_level == 'Medium' else 0.4
        
        # Always generate alert for detected attacks
        actions_taken.append('Generate alert')
        
        # Response based on impact level
        if impact_level == 'High':
            # High impact attacks get aggressive response
            num_actions = random.randint(2, 4)
            actions_taken.extend(random.sample(possible_actions[:-3], min(num_actions, len(possible_actions[:-3]))))
        elif impact_level == 'Medium':
            # Medium impact attacks get moderate response
            num_actions = random.randint(1, 3)
            actions_taken.extend(random.sample(possible_actions[:-3], min(num_actions, len(possible_actions[:-3]))))
        else:
            # Low impact attacks get minimal response
            if random.random() < 0.5:
                actions_taken.append(random.choice(possible_actions[:-3]))
        
        # Determine if attack was successfully blocked
        blocked = random.random() < block_probability
        
        return {
            'blocked': blocked,
            'actions': list(set(actions_taken)),  # Remove duplicates
            'response_time': detection_result['detection_time'] + random.uniform(1.0, 10.0),
            'effectiveness': random.uniform(0.7, 0.95) if blocked else random.uniform(0.3, 0.7)
        }
    
    def get_simulation_history(self) -> List[Dict[str, Any]]:
        """Get history of all simulations"""
        return sorted(self.simulation_history, key=lambda x: x['timestamp'], reverse=True)
    
    def get_active_simulations(self) -> Dict[str, Dict[str, Any]]:
        """Get currently active simulations"""
        return self.active_simulations.copy()
    
    def stop_simulation(self, simulation_id: str) -> bool:
        """Stop an active simulation"""
        if simulation_id in self.active_simulations:
            del self.active_simulations[simulation_id]
            return True
        return False
    
    def _generate_simulation_id(self) -> str:
        """Generate unique simulation ID"""
        timestamp = str(datetime.now().timestamp())
        return f"SIM-{hashlib.md5(timestamp.encode()).hexdigest()[:8].upper()}"
    
    def _parse_duration(self, duration: str) -> int:
        """Parse duration string to seconds"""
        duration_map = {
            "1 minute": 60,
            "5 minutes": 300,
            "15 minutes": 900,
            "30 minutes": 1800
        }
        return duration_map.get(duration, 300)  # Default to 5 minutes
    
    def _calculate_success_probability(self, technique: str, intensity: int) -> float:
        """Calculate probability of attack technique success"""
        base_probabilities = {
            'file_modification': 0.8,
            'network_communication': 0.7,
            'process_injection': 0.6,
            'registry_changes': 0.9,
            'credential_theft': 0.5,
            'privilege_escalation': 0.4,
            'lateral_movement': 0.6
        }
        
        base_prob = base_probabilities.get(technique, 0.5)
        intensity_bonus = (intensity - 5) * 0.05  # Intensity 1-10, centered at 5
        
        return max(0.1, min(0.95, base_prob + intensity_bonus))
    
    def _calculate_stealth_level(self, technique: str) -> float:
        """Calculate stealth level of attack technique (0.0 = obvious, 1.0 = very stealthy)"""
        stealth_levels = {
            'file_modification': 0.3,
            'network_communication': 0.6,
            'process_injection': 0.8,
            'registry_changes': 0.4,
            'credential_theft': 0.7,
            'privilege_escalation': 0.5,
            'lateral_movement': 0.9
        }
        
        return stealth_levels.get(technique, 0.5)
    
    def _calculate_impact_level(self, attack_type: str, technique: str) -> str:
        """Calculate impact level of attack"""
        high_impact_attacks = ['Data Exfiltration', 'File Encryption Simulation', 'System Compromise']
        high_impact_techniques = ['file_modification', 'credential_theft', 'privilege_escalation']
        
        if attack_type in high_impact_attacks or technique in high_impact_techniques:
            return 'High'
        elif 'Simulation' in attack_type or technique in ['network_communication', 'registry_changes']:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_attack_artifacts(self, technique: str) -> List[str]:
        """Generate artifacts that would be left by attack technique"""
        artifact_map = {
            'file_modification': ['Modified file timestamps', 'Unusual file extensions', 'Large file operations'],
            'network_communication': ['Suspicious network connections', 'Encrypted traffic', 'DNS queries'],
            'process_injection': ['Memory modifications', 'Unusual process behavior', 'API call patterns'],
            'registry_changes': ['Registry key modifications', 'Startup program changes', 'Security setting changes'],
            'credential_theft': ['Authentication attempts', 'Credential access patterns', 'Account enumeration']
        }
        
        return artifact_map.get(technique, ['Generic attack artifacts'])
    
    def _get_detection_method(self, technique: str) -> str:
        """Get the detection method used for technique"""
        detection_methods = {
            'file_modification': 'File System Monitoring',
            'network_communication': 'Network Traffic Analysis',
            'process_injection': 'Behavioral Analysis',
            'registry_changes': 'Registry Monitoring',
            'credential_theft': 'Authentication Log Analysis',
            'privilege_escalation': 'Privilege Monitoring',
            'lateral_movement': 'Network Behavior Analysis'
        }
        
        return detection_methods.get(technique, 'Signature-based Detection')
    
    # Technique-specific simulation methods
    def _simulate_file_operations(self, intensity: int, safe_mode: bool) -> Dict[str, Any]:
        """Simulate file system operations"""
        num_files = intensity * 10
        
        return {
            'files_affected': num_files,
            'operations_per_second': intensity * 5,
            'file_types': ['documents', 'images', 'databases'] if intensity > 5 else ['temp_files'],
            'total_size_mb': num_files * random.randint(1, 10)
        }
    
    def _simulate_network_activity(self, intensity: int, safe_mode: bool) -> Dict[str, Any]:
        """Simulate network activity"""
        connections = intensity * 20
        
        return {
            'connections_made': connections,
            'bandwidth_used_mb': intensity * 5,
            'destination_ports': [80, 443, 8080] if intensity > 3 else [80],
            'protocols': ['HTTP', 'HTTPS', 'TCP']
        }
    
    def _simulate_process_operations(self, intensity: int, safe_mode: bool) -> Dict[str, Any]:
        """Simulate process-related operations"""
        return {
            'processes_spawned': intensity,
            'memory_allocated_mb': intensity * 50,
            'cpu_usage_percent': min(100, intensity * 10),
            'api_calls_made': intensity * 100
        }
    
    def _simulate_registry_operations(self, intensity: int, safe_mode: bool) -> Dict[str, Any]:
        """Simulate registry operations"""
        return {
            'registry_keys_modified': intensity * 5,
            'registry_values_changed': intensity * 10,
            'startup_entries_added': min(intensity, 3),
            'security_policies_changed': min(intensity // 2, 5)
        }
    
    def _simulate_credential_operations(self, intensity: int, safe_mode: bool) -> Dict[str, Any]:
        """Simulate credential-related operations"""
        return {
            'accounts_targeted': min(intensity * 2, 50),
            'login_attempts': intensity * 20,
            'credential_sources_accessed': ['SAM', 'LSASS', 'Registry'] if intensity > 7 else ['Registry'],
            'hash_extraction_attempts': min(intensity, 10)
        }
