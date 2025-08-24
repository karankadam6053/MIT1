import random
import time
import socket
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import ipaddress
import json
import hashlib
from collections import defaultdict

class NetworkMonitor:
    """Advanced network security monitoring and intrusion detection system"""
    
    def __init__(self):
        self.monitored_networks = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']
        self.active_connections = {}
        self.blocked_ips = []
        self.network_devices = []
        self.traffic_stats = defaultdict(int)
        self.intrusion_signatures = self._load_intrusion_signatures()
        self.monitoring_active = False
        self.threat_indicators = []
        self.network_topology = self._initialize_network_topology()
        self.ids_rules = self._load_ids_rules()
        self.baseline_traffic = self._establish_traffic_baseline()
        
    def _load_intrusion_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load network intrusion detection signatures"""
        return {
            'port_scan': {
                'pattern': 'multiple_port_connections',
                'threshold': 50,
                'timeframe': 60,  # seconds
                'severity': 'Medium',
                'description': 'Port scanning activity detected'
            },
            'ddos_tcp_syn': {
                'pattern': 'high_syn_rate',
                'threshold': 1000,
                'timeframe': 10,
                'severity': 'Critical',
                'description': 'TCP SYN flood attack detected'
            },
            'ddos_udp': {
                'pattern': 'high_udp_rate',
                'threshold': 5000,
                'timeframe': 10,
                'severity': 'Critical',
                'description': 'UDP flood attack detected'
            },
            'brute_force': {
                'pattern': 'failed_authentication',
                'threshold': 20,
                'timeframe': 300,
                'severity': 'High',
                'description': 'Brute force authentication attack'
            },
            'lateral_movement': {
                'pattern': 'internal_scanning',
                'threshold': 10,
                'timeframe': 120,
                'severity': 'High',
                'description': 'Potential lateral movement detected'
            },
            'data_exfiltration': {
                'pattern': 'large_outbound_transfer',
                'threshold': 100,  # MB
                'timeframe': 60,
                'severity': 'Critical',
                'description': 'Large data transfer detected'
            },
            'dns_tunneling': {
                'pattern': 'abnormal_dns_traffic',
                'threshold': 100,
                'timeframe': 60,
                'severity': 'High',
                'description': 'DNS tunneling activity detected'
            },
            'c2_communication': {
                'pattern': 'periodic_beaconing',
                'threshold': 5,
                'timeframe': 3600,
                'severity': 'Critical',
                'description': 'Command and control communication detected'
            }
        }
    
    def _initialize_network_topology(self) -> Dict[str, Any]:
        """Initialize network topology data"""
        devices = []
        connections = []
        
        # Generate network devices
        device_types = ['firewall', 'switch', 'router', 'server', 'workstation', 'printer', 'camera']
        statuses = ['healthy', 'suspicious', 'compromised']
        
        for i in range(20):
            device = {
                'id': f'device_{i+1}',
                'name': f'{random.choice(device_types)}-{i+1:02d}',
                'type': random.choice(device_types),
                'ip': f'192.168.1.{random.randint(10, 250)}',
                'mac': self._generate_mac_address(),
                'status': random.choices(statuses, weights=[0.8, 0.15, 0.05])[0],
                'x': random.randint(50, 950),
                'y': random.randint(50, 450),
                'last_seen': datetime.now() - timedelta(minutes=random.randint(0, 60)),
                'open_ports': random.sample([22, 23, 80, 135, 139, 443, 445, 3389], random.randint(2, 5)),
                'os': random.choice(['Windows 10', 'Windows Server 2019', 'Ubuntu 20.04', 'CentOS 7', 'macOS']),
                'vulnerability_score': random.uniform(1.0, 10.0)
            }
            devices.append(device)
        
        # Generate connections between devices
        for i in range(30):
            device1 = random.choice(devices)
            device2 = random.choice(devices)
            if device1 != device2:
                connection = {
                    'id': f'conn_{i+1}',
                    'source': device1['id'],
                    'target': device2['id'],
                    'x1': device1['x'],
                    'y1': device1['y'],
                    'x2': device2['x'],
                    'y2': device2['y'],
                    'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                    'port': random.choice([80, 443, 22, 3389, 445]),
                    'status': random.choice(['active', 'idle', 'blocked']),
                    'bandwidth_usage': random.uniform(0.1, 100.0)  # Mbps
                }
                connections.append(connection)
        
        return {
            'devices': devices,
            'connections': connections
        }
    
    def _load_ids_rules(self) -> Dict[str, Any]:
        """Load Intrusion Detection System rules"""
        return {
            'active': True,
            'last_update': '2024-08-23',
            'rules_count': 15247,
            'signature_version': '2024.08.23.001',
            'categories': {
                'malware': 3456,
                'exploit': 2789,
                'policy_violation': 1234,
                'trojan': 2345,
                'worm': 567,
                'backdoor': 890,
                'spyware': 1234,
                'adware': 456,
                'rootkit': 234,
                'other': 3042
            }
        }
    
    def _establish_traffic_baseline(self) -> Dict[str, float]:
        """Establish network traffic baseline"""
        return {
            'average_packets_per_second': 1250.5,
            'average_bytes_per_second': 2048000.0,
            'peak_packets_per_second': 5000.0,
            'peak_bytes_per_second': 10485760.0,
            'connection_rate': 50.0,
            'protocol_distribution': {
                'TCP': 0.70,
                'UDP': 0.25,
                'ICMP': 0.05
            },
            'port_distribution': {
                '80': 0.30,
                '443': 0.35,
                '22': 0.05,
                '21': 0.02,
                '25': 0.03,
                'others': 0.25
            }
        }
    
    def get_network_statistics(self) -> Dict[str, Any]:
        """Get current network statistics"""
        current_time = datetime.now()
        
        # Calculate dynamic statistics
        base_connections = 450
        connection_variance = random.randint(-50, 100)
        current_connections = max(0, base_connections + connection_variance)
        
        # Simulate blocked threats based on time and activity
        base_blocked = 127
        blocked_variance = random.randint(-20, 50)
        blocked_threats = max(0, base_blocked + blocked_variance)
        
        # Calculate health score
        health_factors = []
        health_factors.append(min(10.0, (1000 - current_connections) / 100))  # Connection load
        health_factors.append(min(10.0, (200 - blocked_threats) / 20))  # Threat activity
        health_factors.append(random.uniform(7.0, 9.5))  # Random component
        
        health_score = sum(health_factors) / len(health_factors)
        
        return {
            'networks': len(self.monitored_networks),
            'connections': current_connections,
            'blocked_threats': blocked_threats,
            'health_score': round(health_score, 1),
            'total_devices': len(self.network_topology['devices']),
            'active_devices': len([d for d in self.network_topology['devices'] if d['status'] == 'healthy']),
            'suspicious_devices': len([d for d in self.network_topology['devices'] if d['status'] == 'suspicious']),
            'compromised_devices': len([d for d in self.network_topology['devices'] if d['status'] == 'compromised']),
            'bandwidth_utilization': random.uniform(15.0, 85.0),
            'packet_loss_rate': random.uniform(0.01, 0.5),
            'average_latency_ms': random.uniform(1.0, 50.0)
        }
    
    def analyze_traffic(self) -> Dict[str, Any]:
        """Analyze current network traffic for threats"""
        current_time = datetime.now()
        analysis_results = {
            'threats': [],
            'analysis_time': current_time,
            'packets_analyzed': random.randint(10000, 100000),
            'anomalies_detected': 0,
            'baseline_deviation': {}
        }
        
        # Simulate threat detection based on signatures
        for signature_name, signature in self.intrusion_signatures.items():
            detection_probability = self._calculate_detection_probability(signature_name)
            
            if random.random() < detection_probability:
                threat = self._generate_threat_from_signature(signature_name, signature)
                analysis_results['threats'].append(threat)
                analysis_results['anomalies_detected'] += 1
        
        # Calculate baseline deviations
        current_baseline = self._get_current_traffic_metrics()
        for metric, current_value in current_baseline.items():
            baseline_value = self.baseline_traffic.get(metric, 0)
            if baseline_value > 0:
                deviation = ((current_value - baseline_value) / baseline_value) * 100
                analysis_results['baseline_deviation'][metric] = round(deviation, 2)
        
        return analysis_results
    
    def get_ids_status(self) -> Dict[str, Any]:
        """Get Intrusion Detection System status"""
        return {
            'active': self.ids_rules['active'],
            'last_update': self.ids_rules['last_update'],
            'rules_count': self.ids_rules['rules_count'],
            'signature_version': self.ids_rules['signature_version'],
            'engine_version': '6.4.2',
            'performance': {
                'packets_processed_per_second': random.randint(50000, 200000),
                'cpu_utilization': random.uniform(15.0, 45.0),
                'memory_usage': random.uniform(512.0, 2048.0),
                'disk_usage_gb': random.uniform(50.0, 500.0)
            },
            'categories': self.ids_rules['categories']
        }
    
    def update_signatures(self) -> bool:
        """Update IDS signatures"""
        try:
            # Simulate signature update process
            time.sleep(1)  # Simulate download time
            
            self.ids_rules['last_update'] = datetime.now().strftime('%Y-%m-%d')
            self.ids_rules['rules_count'] += random.randint(10, 100)
            self.ids_rules['signature_version'] = f"2024.{datetime.now().strftime('%m.%d')}.001"
            
            return True
        except Exception as e:
            print(f"Failed to update signatures: {e}")
            return False
    
    def get_network_topology(self) -> Dict[str, Any]:
        """Get network topology for visualization"""
        return self.network_topology
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of blocked IP addresses"""
        blocked_ips_data = []
        
        # Generate some blocked IPs with context
        for i in range(random.randint(5, 20)):
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            blocked_ip = {
                'ip_address': ip,
                'country': random.choice(['CN', 'RU', 'KP', 'IR', 'BR', 'IN', 'US', 'DE']),
                'threat_type': random.choice(['Port Scan', 'Brute Force', 'DDoS', 'Malware C2', 'Spam']),
                'blocked_time': datetime.now() - timedelta(hours=random.randint(0, 24)),
                'block_count': random.randint(1, 1000),
                'reason': random.choice([
                    'Multiple port scan attempts',
                    'Brute force SSH attacks',
                    'DDoS participation',
                    'Malware command and control',
                    'Spam relay activity',
                    'SQL injection attempts',
                    'Known botnet member'
                ]),
                'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
                'auto_blocked': random.choice([True, False]),
                'expires': datetime.now() + timedelta(hours=random.randint(1, 168))  # 1 hour to 1 week
            }
            
            blocked_ips_data.append(blocked_ip)
        
        # Sort by blocked time (most recent first)
        blocked_ips_data.sort(key=lambda x: x['blocked_time'], reverse=True)
        
        return blocked_ips_data
    
    def block_ip(self, ip_address: str, reason: str) -> bool:
        """Block an IP address"""
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            
            # Add to blocked IPs
            block_entry = {
                'ip_address': ip_address,
                'reason': reason,
                'blocked_time': datetime.now(),
                'blocked_by': 'Manual',
                'severity': 'High',
                'auto_blocked': False
            }
            
            self.blocked_ips.append(block_entry)
            
            # In a real implementation, this would interface with firewall/router
            print(f"Blocked IP {ip_address}: {reason}")
            
            return True
            
        except ValueError:
            print(f"Invalid IP address: {ip_address}")
            return False
        except Exception as e:
            print(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        try:
            # Remove from blocked IPs list
            self.blocked_ips = [ip for ip in self.blocked_ips if ip['ip_address'] != ip_address]
            
            # In a real implementation, this would interface with firewall/router
            print(f"Unblocked IP {ip_address}")
            
            return True
            
        except Exception as e:
            print(f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def run_continuous_monitoring(self):
        """Run continuous network monitoring"""
        if self.monitoring_active:
            return  # Already running
        
        self.monitoring_active = True
        
        def monitoring_loop():
            while self.monitoring_active:
                try:
                    # Perform network analysis
                    analysis_results = self.analyze_traffic()
                    
                    # Process any detected threats
                    for threat in analysis_results['threats']:
                        self._process_network_threat(threat)
                    
                    # Update network statistics
                    self._update_traffic_stats()
                    
                    # Check for device status changes
                    self._update_device_status()
                    
                    # Sleep for monitoring interval
                    time.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    print(f"Network monitoring error: {e}")
                    time.sleep(60)  # Wait longer on error
        
        # Start monitoring in separate thread
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous network monitoring"""
        self.monitoring_active = False
    
    def get_traffic_analytics(self) -> Dict[str, Any]:
        """Get detailed traffic analytics"""
        return {
            'total_packets_24h': random.randint(1000000, 10000000),
            'total_bytes_24h': random.randint(1000000000, 100000000000),  # 1GB to 100GB
            'top_protocols': {
                'HTTP': random.randint(100000, 1000000),
                'HTTPS': random.randint(200000, 2000000),
                'SSH': random.randint(1000, 10000),
                'FTP': random.randint(500, 5000),
                'SMTP': random.randint(5000, 50000),
                'DNS': random.randint(10000, 100000)
            },
            'top_destinations': [
                {'ip': '8.8.8.8', 'packets': random.randint(10000, 100000), 'description': 'Google DNS'},
                {'ip': '1.1.1.1', 'packets': random.randint(5000, 50000), 'description': 'Cloudflare DNS'},
                {'ip': '208.67.222.222', 'packets': random.randint(3000, 30000), 'description': 'OpenDNS'},
            ],
            'bandwidth_usage_history': self._generate_bandwidth_history(),
            'connection_types': {
                'Inbound': random.randint(1000, 10000),
                'Outbound': random.randint(5000, 50000),
                'Internal': random.randint(2000, 20000)
            },
            'geographic_distribution': {
                'US': random.randint(100000, 500000),
                'EU': random.randint(50000, 200000),
                'AS': random.randint(30000, 150000),
                'Other': random.randint(20000, 100000)
            }
        }
    
    def _calculate_detection_probability(self, signature_name: str) -> float:
        """Calculate probability of detecting a specific threat type"""
        base_probabilities = {
            'port_scan': 0.15,
            'ddos_tcp_syn': 0.05,
            'ddos_udp': 0.03,
            'brute_force': 0.08,
            'lateral_movement': 0.02,
            'data_exfiltration': 0.01,
            'dns_tunneling': 0.01,
            'c2_communication': 0.005
        }
        
        return base_probabilities.get(signature_name, 0.01)
    
    def _generate_threat_from_signature(self, signature_name: str, signature: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a threat detection from signature"""
        source_ips = [f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(random.randint(1, 5))]
        target_ips = [f"192.168.1.{random.randint(10, 250)}" for _ in range(random.randint(1, 3))]
        
        threat = {
            'type': signature_name.replace('_', ' ').title(),
            'description': signature['description'],
            'severity': signature['severity'],
            'confidence': random.uniform(0.7, 0.95),
            'source_ips': source_ips,
            'target_ips': target_ips,
            'timestamp': datetime.now(),
            'signature_id': f"SIG-{hashlib.md5(signature_name.encode()).hexdigest()[:8].upper()}",
            'packet_count': random.randint(signature['threshold'], signature['threshold'] * 5),
            'duration': random.randint(signature['timeframe'], signature['timeframe'] * 3),
            'protocols': random.sample(['TCP', 'UDP', 'ICMP'], random.randint(1, 2)),
            'ports': random.sample([21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389], random.randint(1, 5))
        }
        
        # Add specific details based on threat type
        if signature_name == 'port_scan':
            threat['scan_type'] = random.choice(['TCP SYN', 'TCP Connect', 'UDP', 'Stealth'])
            threat['ports_scanned'] = random.randint(100, 65535)
            
        elif signature_name == 'brute_force':
            threat['service'] = random.choice(['SSH', 'RDP', 'FTP', 'Telnet'])
            threat['attempts'] = random.randint(20, 1000)
            threat['success_rate'] = random.uniform(0.0, 0.05)
            
        elif 'ddos' in signature_name:
            threat['attack_vector'] = signature_name.replace('ddos_', '').upper()
            threat['bandwidth_consumed'] = random.randint(10, 1000)  # Mbps
            threat['amplification_factor'] = random.uniform(1.0, 50.0)
            
        elif signature_name == 'data_exfiltration':
            threat['data_volume_mb'] = random.randint(100, 10000)
            threat['destination_country'] = random.choice(['CN', 'RU', 'KP', 'IR'])
            threat['encryption_detected'] = random.choice([True, False])
        
        return threat
    
    def _get_current_traffic_metrics(self) -> Dict[str, float]:
        """Get current traffic metrics for baseline comparison"""
        return {
            'packets_per_second': random.uniform(800, 2000),
            'bytes_per_second': random.uniform(1500000, 3000000),
            'connection_rate': random.uniform(30, 80),
            'tcp_ratio': random.uniform(0.65, 0.75),
            'udp_ratio': random.uniform(0.20, 0.30),
            'icmp_ratio': random.uniform(0.03, 0.08)
        }
    
    def _process_network_threat(self, threat: Dict[str, Any]):
        """Process detected network threat"""
        # Add to threat indicators
        self.threat_indicators.append(threat)
        
        # Auto-block high severity threats
        if threat['severity'] in ['Critical', 'High'] and threat['confidence'] > 0.8:
            for source_ip in threat['source_ips']:
                self.block_ip(source_ip, f"Auto-blocked: {threat['description']}")
        
        # Log the threat
        print(f"Network threat detected: {threat['type']} from {threat['source_ips']}")
    
    def _update_traffic_stats(self):
        """Update traffic statistics"""
        current_time = datetime.now()
        
        # Update packet counters
        self.traffic_stats['total_packets'] += random.randint(1000, 10000)
        self.traffic_stats['total_bytes'] += random.randint(1000000, 10000000)
        
        # Update connection counters
        self.traffic_stats['total_connections'] += random.randint(10, 100)
        
        # Update protocol distribution
        self.traffic_stats['tcp_packets'] += random.randint(700, 7000)
        self.traffic_stats['udp_packets'] += random.randint(200, 2500)
        self.traffic_stats['icmp_packets'] += random.randint(50, 500)
    
    def _update_device_status(self):
        """Update network device status"""
        for device in self.network_topology['devices']:
            # Small chance of status change
            if random.random() < 0.05:  # 5% chance
                if device['status'] == 'healthy':
                    device['status'] = random.choice(['suspicious'] * 8 + ['compromised'] * 1)
                elif device['status'] == 'suspicious':
                    device['status'] = random.choice(['healthy'] * 7 + ['compromised'] * 1)
                elif device['status'] == 'compromised':
                    device['status'] = random.choice(['healthy'] * 3 + ['suspicious'] * 5)
            
            # Update last seen time
            if random.random() < 0.8:  # 80% chance device is active
                device['last_seen'] = datetime.now()
    
    def _generate_bandwidth_history(self) -> List[Dict[str, Any]]:
        """Generate bandwidth usage history for charts"""
        history = []
        current_time = datetime.now()
        
        for i in range(24):  # Last 24 hours
            timestamp = current_time - timedelta(hours=23-i)
            bandwidth = random.uniform(10.0, 90.0)  # Percentage
            
            history.append({
                'timestamp': timestamp.strftime('%H:%M'),
                'inbound_mbps': bandwidth * random.uniform(0.3, 0.7),
                'outbound_mbps': bandwidth * random.uniform(0.3, 0.7),
                'total_mbps': bandwidth
            })
        
        return history
    
    def _generate_mac_address(self) -> str:
        """Generate random MAC address"""
        return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])
    
    def get_status(self) -> Dict[str, Any]:
        """Get current network monitoring status"""
        total_devices = len(self.network_devices)
        blocked_ips = len(self.blocked_ips)
        active_threats = len([t for t in self.threat_indicators 
                            if t.get('status') == 'active'])
        
        return {
            'devices': total_devices,
            'blocked_ips': blocked_ips,
            'active_threats': active_threats,
            'monitoring_active': self.monitoring_active,
            'total_connections': len(self.active_connections)
        }
