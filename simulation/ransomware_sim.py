import os
import time
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List
import json

class RansomwareSimulator:
    """Specialized ransomware attack simulator for security testing"""
    
    def __init__(self):
        self.simulation_active = False
        self.encrypted_files = []
        self.ransom_note_locations = []
        self.registry_modifications = []
        self.network_communications = []
        
    def simulate_wannacry_behavior(self, safe_mode: bool = True, intensity: int = 5) -> Dict[str, Any]:
        """Simulate WannaCry ransomware behavior patterns"""
        
        simulation_start = datetime.now()
        results = {
            'simulation_type': 'WannaCry',
            'start_time': simulation_start,
            'safe_mode': safe_mode,
            'intensity': intensity,
            'phases_completed': [],
            'files_processed': 0,
            'registry_changes': 0,
            'network_connections': 0,
            'detection_triggers': []
        }
        
        try:
            # Phase 1: Initial Reconnaissance
            recon_results = self._simulate_reconnaissance_phase(safe_mode, intensity)
            results['phases_completed'].append('reconnaissance')
            results['detection_triggers'].extend(recon_results['triggers'])
            
            # Phase 2: Privilege Escalation
            privesc_results = self._simulate_privilege_escalation(safe_mode, intensity)
            results['phases_completed'].append('privilege_escalation')
            results['detection_triggers'].extend(privesc_results['triggers'])
            
            # Phase 3: File Discovery and Enumeration
            discovery_results = self._simulate_file_discovery(safe_mode, intensity)
            results['phases_completed'].append('file_discovery')
            results['files_processed'] = discovery_results['files_found']
            results['detection_triggers'].extend(discovery_results['triggers'])
            
            # Phase 4: Encryption Simulation
            encryption_results = self._simulate_file_encryption(safe_mode, intensity)
            results['phases_completed'].append('encryption')
            results['files_processed'] += encryption_results['files_encrypted']
            results['detection_triggers'].extend(encryption_results['triggers'])
            
            # Phase 5: Registry Modifications
            registry_results = self._simulate_registry_modifications(safe_mode, intensity)
            results['phases_completed'].append('registry_modification')
            results['registry_changes'] = registry_results['changes_made']
            results['detection_triggers'].extend(registry_results['triggers'])
            
            # Phase 6: Network Propagation
            network_results = self._simulate_network_propagation(safe_mode, intensity)
            results['phases_completed'].append('network_propagation')
            results['network_connections'] = network_results['connections_made']
            results['detection_triggers'].extend(network_results['triggers'])
            
            # Phase 7: Ransom Note Deployment
            ransom_results = self._simulate_ransom_note_deployment(safe_mode, intensity)
            results['phases_completed'].append('ransom_deployment')
            results['detection_triggers'].extend(ransom_results['triggers'])
            
            results['simulation_success'] = True
            results['completion_time'] = datetime.now()
            results['total_duration'] = (results['completion_time'] - simulation_start).total_seconds()
            
        except Exception as e:
            results['simulation_success'] = False
            results['error'] = str(e)
            results['completion_time'] = datetime.now()
        
        return results
    
    def simulate_locky_behavior(self, safe_mode: bool = True, intensity: int = 5) -> Dict[str, Any]:
        """Simulate Locky ransomware behavior patterns"""
        
        simulation_start = datetime.now()
        results = {
            'simulation_type': 'Locky',
            'start_time': simulation_start,
            'safe_mode': safe_mode,
            'intensity': intensity,
            'phases_completed': [],
            'files_processed': 0,
            'detection_triggers': []
        }
        
        try:
            # Locky-specific behavior simulation
            
            # Phase 1: Email-based Initial Infection
            email_results = self._simulate_email_infection_vector(safe_mode, intensity)
            results['phases_completed'].append('email_infection')
            results['detection_triggers'].extend(email_results['triggers'])
            
            # Phase 2: JavaScript/Macro Execution
            script_results = self._simulate_script_execution(safe_mode, intensity)
            results['phases_completed'].append('script_execution')
            results['detection_triggers'].extend(script_results['triggers'])
            
            # Phase 3: Payload Download and Execution
            payload_results = self._simulate_payload_download(safe_mode, intensity)
            results['phases_completed'].append('payload_execution')
            results['detection_triggers'].extend(payload_results['triggers'])
            
            # Phase 4: File Encryption with .locky Extension
            encryption_results = self._simulate_locky_encryption(safe_mode, intensity)
            results['phases_completed'].append('locky_encryption')
            results['files_processed'] = encryption_results['files_encrypted']
            results['detection_triggers'].extend(encryption_results['triggers'])
            
            # Phase 5: Desktop Wallpaper Change
            wallpaper_results = self._simulate_wallpaper_change(safe_mode)
            results['phases_completed'].append('wallpaper_change')
            results['detection_triggers'].extend(wallpaper_results['triggers'])
            
            results['simulation_success'] = True
            results['completion_time'] = datetime.now()
            results['total_duration'] = (results['completion_time'] - simulation_start).total_seconds()
            
        except Exception as e:
            results['simulation_success'] = False
            results['error'] = str(e)
            results['completion_time'] = datetime.now()
        
        return results
    
    def simulate_petya_behavior(self, safe_mode: bool = True, intensity: int = 5) -> Dict[str, Any]:
        """Simulate Petya/NotPetya ransomware behavior patterns"""
        
        simulation_start = datetime.now()
        results = {
            'simulation_type': 'Petya/NotPetya',
            'start_time': simulation_start,
            'safe_mode': safe_mode,
            'intensity': intensity,
            'phases_completed': [],
            'mbr_modifications': 0,
            'lateral_movement_attempts': 0,
            'detection_triggers': []
        }
        
        try:
            # Petya-specific behavior simulation
            
            # Phase 1: Credential Harvesting
            cred_results = self._simulate_credential_harvesting(safe_mode, intensity)
            results['phases_completed'].append('credential_harvesting')
            results['detection_triggers'].extend(cred_results['triggers'])
            
            # Phase 2: SMB Exploit (EternalBlue)
            smb_results = self._simulate_smb_exploit(safe_mode, intensity)
            results['phases_completed'].append('smb_exploit')
            results['lateral_movement_attempts'] = smb_results['exploitation_attempts']
            results['detection_triggers'].extend(smb_results['triggers'])
            
            # Phase 3: Master Boot Record (MBR) Modification
            mbr_results = self._simulate_mbr_modification(safe_mode, intensity)
            results['phases_completed'].append('mbr_modification')
            results['mbr_modifications'] = mbr_results['modifications_made']
            results['detection_triggers'].extend(mbr_results['triggers'])
            
            # Phase 4: File System Encryption
            encryption_results = self._simulate_filesystem_encryption(safe_mode, intensity)
            results['phases_completed'].append('filesystem_encryption')
            results['detection_triggers'].extend(encryption_results['triggers'])
            
            # Phase 5: System Reboot Trigger
            reboot_results = self._simulate_reboot_trigger(safe_mode)
            results['phases_completed'].append('reboot_trigger')
            results['detection_triggers'].extend(reboot_results['triggers'])
            
            results['simulation_success'] = True
            results['completion_time'] = datetime.now()
            results['total_duration'] = (results['completion_time'] - simulation_start).total_seconds()
            
        except Exception as e:
            results['simulation_success'] = False
            results['error'] = str(e)
            results['completion_time'] = datetime.now()
        
        return results
    
    def _simulate_reconnaissance_phase(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate reconnaissance phase of ransomware"""
        triggers = []
        
        # System information gathering
        if not safe_mode:
            # In real mode, would actually gather system info
            time.sleep(0.1)
        
        triggers.append({
            'type': 'System Information Query',
            'description': 'Ransomware querying system information',
            'indicators': ['WMI queries', 'System enumeration', 'OS version check'],
            'timestamp': datetime.now(),
            'severity': 'Medium'
        })
        
        # Network discovery
        triggers.append({
            'type': 'Network Discovery',
            'description': 'Scanning for network shares and connected systems',
            'indicators': ['NetBIOS enumeration', 'SMB share discovery', 'Network scanning'],
            'timestamp': datetime.now(),
            'severity': 'High'
        })
        
        # Process enumeration
        triggers.append({
            'type': 'Process Enumeration',
            'description': 'Enumerating running processes for security software',
            'indicators': ['Process list queries', 'Service enumeration', 'Security software detection'],
            'timestamp': datetime.now(),
            'severity': 'Medium'
        })
        
        return {
            'phase': 'reconnaissance',
            'duration': random.uniform(5, 15) * intensity,
            'triggers': triggers
        }
    
    def _simulate_privilege_escalation(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate privilege escalation attempts"""
        triggers = []
        
        # UAC bypass attempt
        triggers.append({
            'type': 'UAC Bypass Attempt',
            'description': 'Attempting to bypass User Account Control',
            'indicators': ['Registry manipulation', 'Process elevation', 'Token manipulation'],
            'timestamp': datetime.now(),
            'severity': 'High'
        })
        
        # Exploit vulnerability
        if intensity > 5:
            triggers.append({
                'type': 'Local Privilege Escalation',
                'description': 'Exploiting local vulnerability for privilege escalation',
                'indicators': ['Kernel exploit', 'DLL hijacking', 'Service exploitation'],
                'timestamp': datetime.now(),
                'severity': 'Critical'
            })
        
        return {
            'phase': 'privilege_escalation',
            'duration': random.uniform(10, 30) * intensity,
            'triggers': triggers
        }
    
    def _simulate_file_discovery(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate file system discovery and enumeration"""
        triggers = []
        
        # File system traversal
        file_types_targeted = ['.doc', '.docx', '.pdf', '.jpg', '.png', '.xlsx', '.ppt', '.zip', '.rar']
        files_found = intensity * random.randint(100, 500)
        
        triggers.append({
            'type': 'Recursive File Enumeration',
            'description': f'Scanning file system for {len(file_types_targeted)} file types',
            'indicators': ['High file system I/O', 'Directory traversal', 'File type filtering'],
            'timestamp': datetime.now(),
            'severity': 'High',
            'file_count': files_found
        })
        
        # Shadow copy enumeration
        if intensity > 3:
            triggers.append({
                'type': 'Shadow Copy Enumeration',
                'description': 'Enumerating Volume Shadow Copies for deletion',
                'indicators': ['vssadmin queries', 'WMI shadow copy queries', 'Backup enumeration'],
                'timestamp': datetime.now(),
                'severity': 'Critical'
            })
        
        return {
            'phase': 'file_discovery',
            'files_found': files_found,
            'duration': random.uniform(30, 120) * intensity,
            'triggers': triggers
        }
    
    def _simulate_file_encryption(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate file encryption process"""
        triggers = []
        
        # Mass file encryption
        files_encrypted = intensity * random.randint(50, 200)
        encryption_extensions = ['.wncry', '.encrypted', '.locked', '.crypto']
        
        triggers.append({
            'type': 'Mass File Encryption',
            'description': f'Encrypting {files_encrypted} files with ransomware',
            'indicators': [
                'High CPU usage from encryption',
                'Rapid file modifications',
                f'Files renamed with {random.choice(encryption_extensions)} extension',
                'Cryptographic API calls'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical',
            'files_affected': files_encrypted
        })
        
        # Delete shadow copies
        if intensity > 4:
            triggers.append({
                'type': 'Shadow Copy Deletion',
                'description': 'Deleting Volume Shadow Copies to prevent recovery',
                'indicators': ['vssadmin delete shadows', 'WMI shadow copy deletion', 'Backup destruction'],
                'timestamp': datetime.now(),
                'severity': 'Critical'
            })
        
        # Original file deletion
        triggers.append({
            'type': 'Original File Deletion',
            'description': 'Securely deleting original unencrypted files',
            'indicators': ['File deletion patterns', 'Secure erase operations', 'Free space overwriting'],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        return {
            'phase': 'file_encryption',
            'files_encrypted': files_encrypted,
            'duration': random.uniform(60, 300) * intensity,
            'triggers': triggers
        }
    
    def _simulate_registry_modifications(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate registry modifications typical of ransomware"""
        triggers = []
        changes_made = 0
        
        # Startup persistence
        changes_made += 1
        triggers.append({
            'type': 'Registry Startup Modification',
            'description': 'Adding ransomware to startup registry keys',
            'indicators': [
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'Startup program registration'
            ],
            'timestamp': datetime.now(),
            'severity': 'High'
        })
        
        # Security settings modification
        if intensity > 3:
            changes_made += 2
            triggers.append({
                'type': 'Security Settings Modification',
                'description': 'Disabling security features via registry',
                'indicators': [
                    'Windows Defender settings modification',
                    'System Restore settings change',
                    'UAC settings modification'
                ],
                'timestamp': datetime.now(),
                'severity': 'Critical'
            })
        
        # Wallpaper change
        changes_made += 1
        triggers.append({
            'type': 'Desktop Wallpaper Change',
            'description': 'Changing desktop wallpaper to ransom message',
            'indicators': [
                'HKEY_CURRENT_USER\\Control Panel\\Desktop\\Wallpaper',
                'Desktop background modification',
                'System appearance changes'
            ],
            'timestamp': datetime.now(),
            'severity': 'Medium'
        })
        
        return {
            'phase': 'registry_modification',
            'changes_made': changes_made,
            'duration': random.uniform(5, 20),
            'triggers': triggers
        }
    
    def _simulate_network_propagation(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate network propagation attempts"""
        triggers = []
        connections_made = intensity * random.randint(5, 20)
        
        # SMB share enumeration and infection
        triggers.append({
            'type': 'SMB Share Propagation',
            'description': 'Attempting to spread via SMB shares',
            'indicators': [
                'SMB connection attempts',
                'Network share enumeration',
                'Remote file copying',
                f'{connections_made} network connections'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        # Exploit-based propagation (EternalBlue simulation)
        if intensity > 6:
            triggers.append({
                'type': 'EternalBlue Exploit Propagation',
                'description': 'Using EternalBlue exploit for network propagation',
                'indicators': [
                    'SMB vulnerability exploitation',
                    'MS17-010 exploit patterns',
                    'Remote code execution attempts'
                ],
                'timestamp': datetime.now(),
                'severity': 'Critical'
            })
        
        return {
            'phase': 'network_propagation',
            'connections_made': connections_made,
            'duration': random.uniform(30, 120) * intensity,
            'triggers': triggers
        }
    
    def _simulate_ransom_note_deployment(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate ransom note deployment"""
        triggers = []
        
        # Create ransom notes
        note_locations = [
            'Desktop',
            'Documents folder',
            'Each encrypted folder',
            'System root directory'
        ]
        
        triggers.append({
            'type': 'Ransom Note Creation',
            'description': f'Creating ransom notes in {len(note_locations)} locations',
            'indicators': [
                'README_DECRYPT.txt creation',
                'Multiple ransom note files',
                'Ransom message display',
                'Payment instruction files'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        # Display ransom message
        if intensity > 2:
            triggers.append({
                'type': 'Ransom Message Display',
                'description': 'Displaying full-screen ransom message',
                'indicators': [
                    'Full-screen application launch',
                    'Window manipulation',
                    'User interface takeover'
                ],
                'timestamp': datetime.now(),
                'severity': 'High'
            })
        
        return {
            'phase': 'ransom_deployment',
            'notes_created': len(note_locations),
            'duration': random.uniform(5, 15),
            'triggers': triggers
        }
    
    def _simulate_email_infection_vector(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate email-based infection vector (Locky specific)"""
        triggers = []
        
        triggers.append({
            'type': 'Malicious Email Attachment',
            'description': 'Email attachment with malicious macro/JavaScript',
            'indicators': [
                'Microsoft Office macro execution',
                'JavaScript execution from email',
                'Suspicious email attachment behavior'
            ],
            'timestamp': datetime.now(),
            'severity': 'High'
        })
        
        return {
            'phase': 'email_infection',
            'duration': random.uniform(1, 5),
            'triggers': triggers
        }
    
    def _simulate_script_execution(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate malicious script execution"""
        triggers = []
        
        triggers.append({
            'type': 'Malicious Script Execution',
            'description': 'Executing obfuscated JavaScript/VBA macro',
            'indicators': [
                'PowerShell execution with encoded commands',
                'VBA macro with obfuscated code',
                'JavaScript execution from Office document'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        return {
            'phase': 'script_execution',
            'duration': random.uniform(5, 15),
            'triggers': triggers
        }
    
    def _simulate_payload_download(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate payload download and execution"""
        triggers = []
        
        triggers.append({
            'type': 'Malicious Payload Download',
            'description': 'Downloading ransomware payload from C2 server',
            'indicators': [
                'HTTP/HTTPS connections to suspicious domains',
                'Executable download to temp directory',
                'Payload execution from temporary location'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        return {
            'phase': 'payload_download',
            'duration': random.uniform(10, 30),
            'triggers': triggers
        }
    
    def _simulate_locky_encryption(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate Locky-specific encryption behavior"""
        triggers = []
        files_encrypted = intensity * random.randint(100, 400)
        
        triggers.append({
            'type': 'Locky File Encryption',
            'description': f'Encrypting {files_encrypted} files with .locky extension',
            'indicators': [
                'Mass file renaming to .locky extension',
                'AES encryption of user files',
                'File content modification patterns'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical',
            'files_affected': files_encrypted
        })
        
        return {
            'phase': 'locky_encryption',
            'files_encrypted': files_encrypted,
            'duration': random.uniform(60, 240) * intensity,
            'triggers': triggers
        }
    
    def _simulate_wallpaper_change(self, safe_mode: bool) -> Dict[str, Any]:
        """Simulate desktop wallpaper change"""
        triggers = []
        
        triggers.append({
            'type': 'Desktop Wallpaper Modification',
            'description': 'Changing desktop wallpaper to ransom message',
            'indicators': [
                'SystemParametersInfo API call',
                'Desktop wallpaper registry modification',
                'Visual system changes'
            ],
            'timestamp': datetime.now(),
            'severity': 'Medium'
        })
        
        return {
            'phase': 'wallpaper_change',
            'duration': random.uniform(1, 3),
            'triggers': triggers
        }
    
    def _simulate_credential_harvesting(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate credential harvesting (Petya specific)"""
        triggers = []
        
        triggers.append({
            'type': 'Credential Harvesting',
            'description': 'Extracting credentials for lateral movement',
            'indicators': [
                'LSASS memory access',
                'SAM database access',
                'Credential dumping tools execution'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        return {
            'phase': 'credential_harvesting',
            'duration': random.uniform(15, 45),
            'triggers': triggers
        }
    
    def _simulate_smb_exploit(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate SMB exploit (EternalBlue)"""
        triggers = []
        exploitation_attempts = intensity * random.randint(3, 15)
        
        triggers.append({
            'type': 'EternalBlue SMB Exploit',
            'description': f'Attempting EternalBlue exploitation on {exploitation_attempts} targets',
            'indicators': [
                'SMB vulnerability scanning',
                'MS17-010 exploit payload delivery',
                'Remote code execution via SMB'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        return {
            'phase': 'smb_exploit',
            'exploitation_attempts': exploitation_attempts,
            'duration': random.uniform(30, 90) * intensity,
            'triggers': triggers
        }
    
    def _simulate_mbr_modification(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate Master Boot Record modification"""
        triggers = []
        modifications_made = 1
        
        triggers.append({
            'type': 'Master Boot Record Modification',
            'description': 'Overwriting MBR with ransomware bootloader',
            'indicators': [
                'Raw disk access',
                'MBR sector modification',
                'Boot process hijacking'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        return {
            'phase': 'mbr_modification',
            'modifications_made': modifications_made,
            'duration': random.uniform(5, 15),
            'triggers': triggers
        }
    
    def _simulate_filesystem_encryption(self, safe_mode: bool, intensity: int) -> Dict[str, Any]:
        """Simulate file system level encryption"""
        triggers = []
        
        triggers.append({
            'type': 'File System Encryption',
            'description': 'Encrypting entire file system structures',
            'indicators': [
                'MFT (Master File Table) encryption',
                'File system metadata modification',
                'Disk-level encryption operations'
            ],
            'timestamp': datetime.now(),
            'severity': 'Critical'
        })
        
        return {
            'phase': 'filesystem_encryption',
            'duration': random.uniform(120, 600) * intensity,
            'triggers': triggers
        }
    
    def _simulate_reboot_trigger(self, safe_mode: bool) -> Dict[str, Any]:
        """Simulate system reboot trigger"""
        triggers = []
        
        triggers.append({
            'type': 'Forced System Reboot',
            'description': 'Triggering system reboot to activate boot-level encryption',
            'indicators': [
                'System shutdown/reboot command',
                'Forced system restart',
                'Boot process modification'
            ],
            'timestamp': datetime.now(),
            'severity': 'High'
        })
        
        return {
            'phase': 'reboot_trigger',
            'duration': random.uniform(1, 5),
            'triggers': triggers
        }
