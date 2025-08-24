import os
import requests
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import random
from collections import defaultdict
import uuid

class ThreatIntelligence:
    """Threat intelligence integration and management system"""
    
    def __init__(self):
        self.api_keys = self._load_api_keys()
        self.threat_feeds = {}
        self.ioc_database = defaultdict(list)
        self.threat_actors = {}
        self.campaign_tracking = {}
        self.reputation_cache = {}
        self.cache_expiry = {}
        self.feed_sources = self._initialize_feed_sources()
        self.threat_categories = self._initialize_threat_categories()
        self._initialize_sample_data()
        
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment variables"""
        return {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', 'demo_vt_key'),
            'shodan': os.getenv('SHODAN_API_KEY', 'demo_shodan_key'),
            'xforce': os.getenv('XFORCE_API_KEY', 'demo_xforce_key'),
            'otx': os.getenv('OTX_API_KEY', 'demo_otx_key'),
            'threatcrowd': os.getenv('THREATCROWD_API_KEY', 'demo_tc_key'),
            'hybrid_analysis': os.getenv('HYBRID_ANALYSIS_API_KEY', 'demo_ha_key'),
            'urlvoid': os.getenv('URLVOID_API_KEY', 'demo_urlvoid_key'),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', 'demo_abuseipdb_key')
        }
    
    def _initialize_feed_sources(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat intelligence feed sources"""
        return {
            'VirusTotal': {
                'type': 'commercial',
                'categories': ['malware', 'urls', 'domains', 'ips'],
                'api_endpoint': 'https://www.virustotal.com/vtapi/v2/',
                'rate_limit': 4,  # requests per minute
                'enabled': True,
                'last_updated': None,
                'confidence': 0.95
            },
            'Shodan': {
                'type': 'commercial',
                'categories': ['network', 'vulnerabilities', 'infrastructure'],
                'api_endpoint': 'https://api.shodan.io/',
                'rate_limit': 1,
                'enabled': False,
                'last_updated': None,
                'confidence': 0.85
            },
            'IBM X-Force': {
                'type': 'commercial',
                'categories': ['threats', 'vulnerabilities', 'malware'],
                'api_endpoint': 'https://api.xforce.ibmcloud.com/',
                'rate_limit': 5000,  # per month
                'enabled': False,
                'last_updated': None,
                'confidence': 0.90
            },
            'OTX AlienVault': {
                'type': 'community',
                'categories': ['iocs', 'pulses', 'malware'],
                'api_endpoint': 'https://otx.alienvault.com/api/v1/',
                'rate_limit': 10000,  # per hour
                'enabled': True,
                'last_updated': None,
                'confidence': 0.80
            },
            'Malware Bazaar': {
                'type': 'free',
                'categories': ['malware_samples', 'signatures'],
                'api_endpoint': 'https://mb-api.abuse.ch/api/v1/',
                'rate_limit': 1000,  # per day
                'enabled': True,
                'last_updated': None,
                'confidence': 0.88
            },
            'ThreatCrowd': {
                'type': 'free',
                'categories': ['domains', 'ips', 'emails'],
                'api_endpoint': 'https://www.threatcrowd.org/searchApi/v2/',
                'rate_limit': 1,  # per second
                'enabled': True,
                'last_updated': None,
                'confidence': 0.75
            },
            'URLVoid': {
                'type': 'freemium',
                'categories': ['urls', 'domains'],
                'api_endpoint': 'https://api.urlvoid.com/1000/',
                'rate_limit': 200,  # per day (free)
                'enabled': True,
                'last_updated': None,
                'confidence': 0.82
            },
            'AbuseIPDB': {
                'type': 'freemium',
                'categories': ['ips', 'abuse'],
                'api_endpoint': 'https://api.abuseipdb.com/api/v2/',
                'rate_limit': 1000,  # per day (free)
                'enabled': True,
                'last_updated': None,
                'confidence': 0.87
            }
        }
    
    def _initialize_threat_categories(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat categories and classifications"""
        return {
            'malware': {
                'types': ['trojan', 'ransomware', 'spyware', 'adware', 'rootkit', 'worm', 'virus'],
                'severity_mapping': {'trojan': 'high', 'ransomware': 'critical', 'spyware': 'high'},
                'indicators': ['file_hash', 'registry_key', 'mutex', 'network_callback']
            },
            'network': {
                'types': ['c2_server', 'malicious_domain', 'phishing_url', 'exploit_kit'],
                'severity_mapping': {'c2_server': 'critical', 'phishing_url': 'high'},
                'indicators': ['ip_address', 'domain', 'url', 'ssl_certificate']
            },
            'vulnerabilities': {
                'types': ['cve', 'zero_day', 'configuration_issue', 'weak_credential'],
                'severity_mapping': {'zero_day': 'critical', 'cve': 'variable'},
                'indicators': ['cve_id', 'affected_software', 'exploit_code']
            },
            'actors': {
                'types': ['apt_group', 'cybercriminal', 'hacktivist', 'insider_threat'],
                'severity_mapping': {'apt_group': 'critical', 'cybercriminal': 'high'},
                'indicators': ['ttps', 'infrastructure', 'tools', 'targets']
            }
        }
    
    def _initialize_sample_data(self):
        """Initialize with sample threat intelligence data"""
        # Sample IOCs
        sample_iocs = [
            {
                'type': 'ip',
                'value': '198.51.100.42',
                'threat_type': 'c2_server',
                'confidence': 0.95,
                'first_seen': datetime.now() - timedelta(days=5),
                'last_seen': datetime.now() - timedelta(hours=2),
                'source': 'VirusTotal',
                'tags': ['apt', 'malware', 'backdoor'],
                'description': 'Command and control server for advanced persistent threat'
            },
            {
                'type': 'domain',
                'value': 'malicious-example.com',
                'threat_type': 'phishing',
                'confidence': 0.88,
                'first_seen': datetime.now() - timedelta(days=3),
                'last_seen': datetime.now() - timedelta(hours=6),
                'source': 'OTX AlienVault',
                'tags': ['phishing', 'credential_theft'],
                'description': 'Domain hosting phishing pages targeting banking credentials'
            },
            {
                'type': 'hash',
                'value': 'a1b2c3d4e5f6789012345678901234567890abcdef',
                'threat_type': 'ransomware',
                'confidence': 0.97,
                'first_seen': datetime.now() - timedelta(days=1),
                'last_seen': datetime.now() - timedelta(minutes=30),
                'source': 'Malware Bazaar',
                'tags': ['ransomware', 'encryption', 'wannacry'],
                'description': 'WannaCry ransomware variant with improved evasion techniques'
            }
        ]
        
        for ioc in sample_iocs:
            self.ioc_database[ioc['type']].append(ioc)
        
        # Sample threat actors
        self.threat_actors = {
            'APT28': {
                'aliases': ['Fancy Bear', 'Sofacy', 'Pawn Storm'],
                'origin': 'Russia',
                'active_since': '2007',
                'targets': ['government', 'military', 'aerospace'],
                'ttps': ['spear_phishing', 'zero_day_exploits', 'credential_theft'],
                'tools': ['X-Agent', 'Sofacy', 'Chopstick'],
                'recent_activity': datetime.now() - timedelta(days=7),
                'threat_level': 'critical'
            },
            'Lazarus Group': {
                'aliases': ['Hidden Cobra', 'Guardians of Peace'],
                'origin': 'North Korea',
                'active_since': '2009',
                'targets': ['financial', 'cryptocurrency', 'entertainment'],
                'ttps': ['destructive_attacks', 'financial_theft', 'espionage'],
                'tools': ['WannaCry', 'PowerRatankba', 'Brambul'],
                'recent_activity': datetime.now() - timedelta(days=12),
                'threat_level': 'critical'
            }
        }
    
    def get_global_threats(self) -> List[Dict[str, Any]]:
        """Get current global threat landscape"""
        current_threats = [
            {
                'name': 'Advanced Ransomware Campaign',
                'severity': 'Critical',
                'first_seen': datetime.now() - timedelta(days=2),
                'affected_systems': ['Windows', 'Linux'],
                'description': 'New ransomware variant targeting enterprise networks with double extortion tactics',
                'attribution': 'Unknown',
                'iocs': ['multiple file hashes', 'C2 domains', 'registry modifications'],
                'mitigation': 'Update endpoint protection, backup verification, network segmentation'
            },
            {
                'name': 'Supply Chain Compromise',
                'severity': 'High',
                'first_seen': datetime.now() - timedelta(days=5),
                'affected_systems': ['Software Distribution', 'Package Managers'],
                'description': 'Malicious packages discovered in popular software repositories',
                'attribution': 'APT Group',
                'iocs': ['package signatures', 'domain registrations'],
                'mitigation': 'Verify package integrity, restrict software installation sources'
            },
            {
                'name': 'Cloud Infrastructure Attacks',
                'severity': 'High',
                'first_seen': datetime.now() - timedelta(days=3),
                'affected_systems': ['AWS', 'Azure', 'GCP'],
                'description': 'Targeted attacks against misconfigured cloud services and storage buckets',
                'attribution': 'Multiple Groups',
                'iocs': ['IP ranges', 'user agents', 'access patterns'],
                'mitigation': 'Review cloud configurations, enable logging, implement IAM best practices'
            },
            {
                'name': 'Mobile Banking Trojans',
                'severity': 'Medium',
                'first_seen': datetime.now() - timedelta(days=7),
                'affected_systems': ['Android', 'iOS'],
                'description': 'Banking trojans targeting mobile applications with overlay attacks',
                'attribution': 'Cybercriminal Groups',
                'iocs': ['app signatures', 'C2 communications'],
                'mitigation': 'Mobile device management, app store verification, user education'
            },
            {
                'name': 'IoT Botnet Expansion',
                'severity': 'Medium',
                'first_seen': datetime.now() - timedelta(days=10),
                'affected_systems': ['IoT Devices', 'Smart Home'],
                'description': 'Botnet targeting IoT devices with default credentials for DDoS attacks',
                'attribution': 'Mirai Successor',
                'iocs': ['default credentials', 'scanning patterns', 'C2 infrastructure'],
                'mitigation': 'Change default passwords, network segmentation, firmware updates'
            }
        ]
        
        return current_threats
    
    def get_latest_iocs(self) -> List[Dict[str, Any]]:
        """Get latest indicators of compromise"""
        all_iocs = []
        
        # Collect IOCs from all categories
        for ioc_type, iocs in self.ioc_database.items():
            for ioc in iocs:
                ioc_entry = {
                    'type': ioc_type,
                    'value': ioc['value'],
                    'threat_type': ioc['threat_type'],
                    'confidence': ioc['confidence'],
                    'source': ioc['source'],
                    'first_seen': ioc['first_seen'].strftime('%Y-%m-%d %H:%M'),
                    'tags': ', '.join(ioc['tags']),
                    'description': ioc['description']
                }
                all_iocs.append(ioc_entry)
        
        # Sort by first_seen date (most recent first)
        all_iocs.sort(key=lambda x: x['first_seen'], reverse=True)
        
        return all_iocs[:50]  # Return top 50 most recent
    
    def lookup_indicator(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Look up indicator in threat intelligence sources"""
        lookup_result = {
            'indicator': indicator,
            'type': indicator_type,
            'found': False,
            'sources': [],
            'threat_score': 0,
            'confidence': 0.0,
            'first_seen': None,
            'last_seen': None,
            'threat_types': [],
            'descriptions': [],
            'related_indicators': []
        }
        
        # Check local IOC database first
        local_results = self._check_local_iocs(indicator, indicator_type)
        if local_results:
            lookup_result.update(local_results)
            lookup_result['found'] = True
        
        # Query external sources (simulate API calls)
        external_results = self._query_external_sources(indicator, indicator_type)
        if external_results:
            lookup_result = self._merge_lookup_results(lookup_result, external_results)
        
        return lookup_result
    
    def check_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check reputation of indicator across multiple sources"""
        cache_key = f"{indicator_type}:{indicator}"
        
        # Check cache first
        if self._is_cache_valid(cache_key):
            return self.reputation_cache[cache_key]
        
        reputation_result = {
            'indicator': indicator,
            'type': indicator_type,
            'reputation_score': 0,  # 0-100, higher is more malicious
            'verdict': 'unknown',
            'source_results': {},
            'risk_factors': [],
            'recommendations': []
        }
        
        # Simulate checking multiple reputation sources
        sources = ['VirusTotal', 'IBM X-Force', 'ThreatCrowd', 'URLVoid', 'AbuseIPDB']
        malicious_votes = 0
        total_votes = 0
        
        for source in sources:
            if not self.feed_sources.get(source, {}).get('enabled', False):
                continue
            
            # Simulate API call results
            result = self._simulate_reputation_check(indicator, indicator_type, source)
            reputation_result['source_results'][source] = result
            
            if result['responded']:
                total_votes += 1
                if result['malicious']:
                    malicious_votes += 1
        
        # Calculate overall reputation score
        if total_votes > 0:
            reputation_result['reputation_score'] = int((malicious_votes / total_votes) * 100)
        
        # Determine verdict
        if reputation_result['reputation_score'] >= 70:
            reputation_result['verdict'] = 'malicious'
        elif reputation_result['reputation_score'] >= 30:
            reputation_result['verdict'] = 'suspicious'
        elif reputation_result['reputation_score'] > 0:
            reputation_result['verdict'] = 'potentially_malicious'
        else:
            reputation_result['verdict'] = 'clean'
        
        # Generate risk factors and recommendations
        reputation_result['risk_factors'] = self._generate_risk_factors(reputation_result)
        reputation_result['recommendations'] = self._generate_recommendations(reputation_result)
        
        # Cache results
        self.reputation_cache[cache_key] = reputation_result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=6)
        
        return reputation_result
    
    def test_integration(self, source_name: str) -> bool:
        """Test integration with threat intelligence source"""
        if source_name not in self.feed_sources:
            return False
        
        source_config = self.feed_sources[source_name]
        
        # Simulate API connectivity test
        try:
            # In a real implementation, this would make an actual API call
            time.sleep(0.5)  # Simulate network delay
            
            # Simulate success/failure based on configuration
            if source_config.get('enabled', False):
                success_rate = 0.9  # 90% success rate
            else:
                success_rate = 0.3  # 30% success rate for disabled sources
            
            return random.random() < success_rate
            
        except Exception as e:
            print(f"Integration test failed for {source_name}: {e}")
            return False
    
    def update_threat_feeds(self) -> Dict[str, Any]:
        """Update threat intelligence feeds from all sources"""
        update_results = {
            'started_at': datetime.now(),
            'sources_updated': [],
            'sources_failed': [],
            'new_indicators': 0,
            'updated_indicators': 0,
            'errors': []
        }
        
        for source_name, source_config in self.feed_sources.items():
            if not source_config.get('enabled', False):
                continue
            
            try:
                # Simulate feed update
                result = self._update_source_feed(source_name, source_config)
                
                if result['success']:
                    update_results['sources_updated'].append(source_name)
                    update_results['new_indicators'] += result.get('new_indicators', 0)
                    update_results['updated_indicators'] += result.get('updated_indicators', 0)
                    
                    # Update last updated timestamp
                    source_config['last_updated'] = datetime.now()
                else:
                    update_results['sources_failed'].append(source_name)
                    update_results['errors'].append(f"{source_name}: {result.get('error', 'Unknown error')}")
                
            except Exception as e:
                update_results['sources_failed'].append(source_name)
                update_results['errors'].append(f"{source_name}: {str(e)}")
        
        update_results['completed_at'] = datetime.now()
        update_results['duration'] = (update_results['completed_at'] - update_results['started_at']).total_seconds()
        
        return update_results
    
    def get_threat_actor_profile(self, actor_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed threat actor profile"""
        actor = self.threat_actors.get(actor_name)
        
        if not actor:
            return None
        
        # Enhance with recent activity and campaigns
        enhanced_profile = actor.copy()
        enhanced_profile.update({
            'campaigns': self._get_actor_campaigns(actor_name),
            'infrastructure': self._get_actor_infrastructure(actor_name),
            'victims': self._get_actor_victims(actor_name),
            'evolution': self._get_actor_evolution(actor_name)
        })
        
        return enhanced_profile
    
    def search_threat_intelligence(self, query: str, search_type: str = 'all') -> List[Dict[str, Any]]:
        """Search across threat intelligence database"""
        results = []
        
        # Search IOCs
        if search_type in ['all', 'iocs']:
            for ioc_type, iocs in self.ioc_database.items():
                for ioc in iocs:
                    if (query.lower() in ioc['value'].lower() or 
                        query.lower() in ioc['description'].lower() or
                        any(query.lower() in tag.lower() for tag in ioc['tags'])):
                        
                        results.append({
                            'result_type': 'ioc',
                            'ioc_type': ioc_type,
                            'value': ioc['value'],
                            'threat_type': ioc['threat_type'],
                            'confidence': ioc['confidence'],
                            'source': ioc['source'],
                            'description': ioc['description']
                        })
        
        # Search threat actors
        if search_type in ['all', 'actors']:
            for actor_name, actor_data in self.threat_actors.items():
                if (query.lower() in actor_name.lower() or
                    any(query.lower() in alias.lower() for alias in actor_data.get('aliases', [])) or
                    any(query.lower() in target.lower() for target in actor_data.get('targets', []))):
                    
                    results.append({
                        'result_type': 'threat_actor',
                        'name': actor_name,
                        'aliases': actor_data.get('aliases', []),
                        'origin': actor_data.get('origin', 'Unknown'),
                        'threat_level': actor_data.get('threat_level', 'medium'),
                        'description': f"Threat actor active since {actor_data.get('active_since', 'unknown')}"
                    })
        
        return results
    
    def _check_local_iocs(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Check indicator against local IOC database"""
        if indicator_type not in self.ioc_database:
            return None
        
        for ioc in self.ioc_database[indicator_type]:
            if ioc['value'] == indicator:
                return {
                    'sources': [ioc['source']],
                    'threat_score': int(ioc['confidence'] * 100),
                    'confidence': ioc['confidence'],
                    'first_seen': ioc['first_seen'],
                    'last_seen': ioc['last_seen'],
                    'threat_types': [ioc['threat_type']],
                    'descriptions': [ioc['description']]
                }
        
        return None
    
    def _query_external_sources(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query external threat intelligence sources"""
        # Simulate external API queries
        # In a real implementation, this would make actual API calls
        
        external_result = {
            'sources': [],
            'threat_score': 0,
            'confidence': 0.0,
            'threat_types': [],
            'descriptions': []
        }
        
        # Simulate VirusTotal lookup
        if self.feed_sources['VirusTotal']['enabled']:
            vt_result = self._simulate_virustotal_lookup(indicator, indicator_type)
            if vt_result:
                external_result['sources'].append('VirusTotal')
                external_result['threat_score'] = max(external_result['threat_score'], vt_result['score'])
                external_result['confidence'] = max(external_result['confidence'], vt_result['confidence'])
                external_result['threat_types'].extend(vt_result['types'])
                external_result['descriptions'].extend(vt_result['descriptions'])
        
        # Simulate other source lookups
        for source_name in ['OTX AlienVault', 'Malware Bazaar', 'ThreatCrowd']:
            if self.feed_sources[source_name]['enabled'] and random.random() < 0.7:
                external_result['sources'].append(source_name)
        
        return external_result if external_result['sources'] else None
    
    def _simulate_virustotal_lookup(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Simulate VirusTotal API lookup"""
        # Simulate API response based on indicator characteristics
        if indicator_type == 'hash':
            # File hash lookup
            detection_rate = random.uniform(0.0, 0.8)
            if detection_rate > 0.1:
                return {
                    'score': int(detection_rate * 100),
                    'confidence': 0.95,
                    'types': ['malware'],
                    'descriptions': [f'Malware detected by {int(detection_rate * 70)} engines']
                }
        elif indicator_type == 'ip':
            # IP reputation lookup
            if random.random() < 0.3:  # 30% chance of malicious IP
                return {
                    'score': random.randint(60, 95),
                    'confidence': 0.85,
                    'types': ['c2_server', 'malware_distribution'],
                    'descriptions': ['IP associated with malware distribution']
                }
        elif indicator_type == 'domain':
            # Domain reputation lookup
            if random.random() < 0.25:  # 25% chance of malicious domain
                return {
                    'score': random.randint(50, 90),
                    'confidence': 0.80,
                    'types': ['phishing', 'malware_hosting'],
                    'descriptions': ['Domain hosting malicious content']
                }
        
        return None
    
    def _simulate_reputation_check(self, indicator: str, indicator_type: str, source: str) -> Dict[str, Any]:
        """Simulate reputation check for a single source"""
        result = {
            'source': source,
            'responded': random.random() < 0.9,  # 90% response rate
            'malicious': False,
            'score': 0,
            'details': {}
        }
        
        if result['responded']:
            # Simulate malicious detection based on source reliability
            source_confidence = self.feed_sources[source]['confidence']
            detection_probability = 0.1 * source_confidence  # Base 10% scaled by confidence
            
            result['malicious'] = random.random() < detection_probability
            if result['malicious']:
                result['score'] = random.randint(70, 100)
                result['details'] = {
                    'threat_types': random.sample(['malware', 'phishing', 'spam', 'botnet'], 
                                                random.randint(1, 2)),
                    'last_seen': datetime.now() - timedelta(days=random.randint(0, 30))
                }
            else:
                result['score'] = random.randint(0, 20)
        
        return result
    
    def _generate_risk_factors(self, reputation_result: Dict[str, Any]) -> List[str]:
        """Generate risk factors based on reputation results"""
        risk_factors = []
        
        if reputation_result['reputation_score'] >= 70:
            risk_factors.append('High malicious consensus across multiple sources')
        elif reputation_result['reputation_score'] >= 30:
            risk_factors.append('Moderate suspicion from reputation sources')
        
        # Check source-specific factors
        for source, result in reputation_result['source_results'].items():
            if result.get('malicious', False):
                risk_factors.append(f'Flagged as malicious by {source}')
        
        if not risk_factors:
            risk_factors.append('No significant risk factors identified')
        
        return risk_factors
    
    def _generate_recommendations(self, reputation_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on reputation results"""
        recommendations = []
        
        if reputation_result['reputation_score'] >= 70:
            recommendations.extend([
                'Block indicator immediately',
                'Investigate any related activity',
                'Add to threat intelligence feeds'
            ])
        elif reputation_result['reputation_score'] >= 30:
            recommendations.extend([
                'Monitor indicator closely',
                'Consider temporary blocking',
                'Increase logging for related activity'
            ])
        else:
            recommendations.append('Continue normal monitoring')
        
        return recommendations
    
    def _update_source_feed(self, source_name: str, source_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update threat intelligence from a specific source"""
        # Simulate feed update process
        time.sleep(random.uniform(0.5, 2.0))  # Simulate API call time
        
        success = random.random() < 0.85  # 85% success rate
        
        if success:
            new_indicators = random.randint(5, 50)
            updated_indicators = random.randint(0, 20)
            
            # Simulate adding new IOCs to database
            for _ in range(random.randint(1, 5)):
                ioc_type = random.choice(['ip', 'domain', 'hash', 'url'])
                ioc_value = self._generate_sample_ioc_value(ioc_type)
                
                new_ioc = {
                    'type': ioc_type,
                    'value': ioc_value,
                    'threat_type': random.choice(['malware', 'phishing', 'c2_server', 'botnet']),
                    'confidence': random.uniform(0.7, 0.95),
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'source': source_name,
                    'tags': random.sample(['apt', 'malware', 'phishing', 'botnet', 'trojan'], 
                                        random.randint(1, 3)),
                    'description': f'Threat indicator from {source_name} feed'
                }
                
                self.ioc_database[ioc_type].append(new_ioc)
            
            return {
                'success': True,
                'new_indicators': new_indicators,
                'updated_indicators': updated_indicators
            }
        else:
            return {
                'success': False,
                'error': random.choice([
                    'API rate limit exceeded',
                    'Authentication failed',
                    'Network timeout',
                    'Service temporarily unavailable'
                ])
            }
    
    def _generate_sample_ioc_value(self, ioc_type: str) -> str:
        """Generate sample IOC value for testing"""
        if ioc_type == 'ip':
            return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        elif ioc_type == 'domain':
            domains = ['malicious-site.com', 'phishing-bank.net', 'c2-server.org', 'botnet-controller.biz']
            return random.choice(domains)
        elif ioc_type == 'hash':
            return hashlib.sha256(f"sample_malware_{random.randint(1000, 9999)}".encode()).hexdigest()
        elif ioc_type == 'url':
            return f"http://malicious-site.com/path/{random.randint(100, 999)}"
        else:
            return f"sample_{ioc_type}_{random.randint(1000, 9999)}"
    
    def _merge_lookup_results(self, local_result: Dict[str, Any], external_result: Dict[str, Any]) -> Dict[str, Any]:
        """Merge lookup results from local and external sources"""
        merged = local_result.copy()
        
        merged['sources'].extend(external_result['sources'])
        merged['threat_score'] = max(merged['threat_score'], external_result['threat_score'])
        merged['confidence'] = max(merged['confidence'], external_result['confidence'])
        merged['threat_types'].extend(external_result['threat_types'])
        merged['descriptions'].extend(external_result['descriptions'])
        
        # Remove duplicates
        merged['sources'] = list(set(merged['sources']))
        merged['threat_types'] = list(set(merged['threat_types']))
        merged['descriptions'] = list(set(merged['descriptions']))
        
        return merged
    
    def _get_actor_campaigns(self, actor_name: str) -> List[Dict[str, Any]]:
        """Get recent campaigns for threat actor"""
        campaigns = [
            {
                'name': f'{actor_name} Campaign 2024-Q3',
                'start_date': datetime.now() - timedelta(days=45),
                'status': 'active',
                'targets': ['financial_services', 'government'],
                'techniques': ['spear_phishing', 'watering_hole']
            }
        ]
        return campaigns
    
    def _get_actor_infrastructure(self, actor_name: str) -> Dict[str, List[str]]:
        """Get infrastructure associated with threat actor"""
        return {
            'domains': [f'{actor_name.lower().replace(" ", "-")}-c2.com'],
            'ip_addresses': ['203.0.113.42', '198.51.100.123'],
            'ssl_certificates': ['CN=fake-cert.com']
        }
    
    def _get_actor_victims(self, actor_name: str) -> List[str]:
        """Get known victims of threat actor"""
        return ['Organization A', 'Government Agency B', 'Financial Institution C']
    
    def _get_actor_evolution(self, actor_name: str) -> Dict[str, Any]:
        """Get evolution information for threat actor"""
        return {
            'new_techniques': ['living_off_the_land', 'cloud_exploitation'],
            'tool_updates': ['new_backdoor_variant', 'improved_persistence'],
            'targeting_changes': ['expanded_geography', 'new_sectors']
        }
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid"""
        if cache_key not in self.cache_expiry:
            return False
        
        return datetime.now() < self.cache_expiry[cache_key]
