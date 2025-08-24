import os
from datetime import timedelta
from typing import Dict, Any, List

class SecuritySettings:
    """Configuration settings for the cybersecurity threat detection system"""
    
    def __init__(self):
        self.load_settings()
    
    def load_settings(self):
        """Load all configuration settings"""
        
        # System Configuration
        self.SYSTEM_NAME = "AI-Powered Cybersecurity Threat Detection System"
        self.VERSION = "1.0.0"
        self.DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
        
        # Database and Storage
        self.DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///security.db")
        self.REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.DATA_RETENTION_DAYS = int(os.getenv("DATA_RETENTION_DAYS", "90"))
        self.BACKUP_INTERVAL_HOURS = int(os.getenv("BACKUP_INTERVAL_HOURS", "24"))
        
        # API Keys and External Services
        self.API_KEYS = {
            'virustotal': os.getenv("VIRUSTOTAL_API_KEY", ""),
            'shodan': os.getenv("SHODAN_API_KEY", ""),
            'xforce': os.getenv("XFORCE_API_KEY", ""),
            'otx': os.getenv("OTX_API_KEY", ""),
            'abuseipdb': os.getenv("ABUSEIPDB_API_KEY", ""),
            'hybrid_analysis': os.getenv("HYBRID_ANALYSIS_API_KEY", ""),
            'urlvoid': os.getenv("URLVOID_API_KEY", "")
        }
        
        # Threat Detection Settings
        self.THREAT_DETECTION = {
            'global_sensitivity': float(os.getenv("THREAT_SENSITIVITY", "0.7")),
            'auto_quarantine': os.getenv("AUTO_QUARANTINE", "True").lower() == "true",
            'auto_block_ips': os.getenv("AUTO_BLOCK_IPS", "True").lower() == "true",
            'auto_isolate_endpoints': os.getenv("AUTO_ISOLATE_ENDPOINTS", "False").lower() == "true",
            'confidence_threshold': float(os.getenv("CONFIDENCE_THRESHOLD", "0.8")),
            'correlation_window_minutes': int(os.getenv("CORRELATION_WINDOW", "30")),
            'max_concurrent_scans': int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
        }
        
        # Alert Configuration
        self.ALERT_SETTINGS = {
            'email_enabled': os.getenv("EMAIL_ALERTS", "True").lower() == "true",
            'sms_enabled': os.getenv("SMS_ALERTS", "False").lower() == "true",
            'webhook_enabled': os.getenv("WEBHOOK_ALERTS", "True").lower() == "true",
            'slack_enabled': os.getenv("SLACK_ALERTS", "False").lower() == "true",
            'email_recipients': os.getenv("ALERT_EMAIL_RECIPIENTS", "security-team@company.com").split(","),
            'webhook_url': os.getenv("ALERT_WEBHOOK_URL", "https://webhook.company.com/security-alerts"),
            'slack_webhook': os.getenv("SLACK_WEBHOOK_URL", ""),
            'notification_throttle_minutes': int(os.getenv("NOTIFICATION_THROTTLE", "5")),
            'escalation_enabled': os.getenv("ALERT_ESCALATION", "True").lower() == "true"
        }
        
        # SLA and Response Times
        self.SLA_CONFIGURATION = {
            'critical_response_minutes': int(os.getenv("CRITICAL_SLA_MINUTES", "15")),
            'high_response_hours': int(os.getenv("HIGH_SLA_HOURS", "2")),
            'medium_response_hours': int(os.getenv("MEDIUM_SLA_HOURS", "8")),
            'low_response_hours': int(os.getenv("LOW_SLA_HOURS", "24")),
            'escalation_intervals': {
                'critical': timedelta(minutes=15),
                'high': timedelta(hours=1),
                'medium': timedelta(hours=4),
                'low': timedelta(hours=12)
            }
        }
        
        # Network Monitoring
        self.NETWORK_MONITORING = {
            'monitored_networks': os.getenv("MONITORED_NETWORKS", "192.168.1.0/24,10.0.0.0/8,172.16.0.0/12").split(","),
            'ids_enabled': os.getenv("IDS_ENABLED", "True").lower() == "true",
            'ips_enabled': os.getenv("IPS_ENABLED", "True").lower() == "true",
            'packet_capture_enabled': os.getenv("PACKET_CAPTURE", "False").lower() == "true",
            'flow_monitoring': os.getenv("FLOW_MONITORING", "True").lower() == "true",
            'baseline_learning_days': int(os.getenv("BASELINE_LEARNING_DAYS", "7")),
            'anomaly_threshold': float(os.getenv("ANOMALY_THRESHOLD", "2.5"))
        }
        
        # Endpoint Security
        self.ENDPOINT_SECURITY = {
            'real_time_protection': os.getenv("REAL_TIME_PROTECTION", "True").lower() == "true",
            'behavioral_analysis': os.getenv("BEHAVIORAL_ANALYSIS", "True").lower() == "true",
            'file_integrity_monitoring': os.getenv("FILE_INTEGRITY_MONITORING", "True").lower() == "true",
            'process_monitoring': os.getenv("PROCESS_MONITORING", "True").lower() == "true",
            'registry_monitoring': os.getenv("REGISTRY_MONITORING", "True").lower() == "true",
            'network_monitoring': os.getenv("ENDPOINT_NETWORK_MONITORING", "True").lower() == "true",
            'quarantine_directory': os.getenv("QUARANTINE_DIRECTORY", "/quarantine/"),
            'scan_schedule_hours': int(os.getenv("SCAN_SCHEDULE_HOURS", "24")),
            'max_scan_duration_minutes': int(os.getenv("MAX_SCAN_DURATION", "60"))
        }
        
        # IoT Security
        self.IOT_SECURITY = {
            'device_discovery': os.getenv("IOT_DEVICE_DISCOVERY", "True").lower() == "true",
            'vulnerability_scanning': os.getenv("IOT_VULN_SCANNING", "True").lower() == "true",
            'traffic_analysis': os.getenv("IOT_TRAFFIC_ANALYSIS", "True").lower() == "true",
            'default_credential_check': os.getenv("IOT_DEFAULT_CREDS", "True").lower() == "true",
            'firmware_analysis': os.getenv("IOT_FIRMWARE_ANALYSIS", "False").lower() == "true",
            'network_segmentation': os.getenv("IOT_NETWORK_SEGMENTATION", "True").lower() == "true",
            'scan_interval_hours': int(os.getenv("IOT_SCAN_INTERVAL", "6"))
        }
        
        # Mobile Security
        self.MOBILE_SECURITY = {
            'mdm_integration': os.getenv("MDM_INTEGRATION", "True").lower() == "true",
            'app_reputation_checking': os.getenv("APP_REPUTATION_CHECK", "True").lower() == "true",
            'device_compliance_monitoring': os.getenv("DEVICE_COMPLIANCE", "True").lower() == "true",
            'jailbreak_detection': os.getenv("JAILBREAK_DETECTION", "True").lower() == "true",
            'network_traffic_analysis': os.getenv("MOBILE_TRAFFIC_ANALYSIS", "True").lower() == "true",
            'policy_enforcement': os.getenv("MOBILE_POLICY_ENFORCEMENT", "True").lower() == "true",
            'remote_wipe_enabled': os.getenv("REMOTE_WIPE", "True").lower() == "true"
        }
        
        # AI and Machine Learning
        self.AI_ML_SETTINGS = {
            'ensemble_models': os.getenv("ENSEMBLE_MODELS", "True").lower() == "true",
            'model_retraining_interval_days': int(os.getenv("MODEL_RETRAIN_DAYS", "7")),
            'feature_selection_enabled': os.getenv("FEATURE_SELECTION", "True").lower() == "true",
            'anomaly_detection_enabled': os.getenv("ANOMALY_DETECTION", "True").lower() == "true",
            'false_positive_learning': os.getenv("FP_LEARNING", "True").lower() == "true",
            'model_performance_monitoring': os.getenv("MODEL_MONITORING", "True").lower() == "true",
            'prediction_confidence_threshold': float(os.getenv("PREDICTION_THRESHOLD", "0.75"))
        }
        
        # Threat Intelligence
        self.THREAT_INTELLIGENCE = {
            'feed_update_interval_hours': int(os.getenv("TI_UPDATE_INTERVAL", "6")),
            'ioc_retention_days': int(os.getenv("IOC_RETENTION_DAYS", "30")),
            'reputation_cache_hours': int(os.getenv("REPUTATION_CACHE_HOURS", "6")),
            'auto_feed_updates': os.getenv("AUTO_FEED_UPDATES", "True").lower() == "true",
            'external_feed_enabled': os.getenv("EXTERNAL_FEEDS", "True").lower() == "true",
            'threat_hunting_enabled': os.getenv("THREAT_HUNTING", "True").lower() == "true",
            'attribution_analysis': os.getenv("ATTRIBUTION_ANALYSIS", "True").lower() == "true"
        }
        
        # Compliance and Reporting
        self.COMPLIANCE_SETTINGS = {
            'gdpr_compliance': os.getenv("GDPR_COMPLIANCE", "True").lower() == "true",
            'hipaa_compliance': os.getenv("HIPAA_COMPLIANCE", "False").lower() == "true",
            'pci_dss_compliance': os.getenv("PCI_DSS_COMPLIANCE", "False").lower() == "true",
            'sox_compliance': os.getenv("SOX_COMPLIANCE", "False").lower() == "true",
            'audit_logging': os.getenv("AUDIT_LOGGING", "True").lower() == "true",
            'report_generation_schedule': os.getenv("REPORT_SCHEDULE", "daily"),
            'data_anonymization': os.getenv("DATA_ANONYMIZATION", "True").lower() == "true"
        }
        
        # Performance and Scaling
        self.PERFORMANCE_SETTINGS = {
            'max_worker_threads': int(os.getenv("MAX_WORKER_THREADS", "10")),
            'queue_max_size': int(os.getenv("QUEUE_MAX_SIZE", "10000")),
            'cache_size_mb': int(os.getenv("CACHE_SIZE_MB", "1024")),
            'batch_processing_size': int(os.getenv("BATCH_SIZE", "100")),
            'connection_pool_size': int(os.getenv("CONNECTION_POOL_SIZE", "20")),
            'request_timeout_seconds': int(os.getenv("REQUEST_TIMEOUT", "30")),
            'health_check_interval_seconds': int(os.getenv("HEALTH_CHECK_INTERVAL", "60"))
        }
        
        # Security Hardening
        self.SECURITY_HARDENING = {
            'encryption_key': os.getenv("ENCRYPTION_KEY", self._generate_default_key()),
            'jwt_secret': os.getenv("JWT_SECRET", self._generate_default_key()),
            'api_rate_limiting': os.getenv("API_RATE_LIMITING", "True").lower() == "true",
            'max_requests_per_minute': int(os.getenv("MAX_REQUESTS_PER_MINUTE", "100")),
            'secure_headers': os.getenv("SECURE_HEADERS", "True").lower() == "true",
            'ssl_verification': os.getenv("SSL_VERIFICATION", "True").lower() == "true",
            'password_policy_enabled': os.getenv("PASSWORD_POLICY", "True").lower() == "true",
            'session_timeout_minutes': int(os.getenv("SESSION_TIMEOUT", "60"))
        }
        
        # Simulation and Testing
        self.SIMULATION_SETTINGS = {
            'simulation_enabled': os.getenv("SIMULATION_ENABLED", "True").lower() == "true",
            'safe_mode_default': os.getenv("SAFE_MODE_DEFAULT", "True").lower() == "true",
            'max_simulation_duration_minutes': int(os.getenv("MAX_SIMULATION_DURATION", "60")),
            'simulation_logging': os.getenv("SIMULATION_LOGGING", "True").lower() == "true",
            'red_team_exercises': os.getenv("RED_TEAM_EXERCISES", "False").lower() == "true",
            'penetration_testing': os.getenv("PENETRATION_TESTING", "False").lower() == "true"
        }
        
        # Integration Settings
        self.INTEGRATION_SETTINGS = {
            'siem_integration': os.getenv("SIEM_INTEGRATION", "False").lower() == "true",
            'siem_type': os.getenv("SIEM_TYPE", "splunk"),
            'siem_endpoint': os.getenv("SIEM_ENDPOINT", ""),
            'siem_api_key': os.getenv("SIEM_API_KEY", ""),
            'soar_integration': os.getenv("SOAR_INTEGRATION", "False").lower() == "true",
            'ticketing_integration': os.getenv("TICKETING_INTEGRATION", "False").lower() == "true",
            'cloud_security_integration': os.getenv("CLOUD_SECURITY", "True").lower() == "true"
        }
    
    def _generate_default_key(self) -> str:
        """Generate a default encryption key if none provided"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def get_setting(self, category: str, key: str, default: Any = None) -> Any:
        """Get a specific setting value"""
        category_settings = getattr(self, category.upper(), {})
        return category_settings.get(key, default)
    
    def update_setting(self, category: str, key: str, value: Any) -> bool:
        """Update a specific setting value"""
        try:
            category_settings = getattr(self, category.upper(), {})
            category_settings[key] = value
            return True
        except Exception:
            return False
    
    def get_all_settings(self) -> Dict[str, Dict[str, Any]]:
        """Get all settings organized by category"""
        settings = {}
        
        # Get all setting categories
        setting_categories = [
            'API_KEYS', 'THREAT_DETECTION', 'ALERT_SETTINGS', 'SLA_CONFIGURATION',
            'NETWORK_MONITORING', 'ENDPOINT_SECURITY', 'IOT_SECURITY', 'MOBILE_SECURITY',
            'AI_ML_SETTINGS', 'THREAT_INTELLIGENCE', 'COMPLIANCE_SETTINGS',
            'PERFORMANCE_SETTINGS', 'SECURITY_HARDENING', 'SIMULATION_SETTINGS',
            'INTEGRATION_SETTINGS'
        ]
        
        for category in setting_categories:
            settings[category.lower()] = getattr(self, category, {})
        
        return settings
    
    def validate_settings(self) -> Dict[str, List[str]]:
        """Validate all settings and return any issues"""
        issues = {
            'errors': [],
            'warnings': [],
            'recommendations': []
        }
        
        # Validate API keys
        for service, key in self.API_KEYS.items():
            if not key and service in ['virustotal', 'otx']:  # Required services
                issues['warnings'].append(f"Missing API key for {service}")
        
        # Validate network settings
        if not self.NETWORK_MONITORING['monitored_networks']:
            issues['errors'].append("No monitored networks configured")
        
        # Validate alert settings
        if not any([self.ALERT_SETTINGS['email_enabled'], 
                   self.ALERT_SETTINGS['webhook_enabled'],
                   self.ALERT_SETTINGS['slack_enabled']]):
            issues['warnings'].append("No alert mechanisms enabled")
        
        # Validate SLA settings
        if self.SLA_CONFIGURATION['critical_response_minutes'] > 60:
            issues['recommendations'].append("Critical response time should be under 60 minutes")
        
        # Validate performance settings
        if self.PERFORMANCE_SETTINGS['max_worker_threads'] < 5:
            issues['recommendations'].append("Consider increasing worker threads for better performance")
        
        # Validate security settings
        if not self.SECURITY_HARDENING['ssl_verification']:
            issues['warnings'].append("SSL verification is disabled - security risk")
        
        if not self.SECURITY_HARDENING['api_rate_limiting']:
            issues['warnings'].append("API rate limiting is disabled - potential DoS risk")
        
        return issues
    
    def export_settings(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Export settings for backup or sharing"""
        settings = self.get_all_settings()
        
        if not include_sensitive:
            # Remove sensitive information
            if 'api_keys' in settings:
                settings['api_keys'] = {k: '***' for k in settings['api_keys']}
            
            if 'security_hardening' in settings:
                sensitive_keys = ['encryption_key', 'jwt_secret']
                for key in sensitive_keys:
                    if key in settings['security_hardening']:
                        settings['security_hardening'][key] = '***'
        
        return {
            'system_name': self.SYSTEM_NAME,
            'version': self.VERSION,
            'export_date': str(datetime.now()),
            'settings': settings
        }
    
    def get_security_policy_template(self) -> Dict[str, Any]:
        """Get a template for security policies"""
        return {
            'password_policy': {
                'min_length': 12,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special_chars': True,
                'max_age_days': 90,
                'prevent_reuse_count': 5
            },
            'access_control': {
                'principle_of_least_privilege': True,
                'regular_access_reviews': True,
                'multi_factor_authentication': True,
                'session_timeout_minutes': 60,
                'account_lockout_threshold': 5
            },
            'data_protection': {
                'encryption_at_rest': True,
                'encryption_in_transit': True,
                'data_classification': True,
                'data_retention_policy': True,
                'secure_deletion': True
            },
            'incident_response': {
                'incident_classification': True,
                'escalation_procedures': True,
                'communication_plan': True,
                'forensics_preservation': True,
                'lessons_learned_review': True
            },
            'vulnerability_management': {
                'regular_scanning': True,
                'patch_management': True,
                'risk_assessment': True,
                'remediation_timeline': True,
                'exception_handling': True
            }
        }

# Global settings instance
settings = SecuritySettings()

# Helper functions for common setting operations
def get_threat_sensitivity() -> float:
    """Get current threat detection sensitivity"""
    return settings.THREAT_DETECTION['global_sensitivity']

def get_alert_recipients() -> List[str]:
    """Get list of alert email recipients"""
    return settings.ALERT_SETTINGS['email_recipients']

def is_auto_quarantine_enabled() -> bool:
    """Check if auto-quarantine is enabled"""
    return settings.THREAT_DETECTION['auto_quarantine']

def get_api_key(service: str) -> str:
    """Get API key for specific service"""
    return settings.API_KEYS.get(service, "")

def get_sla_response_time(severity: str) -> timedelta:
    """Get SLA response time for severity level"""
    sla_map = {
        'critical': timedelta(minutes=settings.SLA_CONFIGURATION['critical_response_minutes']),
        'high': timedelta(hours=settings.SLA_CONFIGURATION['high_response_hours']),
        'medium': timedelta(hours=settings.SLA_CONFIGURATION['medium_response_hours']),
        'low': timedelta(hours=settings.SLA_CONFIGURATION['low_response_hours'])
    }
    return sla_map.get(severity.lower(), timedelta(hours=24))

def is_feature_enabled(category: str, feature: str) -> bool:
    """Check if a specific feature is enabled"""
    category_settings = getattr(settings, category.upper(), {})
    return category_settings.get(feature, False)
