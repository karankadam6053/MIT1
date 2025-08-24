import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from enum import Enum
import hashlib

class AlertSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class AlertStatus(Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"
    CLOSED = "Closed"

class AlertManager:
    """Advanced alert management system with incident response capabilities"""
    
    def __init__(self):
        self.alerts = []
        self.alert_history = []
        self.false_positive_feedback = []
        self.escalation_rules = self._initialize_escalation_rules()
        self.notification_settings = self._initialize_notification_settings()
        self.sla_timers = {}
        
    def _initialize_escalation_rules(self) -> List[Dict[str, Any]]:
        """Initialize alert escalation rules"""
        return [
            {
                'severity': AlertSeverity.CRITICAL.value,
                'escalation_time': timedelta(minutes=15),
                'escalate_to': ['security_team_lead', 'ciso'],
                'auto_actions': ['isolate_system', 'block_ip', 'notify_soc']
            },
            {
                'severity': AlertSeverity.HIGH.value,
                'escalation_time': timedelta(hours=1),
                'escalate_to': ['security_analyst_l2'],
                'auto_actions': ['create_ticket', 'notify_analyst']
            },
            {
                'severity': AlertSeverity.MEDIUM.value,
                'escalation_time': timedelta(hours=4),
                'escalate_to': ['security_analyst_l1'],
                'auto_actions': ['queue_for_review']
            },
            {
                'severity': AlertSeverity.LOW.value,
                'escalation_time': timedelta(hours=24),
                'escalate_to': ['junior_analyst'],
                'auto_actions': ['log_for_trending']
            }
        ]
    
    def _initialize_notification_settings(self) -> Dict[str, Any]:
        """Initialize notification settings"""
        return {
            'email_enabled': True,
            'sms_enabled': False,
            'webhook_enabled': True,
            'slack_enabled': False,
            'email_recipients': ['security-team@company.com'],
            'webhook_url': 'https://webhook.company.com/security-alerts',
            'notification_throttle': timedelta(minutes=5)
        }
    
    def create_alert(self, 
                    title: str,
                    description: str,
                    severity: str,
                    source: str,
                    asset: str,
                    indicators: List[str] = None,
                    confidence: float = 1.0,
                    threat_type: str = "Unknown") -> Dict[str, Any]:
        """Create a new security alert"""
        
        alert_id = str(uuid.uuid4())
        current_time = datetime.now()
        
        alert = {
            'id': alert_id,
            'title': title,
            'description': description,
            'severity': severity,
            'status': AlertStatus.OPEN.value,
            'source': source,
            'asset': asset,
            'threat_type': threat_type,
            'confidence': confidence,
            'indicators': indicators or [],
            'timestamp': current_time,
            'created_by': 'AI_Detection_Engine',
            'assigned_to': None,
            'investigation_notes': [],
            'tags': [],
            'related_alerts': [],
            'evidence': [],
            'remediation_actions': [],
            'false_positive_score': 0.0,
            'updated_at': current_time,
            'escalation_level': 0,
            'sla_breach_time': self._calculate_sla_breach_time(severity),
            'closure_reason': None,
            'metrics': {
                'detection_time': current_time,
                'first_response_time': None,
                'resolution_time': None,
                'escalation_count': 0
            }
        }
        
        # Add contextual information
        alert['context'] = self._gather_alert_context(source, asset, threat_type)
        
        # Calculate risk score
        alert['risk_score'] = self._calculate_risk_score(severity, confidence, threat_type, asset)
        
        # Set priority based on risk score and business impact
        alert['priority'] = self._calculate_priority(alert['risk_score'], asset)
        
        # Add to active alerts
        self.alerts.append(alert)
        
        # Trigger automatic actions based on severity
        self._trigger_auto_actions(alert)
        
        # Send notifications
        self._send_alert_notifications(alert)
        
        # Start SLA timer
        self._start_sla_timer(alert_id, severity)
        
        return alert
    
    def _gather_alert_context(self, source: str, asset: str, threat_type: str) -> Dict[str, Any]:
        """Gather contextual information for the alert"""
        return {
            'environment': self._determine_environment(source),
            'asset_criticality': self._get_asset_criticality(asset),
            'threat_intelligence': self._get_threat_intelligence(threat_type),
            'similar_alerts_24h': self._count_similar_alerts(source, threat_type),
            'asset_vulnerability_score': self._get_asset_vulnerability_score(asset),
            'business_hours': self._is_business_hours(),
            'geographic_location': self._get_asset_location(asset)
        }
    
    def _calculate_risk_score(self, severity: str, confidence: float, threat_type: str, asset: str) -> float:
        """Calculate risk score for the alert"""
        base_scores = {
            AlertSeverity.CRITICAL.value: 10.0,
            AlertSeverity.HIGH.value: 7.5,
            AlertSeverity.MEDIUM.value: 5.0,
            AlertSeverity.LOW.value: 2.5
        }
        
        base_score = base_scores.get(severity, 5.0)
        
        # Adjust for confidence
        confidence_adjusted = base_score * confidence
        
        # Adjust for threat type criticality
        threat_multipliers = {
            'Ransomware': 1.5,
            'Data Exfiltration': 1.4,
            'APT': 1.3,
            'Zero-Day Exploit': 1.6,
            'Insider Threat': 1.2,
            'Malware': 1.1,
            'Phishing': 1.0,
            'Network Intrusion': 1.1
        }
        
        threat_multiplier = threat_multipliers.get(threat_type, 1.0)
        
        # Adjust for asset criticality
        asset_criticality = self._get_asset_criticality(asset)
        asset_multipliers = {
            'Critical': 1.3,
            'High': 1.2,
            'Medium': 1.0,
            'Low': 0.8
        }
        
        asset_multiplier = asset_multipliers.get(asset_criticality, 1.0)
        
        final_score = min(10.0, confidence_adjusted * threat_multiplier * asset_multiplier)
        
        return round(final_score, 2)
    
    def _calculate_priority(self, risk_score: float, asset: str) -> str:
        """Calculate alert priority"""
        if risk_score >= 8.0:
            return "P1 - Critical"
        elif risk_score >= 6.0:
            return "P2 - High"
        elif risk_score >= 4.0:
            return "P3 - Medium"
        else:
            return "P4 - Low"
    
    def _trigger_auto_actions(self, alert: Dict[str, Any]):
        """Trigger automatic response actions based on alert"""
        severity = alert['severity']
        threat_type = alert['threat_type']
        
        # Find applicable escalation rule
        rule = next((r for r in self.escalation_rules if r['severity'] == severity), None)
        
        if rule:
            for action in rule['auto_actions']:
                self._execute_auto_action(alert, action)
    
    def _execute_auto_action(self, alert: Dict[str, Any], action: str):
        """Execute automatic response action"""
        action_results = {
            'action': action,
            'timestamp': datetime.now(),
            'status': 'executed',
            'details': ''
        }
        
        if action == 'isolate_system':
            # Logic to isolate the affected system
            action_results['details'] = f"System {alert['asset']} marked for isolation"
            
        elif action == 'block_ip':
            # Logic to block malicious IPs from indicators
            blocked_ips = [ioc for ioc in alert['indicators'] if self._is_ip_address(ioc)]
            action_results['details'] = f"Blocked {len(blocked_ips)} IP addresses"
            
        elif action == 'notify_soc':
            # Logic to notify SOC team
            action_results['details'] = "SOC team notified via priority channels"
            
        elif action == 'create_ticket':
            # Logic to create incident ticket
            ticket_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{alert['id'][:8]}"
            action_results['details'] = f"Incident ticket {ticket_id} created"
            
        # Add action to alert's remediation actions
        alert['remediation_actions'].append(action_results)
    
    def update_alert(self, alert_id: str, updates: Dict[str, Any]) -> bool:
        """Update existing alert"""
        alert = self._find_alert_by_id(alert_id)
        
        if not alert:
            return False
        
        # Update fields
        for key, value in updates.items():
            if key in alert:
                alert[key] = value
        
        alert['updated_at'] = datetime.now()
        
        # Handle status changes
        if 'status' in updates:
            self._handle_status_change(alert, updates['status'])
        
        return True
    
    def assign_alert(self, alert_id: str, assignee: str) -> bool:
        """Assign alert to analyst"""
        alert = self._find_alert_by_id(alert_id)
        
        if not alert:
            return False
        
        alert['assigned_to'] = assignee
        alert['updated_at'] = datetime.now()
        
        if not alert['metrics']['first_response_time']:
            alert['metrics']['first_response_time'] = datetime.now()
        
        return True
    
    def add_investigation_note(self, alert_id: str, note: str, analyst: str) -> bool:
        """Add investigation note to alert"""
        alert = self._find_alert_by_id(alert_id)
        
        if not alert:
            return False
        
        investigation_note = {
            'timestamp': datetime.now(),
            'analyst': analyst,
            'note': note,
            'id': str(uuid.uuid4())[:8]
        }
        
        alert['investigation_notes'].append(investigation_note)
        alert['updated_at'] = datetime.now()
        
        return True
    
    def escalate_alert(self, alert_id: str, reason: str = "SLA breach") -> bool:
        """Escalate alert to next level"""
        alert = self._find_alert_by_id(alert_id)
        
        if not alert:
            return False
        
        alert['escalation_level'] += 1
        alert['metrics']['escalation_count'] += 1
        alert['updated_at'] = datetime.now()
        
        # Find escalation rule
        rule = next((r for r in self.escalation_rules if r['severity'] == alert['severity']), None)
        
        if rule and 'escalate_to' in rule:
            escalate_to = rule['escalate_to']
            if alert['escalation_level'] <= len(escalate_to):
                alert['assigned_to'] = escalate_to[alert['escalation_level'] - 1]
        
        # Add escalation note
        escalation_note = {
            'timestamp': datetime.now(),
            'reason': reason,
            'escalated_to': alert['assigned_to'],
            'level': alert['escalation_level']
        }
        
        alert['investigation_notes'].append({
            'timestamp': datetime.now(),
            'analyst': 'System',
            'note': f"Alert escalated to level {alert['escalation_level']}: {reason}",
            'id': str(uuid.uuid4())[:8]
        })
        
        return True
    
    def mark_false_positive(self, alert_id: str, reason: str = "", analyst: str = "Unknown") -> bool:
        """Mark alert as false positive"""
        alert = self._find_alert_by_id(alert_id)
        
        if not alert:
            return False
        
        alert['status'] = AlertStatus.FALSE_POSITIVE.value
        alert['closure_reason'] = reason or "Determined to be false positive"
        alert['metrics']['resolution_time'] = datetime.now()
        alert['updated_at'] = datetime.now()
        
        # Record false positive feedback for ML improvement
        fp_feedback = {
            'alert_id': alert_id,
            'timestamp': datetime.now(),
            'analyst': analyst,
            'reason': reason,
            'alert_features': {
                'severity': alert['severity'],
                'threat_type': alert['threat_type'],
                'confidence': alert['confidence'],
                'source': alert['source'],
                'indicators': alert['indicators']
            }
        }
        
        self.false_positive_feedback.append(fp_feedback)
        
        # Update false positive score for similar alerts
        self._update_false_positive_scores(alert)
        
        return True
    
    def resolve_alert(self, alert_id: str, resolution: str, analyst: str = "Unknown") -> bool:
        """Resolve alert"""
        alert = self._find_alert_by_id(alert_id)
        
        if not alert:
            return False
        
        alert['status'] = AlertStatus.RESOLVED.value
        alert['closure_reason'] = resolution
        alert['metrics']['resolution_time'] = datetime.now()
        alert['updated_at'] = datetime.now()
        
        # Add resolution note
        alert['investigation_notes'].append({
            'timestamp': datetime.now(),
            'analyst': analyst,
            'note': f"Alert resolved: {resolution}",
            'id': str(uuid.uuid4())[:8]
        })
        
        # Stop SLA timer
        if alert_id in self.sla_timers:
            del self.sla_timers[alert_id]
        
        # Move to history if older than retention period
        if alert['timestamp'] < datetime.now() - timedelta(days=30):
            self.alert_history.append(alert)
            self.alerts.remove(alert)
        
        return True
    
    def start_investigation(self, alert_id: str, analyst: str = "Unknown") -> bool:
        """Start investigation on alert"""
        alert = self._find_alert_by_id(alert_id)
        
        if not alert:
            return False
        
        alert['status'] = AlertStatus.IN_PROGRESS.value
        alert['assigned_to'] = analyst
        alert['updated_at'] = datetime.now()
        
        if not alert['metrics']['first_response_time']:
            alert['metrics']['first_response_time'] = datetime.now()
        
        # Add investigation start note
        alert['investigation_notes'].append({
            'timestamp': datetime.now(),
            'analyst': analyst,
            'note': "Investigation started",
            'id': str(uuid.uuid4())[:8]
        })
        
        return True
    
    def get_filtered_alerts(self, 
                          severity: str = "All",
                          status: str = "All", 
                          time_range: str = "Last 24h",
                          environment: str = "All") -> List[Dict[str, Any]]:
        """Get filtered list of alerts"""
        filtered_alerts = self.alerts.copy()
        
        # Filter by severity
        if severity != "All":
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
        
        # Filter by status
        if status != "All":
            filtered_alerts = [a for a in filtered_alerts if a['status'] == status]
        
        # Filter by time range
        if time_range != "All":
            cutoff_time = self._get_time_cutoff(time_range)
            filtered_alerts = [a for a in filtered_alerts if a['timestamp'] > cutoff_time]
        
        # Filter by environment
        if environment != "All":
            filtered_alerts = [a for a in filtered_alerts if a.get('context', {}).get('environment') == environment]
        
        # Sort by timestamp (newest first)
        filtered_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return filtered_alerts
    
    def get_alerts_count(self) -> Dict[str, int]:
        """Get count of alerts by status and severity"""
        counts = {
            'total': len(self.alerts),
            'open': len([a for a in self.alerts if a['status'] == AlertStatus.OPEN.value]),
            'in_progress': len([a for a in self.alerts if a['status'] == AlertStatus.IN_PROGRESS.value]),
            'resolved': len([a for a in self.alerts if a['status'] == AlertStatus.RESOLVED.value]),
            'critical': len([a for a in self.alerts if a['severity'] == AlertSeverity.CRITICAL.value]),
            'high': len([a for a in self.alerts if a['severity'] == AlertSeverity.HIGH.value]),
            'medium': len([a for a in self.alerts if a['severity'] == AlertSeverity.MEDIUM.value]),
            'low': len([a for a in self.alerts if a['severity'] == AlertSeverity.LOW.value]),
            'new_critical': len([a for a in self.alerts if a['severity'] == AlertSeverity.CRITICAL.value and a['timestamp'] > datetime.now() - timedelta(hours=1)])
        }
        
        return counts
    
    def get_alerts_timeline(self) -> Dict[str, Any]:
        """Get alerts timeline data for visualization"""
        # Get last 24 hours of alerts
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent_alerts = [a for a in self.alerts if a['timestamp'] > cutoff_time]
        
        if not recent_alerts:
            return {'timestamps': [], 'counts': []}
        
        # Group by hour
        hourly_counts = {}
        for alert in recent_alerts:
            hour_key = alert['timestamp'].replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
        
        # Fill in missing hours with 0
        current_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
        timestamps = []
        counts = []
        
        for i in range(24):
            hour = current_hour - timedelta(hours=i)
            timestamps.append(hour)
            counts.append(hourly_counts.get(hour, 0))
        
        timestamps.reverse()
        counts.reverse()
        
        return {
            'timestamps': timestamps,
            'counts': counts
        }
    
    def get_false_positive_rate(self) -> float:
        """Calculate false positive rate"""
        total_alerts = len(self.alerts) + len(self.alert_history)
        
        if total_alerts == 0:
            return 0.0
        
        false_positives = len([a for a in self.alerts + self.alert_history 
                             if a['status'] == AlertStatus.FALSE_POSITIVE.value])
        
        return false_positives / total_alerts
    
    def get_false_positive_trends(self) -> Dict[str, Any]:
        """Get false positive rate trends"""
        # Calculate daily false positive rates for last 30 days
        dates = []
        rates = []
        
        for i in range(30):
            date = datetime.now() - timedelta(days=i)
            day_alerts = [a for a in self.alerts + self.alert_history 
                         if a['timestamp'].date() == date.date()]
            
            if day_alerts:
                day_fp = len([a for a in day_alerts if a['status'] == AlertStatus.FALSE_POSITIVE.value])
                fp_rate = day_fp / len(day_alerts)
            else:
                fp_rate = 0.0
            
            dates.append(date.strftime('%Y-%m-%d'))
            rates.append(fp_rate)
        
        dates.reverse()
        rates.reverse()
        
        return {
            'dates': dates,
            'rates': rates
        }
    
    def get_false_positives_by_type(self) -> Dict[str, int]:
        """Get false positives grouped by threat type"""
        fp_alerts = [a for a in self.alerts + self.alert_history 
                    if a['status'] == AlertStatus.FALSE_POSITIVE.value]
        
        fp_by_type = {}
        for alert in fp_alerts:
            threat_type = alert['threat_type']
            fp_by_type[threat_type] = fp_by_type.get(threat_type, 0) + 1
        
        return fp_by_type
    
    def _find_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Find alert by ID"""
        return next((alert for alert in self.alerts if alert['id'] == alert_id), None)
    
    def _handle_status_change(self, alert: Dict[str, Any], new_status: str):
        """Handle alert status changes"""
        if new_status == AlertStatus.IN_PROGRESS.value and not alert['metrics']['first_response_time']:
            alert['metrics']['first_response_time'] = datetime.now()
        elif new_status in [AlertStatus.RESOLVED.value, AlertStatus.FALSE_POSITIVE.value]:
            alert['metrics']['resolution_time'] = datetime.now()
    
    def _send_alert_notifications(self, alert: Dict[str, Any]):
        """Send alert notifications based on configuration"""
        if not self._should_send_notification(alert):
            return
        
        notification_payload = {
            'alert_id': alert['id'],
            'title': alert['title'],
            'severity': alert['severity'],
            'description': alert['description'],
            'asset': alert['asset'],
            'timestamp': alert['timestamp'].isoformat(),
            'priority': alert['priority']
        }
        
        # Email notification
        if self.notification_settings['email_enabled']:
            self._send_email_notification(notification_payload)
        
        # Webhook notification
        if self.notification_settings['webhook_enabled']:
            self._send_webhook_notification(notification_payload)
    
    def _should_send_notification(self, alert: Dict[str, Any]) -> bool:
        """Check if notification should be sent"""
        # Check throttling
        throttle_key = f"{alert['source']}_{alert['threat_type']}"
        current_time = datetime.now()
        
        if hasattr(self, '_last_notifications'):
            last_notification = self._last_notifications.get(throttle_key)
            if last_notification and current_time - last_notification < self.notification_settings['notification_throttle']:
                return False
        else:
            self._last_notifications = {}
        
        self._last_notifications[throttle_key] = current_time
        return True
    
    def _send_email_notification(self, payload: Dict[str, Any]):
        """Send email notification (implementation would use actual email service)"""
        # In a real implementation, this would integrate with email service
        pass
    
    def _send_webhook_notification(self, payload: Dict[str, Any]):
        """Send webhook notification (implementation would make HTTP request)"""
        # In a real implementation, this would make HTTP POST to webhook URL
        pass
    
    def _calculate_sla_breach_time(self, severity: str) -> datetime:
        """Calculate when SLA would be breached"""
        sla_times = {
            AlertSeverity.CRITICAL.value: timedelta(minutes=15),
            AlertSeverity.HIGH.value: timedelta(hours=2),
            AlertSeverity.MEDIUM.value: timedelta(hours=8),
            AlertSeverity.LOW.value: timedelta(hours=24)
        }
        
        sla_time = sla_times.get(severity, timedelta(hours=24))
        return datetime.now() + sla_time
    
    def _start_sla_timer(self, alert_id: str, severity: str):
        """Start SLA timer for alert"""
        breach_time = self._calculate_sla_breach_time(severity)
        self.sla_timers[alert_id] = breach_time
    
    def _get_time_cutoff(self, time_range: str) -> datetime:
        """Get cutoff time for filtering"""
        now = datetime.now()
        
        if time_range == "Last Hour":
            return now - timedelta(hours=1)
        elif time_range == "Last 24h":
            return now - timedelta(days=1)
        elif time_range == "Last 7 days":
            return now - timedelta(days=7)
        elif time_range == "Last 30 days":
            return now - timedelta(days=30)
        else:
            return now - timedelta(days=1)
    
    # Helper methods for context gathering
    def _determine_environment(self, source: str) -> str:
        """Determine environment type from source"""
        if 'network' in source.lower():
            return 'Network'
        elif 'endpoint' in source.lower():
            return 'Endpoint'
        elif 'cloud' in source.lower():
            return 'Cloud'
        elif 'iot' in source.lower():
            return 'IoT'
        elif 'mobile' in source.lower():
            return 'Mobile'
        else:
            return 'Unknown'
    
    def _get_asset_criticality(self, asset: str) -> str:
        """Get asset criticality level"""
        critical_assets = ['domain-controller', 'database', 'mail-server', 'web-server']
        high_assets = ['file-server', 'backup-server', 'vpn-gateway']
        
        asset_lower = asset.lower()
        
        if any(critical in asset_lower for critical in critical_assets):
            return 'Critical'
        elif any(high in asset_lower for high in high_assets):
            return 'High'
        elif 'workstation' in asset_lower:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_threat_intelligence(self, threat_type: str) -> Dict[str, Any]:
        """Get threat intelligence for threat type"""
        return {
            'known_campaigns': [],
            'recent_activity': False,
            'attribution': None,
            'severity_trend': 'stable'
        }
    
    def _count_similar_alerts(self, source: str, threat_type: str) -> int:
        """Count similar alerts in last 24 hours"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        similar_alerts = [
            a for a in self.alerts 
            if a['timestamp'] > cutoff_time 
            and a['source'] == source 
            and a['threat_type'] == threat_type
        ]
        return len(similar_alerts)
    
    def _get_asset_vulnerability_score(self, asset: str) -> float:
        """Get vulnerability score for asset"""
        # In real implementation, this would query vulnerability management system
        return round(random.uniform(0.0, 10.0), 1)
    
    def _is_business_hours(self) -> bool:
        """Check if current time is business hours"""
        now = datetime.now()
        return 9 <= now.hour <= 17 and now.weekday() < 5
    
    def _get_asset_location(self, asset: str) -> str:
        """Get geographic location of asset"""
        # In real implementation, this would query asset management system
        locations = ['US-East', 'US-West', 'EU-Central', 'APAC-Singapore']
        return random.choice(locations)
    
    def _is_ip_address(self, indicator: str) -> bool:
        """Check if indicator is an IP address"""
        import re
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        return bool(re.match(ip_pattern, indicator))
    
    def _update_false_positive_scores(self, alert: Dict[str, Any]):
        """Update false positive scores for similar alerts"""
        similar_alerts = [
            a for a in self.alerts 
            if a['threat_type'] == alert['threat_type'] 
            and a['source'] == alert['source']
            and a['id'] != alert['id']
        ]
        
        for similar_alert in similar_alerts:
            similar_alert['false_positive_score'] = min(1.0, similar_alert['false_positive_score'] + 0.1)

import random
