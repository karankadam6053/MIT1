import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import threading
import os

# Import our custom modules
from core.threat_detection import ThreatDetectionEngine
from core.ai_models import AIThreatAnalyzer
from core.log_analyzer import LogAnalyzer
from core.alert_manager import AlertManager
from simulation.attack_simulator import AttackSimulator
from monitoring.network_monitor import NetworkMonitor
from monitoring.endpoint_monitor import EndpointMonitor
from monitoring.iot_monitor import IoTMonitor
from monitoring.mobile_monitor import MobileMonitor
from utils.data_processor import DataProcessor
from utils.threat_intelligence import ThreatIntelligence

# Configure page
st.set_page_config(
    page_title="AI Cybersecurity Threat Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'threat_engine' not in st.session_state:
    st.session_state.threat_engine = ThreatDetectionEngine()
    st.session_state.ai_analyzer = AIThreatAnalyzer()
    st.session_state.log_analyzer = LogAnalyzer()
    st.session_state.alert_manager = AlertManager()
    st.session_state.attack_simulator = AttackSimulator()
    st.session_state.network_monitor = NetworkMonitor()
    st.session_state.endpoint_monitor = EndpointMonitor()
    st.session_state.iot_monitor = IoTMonitor()
    st.session_state.mobile_monitor = MobileMonitor()
    st.session_state.data_processor = DataProcessor()
    st.session_state.threat_intel = ThreatIntelligence()

def main():
    st.title("🛡️ AI-Powered Cybersecurity Threat Detection System")
    st.markdown("### Comprehensive Multi-Environment Security Monitoring & Response")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox("Select Module", [
        "🏠 Dashboard Overview",
        "🎯 Real-Time Threat Detection",
        "📊 Alert Management",
        "🔍 Log Analysis",
        "🌐 Network Security",
        "💻 Endpoint Protection",
        "📱 IoT & Mobile Security",
        "⚔️ Attack Simulation",
        "📈 Analytics & Reports",
        "⚙️ System Configuration"
    ])
    
    # Real-time monitoring toggle
    if st.sidebar.checkbox("Enable Real-Time Monitoring"):
        if 'monitoring_active' not in st.session_state:
            st.session_state.monitoring_active = True
            start_background_monitoring()
    
    # Route to selected page
    if page == "🏠 Dashboard Overview":
        show_dashboard_overview()
    elif page == "🎯 Real-Time Threat Detection":
        show_threat_detection()
    elif page == "📊 Alert Management":
        show_alert_management()
    elif page == "🔍 Log Analysis":
        show_log_analysis()
    elif page == "🌐 Network Security":
        show_network_security()
    elif page == "💻 Endpoint Protection":
        show_endpoint_protection()
    elif page == "📱 IoT & Mobile Security":
        show_iot_mobile_security()
    elif page == "⚔️ Attack Simulation":
        show_attack_simulation()
    elif page == "📈 Analytics & Reports":
        show_analytics_reports()
    elif page == "⚙️ System Configuration":
        show_system_configuration()

def show_dashboard_overview():
    """Main dashboard with system overview"""
    col1, col2, col3, col4 = st.columns(4)
    
    # Get current system status
    active_threats = st.session_state.threat_engine.get_active_threats()
    alerts_count = st.session_state.alert_manager.get_alerts_count()
    system_health = st.session_state.threat_engine.get_system_health()
    
    with col1:
        st.metric("Active Threats", len(active_threats), delta=f"+{len([t for t in active_threats if t['timestamp'] > datetime.now() - timedelta(hours=1)])}")
    
    with col2:
        st.metric("Critical Alerts", alerts_count['critical'], delta=f"+{alerts_count.get('new_critical', 0)}")
    
    with col3:
        st.metric("System Health", f"{system_health['score']:.1f}/10", delta=f"{system_health['trend']:+.1f}")
    
    with col4:
        st.metric("Protected Assets", system_health['protected_assets'], delta=f"+{system_health.get('new_assets', 0)}")
    
    # Threat severity distribution
    st.subheader("🚨 Current Threat Landscape")
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat types pie chart
        threat_types = st.session_state.threat_engine.get_threat_distribution()
        if threat_types:
            fig = px.pie(
                values=list(threat_types.values()),
                names=list(threat_types.keys()),
                title="Threat Types Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Alert timeline
        alerts_timeline = st.session_state.alert_manager.get_alerts_timeline()
        if alerts_timeline:
            fig = px.line(
                x=alerts_timeline['timestamps'],
                y=alerts_timeline['counts'],
                title="Alerts Over Time (Last 24h)"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Recent threats table
    st.subheader("🔍 Recent Threat Activity")
    if active_threats:
        df = pd.DataFrame(active_threats)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No active threats detected in the current timeframe.")
    
    # Environment status
    st.subheader("🌐 Multi-Environment Status")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**Network Security**")
        network_status = st.session_state.network_monitor.get_status()
        st.metric("Monitored Devices", network_status['devices'])
        st.metric("Blocked IPs", network_status['blocked_ips'])
    
    with col2:
        st.markdown("**Endpoint Protection**")
        endpoint_status = st.session_state.endpoint_monitor.get_status()
        st.metric("Protected Endpoints", endpoint_status['protected'])
        st.metric("Quarantined Files", endpoint_status['quarantined'])
    
    with col3:
        st.markdown("**IoT & Mobile**")
        iot_status = st.session_state.iot_monitor.get_status()
        mobile_status = st.session_state.mobile_monitor.get_status()
        st.metric("IoT Devices", iot_status['devices'])
        st.metric("Mobile Devices", mobile_status['devices'])

def show_threat_detection():
    """Real-time threat detection interface"""
    st.header("🎯 Real-Time Threat Detection Engine")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 AI Analysis Dashboard")
        
        # Real-time threat feed
        if st.button("🔄 Refresh Threat Analysis"):
            with st.spinner("Analyzing threats..."):
                threats = st.session_state.ai_analyzer.analyze_real_time()
                
                if threats:
                    for threat in threats:
                        severity_color = {
                            'Critical': '🔴',
                            'High': '🟠', 
                            'Medium': '🟡',
                            'Low': '🟢'
                        }.get(threat['severity'], '⚪')
                        
                        st.warning(f"{severity_color} **{threat['type']}** - Confidence: {threat['confidence']:.1%}")
                        st.write(f"**Target**: {threat['target']}")
                        st.write(f"**Description**: {threat['description']}")
                        st.write(f"**Recommended Action**: {threat['action']}")
                        st.write("---")
                else:
                    st.success("✅ No active threats detected")
    
    with col2:
        st.subheader("⚙️ Detection Settings")
        
        # Detection sensitivity
        sensitivity = st.slider("Detection Sensitivity", 0.1, 1.0, 0.7, 0.1)
        st.session_state.ai_analyzer.set_sensitivity(sensitivity)
        
        # Monitored threat types
        st.write("**Monitored Threats:**")
        threat_types = [
            "Ransomware", "Zero-day Exploits", "Network Intrusions",
            "Malware", "Phishing", "DDoS Attacks", "Data Exfiltration",
            "Privilege Escalation", "Lateral Movement", "Social Engineering"
        ]
        
        selected_threats = []
        for threat in threat_types:
            if st.checkbox(threat, value=True):
                selected_threats.append(threat)
        
        st.session_state.ai_analyzer.set_monitored_threats(selected_threats)
        
        # Auto-response settings
        st.write("**Auto-Response:**")
        auto_quarantine = st.checkbox("Auto-quarantine malicious files")
        auto_block_ips = st.checkbox("Auto-block suspicious IPs")
        auto_isolate_endpoints = st.checkbox("Auto-isolate compromised endpoints")
    
    # Threat pattern analysis
    st.subheader("📊 Threat Pattern Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Attack vectors
        attack_vectors = st.session_state.ai_analyzer.get_attack_vectors()
        if attack_vectors:
            fig = px.bar(
                x=list(attack_vectors.keys()),
                y=list(attack_vectors.values()),
                title="Most Common Attack Vectors (Last 7 Days)"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Confidence scores distribution
        confidence_dist = st.session_state.ai_analyzer.get_confidence_distribution()
        if confidence_dist:
            fig = px.histogram(
                x=confidence_dist,
                title="Detection Confidence Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)

def show_alert_management():
    """Alert management and response interface"""
    st.header("📊 Alert Management & Incident Response")
    
    # Alert filters
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
    with col2:
        status_filter = st.selectbox("Status", ["All", "Open", "In Progress", "Resolved", "False Positive"])
    with col3:
        time_filter = st.selectbox("Time Range", ["Last Hour", "Last 24h", "Last 7 days", "Last 30 days"])
    with col4:
        environment_filter = st.selectbox("Environment", ["All", "Network", "Endpoint", "Cloud", "IoT", "Mobile"])
    
    # Get filtered alerts
    alerts = st.session_state.alert_manager.get_filtered_alerts(
        severity=severity_filter,
        status=status_filter,
        time_range=time_filter,
        environment=environment_filter
    )
    
    # Alert summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Alerts", len(alerts))
    with col2:
        critical_count = len([a for a in alerts if a['severity'] == 'Critical'])
        st.metric("Critical Alerts", critical_count)
    with col3:
        open_count = len([a for a in alerts if a['status'] == 'Open'])
        st.metric("Open Alerts", open_count)
    with col4:
        false_positive_rate = st.session_state.alert_manager.get_false_positive_rate()
        st.metric("False Positive Rate", f"{false_positive_rate:.1%}")
    
    # Alert management interface
    if alerts:
        st.subheader("🚨 Active Alerts")
        
        for i, alert in enumerate(alerts[:10]):  # Show top 10
            with st.expander(f"{alert['severity']} - {alert['title']} ({alert['timestamp']})"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Description**: {alert['description']}")
                    st.write(f"**Affected Asset**: {alert['asset']}")
                    st.write(f"**Source**: {alert['source']}")
                    st.write(f"**Confidence**: {alert['confidence']:.1%}")
                    
                    if alert.get('indicators'):
                        st.write("**Indicators of Compromise (IoCs):**")
                        for ioc in alert['indicators']:
                            st.code(ioc)
                
                with col2:
                    st.write(f"**Status**: {alert['status']}")
                    st.write(f"**Assigned To**: {alert.get('assigned_to', 'Unassigned')}")
                    
                    # Action buttons
                    if st.button(f"Investigate", key=f"investigate_{i}"):
                        st.session_state.alert_manager.start_investigation(alert['id'])
                        st.success("Investigation started")
                        st.rerun()
                    
                    if st.button(f"Mark False Positive", key=f"fp_{i}"):
                        st.session_state.alert_manager.mark_false_positive(alert['id'])
                        st.success("Marked as false positive")
                        st.rerun()
                    
                    if st.button(f"Resolve", key=f"resolve_{i}"):
                        st.session_state.alert_manager.resolve_alert(alert['id'])
                        st.success("Alert resolved")
                        st.rerun()
    
    # False positive analysis
    st.subheader("📈 False Positive Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        fp_trends = st.session_state.alert_manager.get_false_positive_trends()
        if fp_trends:
            fig = px.line(
                x=fp_trends['dates'],
                y=fp_trends['rates'],
                title="False Positive Rate Trend"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fp_by_type = st.session_state.alert_manager.get_false_positives_by_type()
        if fp_by_type:
            fig = px.bar(
                x=list(fp_by_type.keys()),
                y=list(fp_by_type.values()),
                title="False Positives by Alert Type"
            )
            st.plotly_chart(fig, use_container_width=True)

def show_log_analysis():
    """Log analysis and forensics interface"""
    st.header("🔍 Advanced Log Analysis & Digital Forensics")
    
    # Log source selection
    col1, col2, col3 = st.columns(3)
    
    with col1:
        log_sources = st.multiselect(
            "Select Log Sources",
            ["Windows Event Logs", "Linux Syslogs", "Network Devices", "Web Servers", 
             "Database Logs", "Cloud Audit Logs", "IoT Device Logs", "Mobile Device Logs"],
            default=["Windows Event Logs", "Network Devices"]
        )
    
    with col2:
        time_range = st.selectbox(
            "Analysis Time Range",
            ["Last Hour", "Last 24h", "Last 7 days", "Custom Range"]
        )
    
    with col3:
        analysis_type = st.selectbox(
            "Analysis Type",
            ["Real-time", "Historical", "Correlation", "Pattern Detection"]
        )
    
    # Custom time range
    if time_range == "Custom Range":
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date")
        with col2:
            end_date = st.date_input("End Date")
    
    # Log analysis controls
    if st.button("🔍 Start Log Analysis"):
        with st.spinner("Analyzing logs..."):
            results = st.session_state.log_analyzer.analyze_logs(
                sources=log_sources,
                time_range=time_range,
                analysis_type=analysis_type
            )
            
            if results:
                st.success(f"Analysis complete. Found {len(results['events'])} relevant events.")
                
                # Event timeline
                st.subheader("📅 Event Timeline")
                if results['timeline']:
                    fig = px.scatter(
                        x=results['timeline']['timestamps'],
                        y=results['timeline']['sources'],
                        color=results['timeline']['severities'],
                        title="Security Events Timeline"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Top findings
                st.subheader("🎯 Key Findings")
                for finding in results['findings'][:5]:
                    severity_emoji = {
                        'Critical': '🔴',
                        'High': '🟠',
                        'Medium': '🟡',
                        'Low': '🟢'
                    }.get(finding['severity'], '⚪')
                    
                    st.write(f"{severity_emoji} **{finding['title']}**")
                    st.write(f"Confidence: {finding['confidence']:.1%}")
                    st.write(f"Description: {finding['description']}")
                    
                    if finding.get('recommendations'):
                        st.write("**Recommendations:**")
                        for rec in finding['recommendations']:
                            st.write(f"• {rec}")
                    st.write("---")
                
                # Raw log viewer
                with st.expander("📄 Raw Log Data"):
                    if results['raw_logs']:
                        df = pd.DataFrame(results['raw_logs'])
                        st.dataframe(df, use_container_width=True)
    
    # Log correlation analysis
    st.subheader("🔗 Cross-Platform Log Correlation")
    
    if st.button("🔄 Run Correlation Analysis"):
        correlations = st.session_state.log_analyzer.run_correlation_analysis()
        
        if correlations:
            for correlation in correlations:
                st.write(f"**Correlation Pattern**: {correlation['pattern']}")
                st.write(f"**Confidence**: {correlation['confidence']:.1%}")
                st.write(f"**Affected Systems**: {', '.join(correlation['systems'])}")
                st.write(f"**Timeline**: {correlation['timespan']}")
                st.write("---")

def show_network_security():
    """Network security monitoring interface"""
    st.header("🌐 Network Security Monitoring")
    
    # Network overview
    col1, col2, col3, col4 = st.columns(4)
    
    network_stats = st.session_state.network_monitor.get_network_statistics()
    
    with col1:
        st.metric("Monitored Networks", network_stats['networks'])
    with col2:
        st.metric("Active Connections", network_stats['connections'])
    with col3:
        st.metric("Blocked Threats", network_stats['blocked_threats'])
    with col4:
        st.metric("Network Health", f"{network_stats['health_score']:.1f}/10")
    
    # Real-time network monitoring
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 Real-Time Traffic Analysis")
        
        if st.button("📊 Analyze Current Traffic"):
            with st.spinner("Analyzing network traffic..."):
                traffic_analysis = st.session_state.network_monitor.analyze_traffic()
                
                if traffic_analysis['threats']:
                    st.warning("⚠️ Suspicious Network Activity Detected!")
                    for threat in traffic_analysis['threats']:
                        st.write(f"**Type**: {threat['type']}")
                        st.write(f"**Source**: {threat['source_ip']}")
                        st.write(f"**Destination**: {threat['dest_ip']}")
                        st.write(f"**Risk Level**: {threat['risk_level']}")
                        st.write("---")
                else:
                    st.success("✅ No suspicious network activity detected")
    
    with col2:
        st.subheader("🛡️ Intrusion Detection")
        
        # IDS/IPS status
        ids_status = st.session_state.network_monitor.get_ids_status()
        
        st.write(f"**IDS Status**: {'🟢 Active' if ids_status['active'] else '🔴 Inactive'}")
        st.write(f"**Signatures Updated**: {ids_status['last_update']}")
        st.write(f"**Detection Rules**: {ids_status['rules_count']}")
        
        if st.button("🔄 Update Signatures"):
            st.session_state.network_monitor.update_signatures()
            st.success("Signatures updated successfully")
    
    # Network topology visualization
    st.subheader("🗺️ Network Topology & Threat Map")
    
    topology_data = st.session_state.network_monitor.get_network_topology()
    if topology_data:
        # Create network visualization
        fig = go.Figure()
        
        # Add nodes (devices)
        for device in topology_data['devices']:
            color = 'red' if device['status'] == 'compromised' else 'yellow' if device['status'] == 'suspicious' else 'green'
            fig.add_trace(go.Scatter(
                x=[device['x']],
                y=[device['y']],
                mode='markers+text',
                marker=dict(size=15, color=color),
                text=device['name'],
                textposition="bottom center",
                name=device['type']
            ))
        
        # Add connections
        for connection in topology_data['connections']:
            fig.add_trace(go.Scatter(
                x=[connection['x1'], connection['x2']],
                y=[connection['y1'], connection['y2']],
                mode='lines',
                line=dict(color='gray', width=2),
                showlegend=False
            ))
        
        fig.update_layout(title="Network Topology with Threat Indicators")
        st.plotly_chart(fig, use_container_width=True)
    
    # Firewall management
    st.subheader("🔥 Firewall Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Blocked IPs (Last 24h)**")
        blocked_ips = st.session_state.network_monitor.get_blocked_ips()
        if blocked_ips:
            df = pd.DataFrame(blocked_ips)
            st.dataframe(df, use_container_width=True)
    
    with col2:
        st.write("**Add IP to Blocklist**")
        ip_to_block = st.text_input("IP Address")
        reason = st.text_input("Reason")
        if st.button("🚫 Block IP"):
            if ip_to_block:
                st.session_state.network_monitor.block_ip(ip_to_block, reason)
                st.success(f"IP {ip_to_block} blocked successfully")

def show_endpoint_protection():
    """Endpoint protection interface"""
    st.header("💻 Endpoint Protection & Management")
    
    # Endpoint overview
    col1, col2, col3, col4 = st.columns(4)
    
    endpoint_stats = st.session_state.endpoint_monitor.get_endpoint_statistics()
    
    with col1:
        st.metric("Protected Endpoints", endpoint_stats['protected'])
    with col2:
        st.metric("Threats Detected", endpoint_stats['threats_detected'])
    with col3:
        st.metric("Quarantined Files", endpoint_stats['quarantined'])
    with col4:
        st.metric("Compliance Score", f"{endpoint_stats['compliance_score']:.1%}")
    
    # Endpoint status grid
    st.subheader("🖥️ Endpoint Status Overview")
    
    endpoints = st.session_state.endpoint_monitor.get_all_endpoints()
    
    if endpoints:
        # Create status grid
        cols = st.columns(4)
        for i, endpoint in enumerate(endpoints):
            with cols[i % 4]:
                status_color = {
                    'healthy': '🟢',
                    'warning': '🟡', 
                    'critical': '🔴',
                    'offline': '⚫'
                }.get(endpoint['status'], '⚪')
                
                st.markdown(f"""
                **{endpoint['name']}** {status_color}
                - OS: {endpoint['os']}
                - Last Scan: {endpoint['last_scan']}
                - Threats: {endpoint['threat_count']}
                """)
    
    # Real-time scanning
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 Real-Time Endpoint Scanning")
        
        selected_endpoint = st.selectbox(
            "Select Endpoint",
            [ep['name'] for ep in endpoints] if endpoints else ["No endpoints available"]
        )
        
        scan_type = st.selectbox(
            "Scan Type",
            ["Quick Scan", "Full System Scan", "Custom Scan", "Memory Scan"]
        )
        
        if st.button("🚀 Start Scan"):
            with st.spinner(f"Running {scan_type} on {selected_endpoint}..."):
                scan_results = st.session_state.endpoint_monitor.run_scan(selected_endpoint, scan_type)
                
                if scan_results['threats_found']:
                    st.warning(f"⚠️ {len(scan_results['threats_found'])} threats detected!")
                    for threat in scan_results['threats_found']:
                        st.write(f"**File**: {threat['file_path']}")
                        st.write(f"**Threat Type**: {threat['type']}")
                        st.write(f"**Action**: {threat['action_taken']}")
                        st.write("---")
                else:
                    st.success("✅ No threats detected")
    
    with col2:
        st.subheader("🛡️ Behavioral Analysis")
        
        behavior_data = st.session_state.endpoint_monitor.get_behavioral_analysis()
        
        if behavior_data:
            st.write("**Suspicious Processes:**")
            for process in behavior_data['suspicious_processes']:
                st.write(f"• {process['name']} (PID: {process['pid']}) - Risk: {process['risk_score']:.1%}")
            
            st.write("**Unusual Network Connections:**")
            for connection in behavior_data['network_anomalies']:
                st.write(f"• {connection['process']} → {connection['destination']} - Risk: {connection['risk_score']:.1%}")
    
    # Malware analysis
    st.subheader("🦠 Advanced Malware Analysis")
    
    uploaded_file = st.file_uploader("Upload file for analysis", type=['exe', 'dll', 'pdf', 'doc', 'zip'])
    
    if uploaded_file and st.button("🔬 Analyze File"):
        with st.spinner("Analyzing file for malware..."):
            analysis_results = st.session_state.endpoint_monitor.analyze_file(uploaded_file)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**File**: {uploaded_file.name}")
                st.write(f"**Size**: {len(uploaded_file.getvalue())} bytes")
                st.write(f"**MD5**: {analysis_results['md5']}")
                st.write(f"**SHA256**: {analysis_results['sha256']}")
                st.write(f"**Threat Score**: {analysis_results['threat_score']:.1%}")
            
            with col2:
                if analysis_results['is_malicious']:
                    st.error("🚫 MALICIOUS FILE DETECTED!")
                    st.write(f"**Threat Type**: {analysis_results['threat_type']}")
                    st.write(f"**Family**: {analysis_results['malware_family']}")
                else:
                    st.success("✅ File appears to be clean")
                
                st.write("**Detection Engines:**")
                for engine, result in analysis_results['engine_results'].items():
                    status = "🔴 Detected" if result['detected'] else "🟢 Clean"
                    st.write(f"• {engine}: {status}")

def show_iot_mobile_security():
    """IoT and mobile security interface"""
    st.header("📱 IoT & Mobile Device Security")
    
    # Overview metrics
    col1, col2, col3, col4 = st.columns(4)
    
    iot_stats = st.session_state.iot_monitor.get_statistics()
    mobile_stats = st.session_state.mobile_monitor.get_statistics()
    
    with col1:
        st.metric("IoT Devices", iot_stats['total_devices'])
    with col2:
        st.metric("Mobile Devices", mobile_stats['total_devices'])
    with col3:
        st.metric("Vulnerable Devices", iot_stats['vulnerable'] + mobile_stats['vulnerable'])
    with col4:
        combined_score = (iot_stats['security_score'] + mobile_stats['security_score']) / 2
        st.metric("Overall Security Score", f"{combined_score:.1f}/10")
    
    # IoT Security Section
    st.subheader("🏠 IoT Device Security")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Connected IoT Devices**")
        iot_devices = st.session_state.iot_monitor.get_devices()
        
        if iot_devices:
            for device in iot_devices:
                status_emoji = {
                    'secure': '🟢',
                    'warning': '🟡',
                    'vulnerable': '🔴',
                    'unknown': '⚪'
                }.get(device['security_status'], '⚪')
                
                with st.expander(f"{status_emoji} {device['name']} ({device['type']})"):
                    st.write(f"**IP Address**: {device['ip']}")
                    st.write(f"**Firmware**: {device['firmware_version']}")
                    st.write(f"**Last Seen**: {device['last_seen']}")
                    st.write(f"**Security Score**: {device['security_score']:.1f}/10")
                    
                    if device['vulnerabilities']:
                        st.write("**Vulnerabilities:**")
                        for vuln in device['vulnerabilities']:
                            st.write(f"• {vuln['description']} (CVE: {vuln['cve']})")
    
    with col2:
        st.write("**IoT Threat Detection**")
        
        if st.button("🔍 Scan IoT Network"):
            with st.spinner("Scanning IoT devices for threats..."):
                scan_results = st.session_state.iot_monitor.scan_for_threats()
                
                if scan_results['threats']:
                    st.warning(f"⚠️ {len(scan_results['threats'])} IoT threats detected!")
                    for threat in scan_results['threats']:
                        st.write(f"**Device**: {threat['device_name']}")
                        st.write(f"**Threat**: {threat['type']}")
                        st.write(f"**Severity**: {threat['severity']}")
                        st.write("---")
                else:
                    st.success("✅ No IoT threats detected")
    
    # Mobile Security Section
    st.subheader("📱 Mobile Device Security")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Managed Mobile Devices**")
        mobile_devices = st.session_state.mobile_monitor.get_devices()
        
        if mobile_devices:
            for device in mobile_devices:
                status_emoji = {
                    'compliant': '🟢',
                    'non_compliant': '🟡',
                    'compromised': '🔴',
                    'unknown': '⚪'
                }.get(device['compliance_status'], '⚪')
                
                with st.expander(f"{status_emoji} {device['name']} ({device['platform']})"):
                    st.write(f"**User**: {device['user']}")
                    st.write(f"**OS Version**: {device['os_version']}")
                    st.write(f"**Last Check-in**: {device['last_checkin']}")
                    st.write(f"**Jailbroken/Rooted**: {'Yes' if device['is_jailbroken'] else 'No'}")
                    
                    if device['installed_apps']:
                        risky_apps = [app for app in device['installed_apps'] if app['risk_level'] == 'high']
                        if risky_apps:
                            st.write("**Risky Applications:**")
                            for app in risky_apps:
                                st.write(f"• {app['name']} - {app['risk_reason']}")
    
    with col2:
        st.write("**Mobile Threat Protection**")
        
        # Mobile threat categories
        threat_categories = [
            "Malicious Apps",
            "Phishing Attempts", 
            "Network Attacks",
            "Data Leakage",
            "Device Compromise"
        ]
        
        for category in threat_categories:
            count = st.session_state.mobile_monitor.get_threat_count(category)
            st.metric(category, count)
        
        if st.button("🛡️ Update Mobile Security Policies"):
            st.session_state.mobile_monitor.update_security_policies()
            st.success("Mobile security policies updated")
    
    # Device compliance dashboard
    st.subheader("📋 Device Compliance Dashboard")
    
    compliance_data = {
        'iot': st.session_state.iot_monitor.get_compliance_data(),
        'mobile': st.session_state.mobile_monitor.get_compliance_data()
    }
    
    col1, col2 = st.columns(2)
    
    with col1:
        # IoT compliance chart
        if compliance_data['iot']:
            fig = px.pie(
                values=list(compliance_data['iot'].values()),
                names=list(compliance_data['iot'].keys()),
                title="IoT Device Compliance Status"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Mobile compliance chart  
        if compliance_data['mobile']:
            fig = px.pie(
                values=list(compliance_data['mobile'].values()),
                names=list(compliance_data['mobile'].keys()),
                title="Mobile Device Compliance Status"
            )
            st.plotly_chart(fig, use_container_width=True)

def show_attack_simulation():
    """Attack simulation and testing interface"""
    st.header("⚔️ Attack Simulation & Penetration Testing")
    
    st.warning("⚠️ **WARNING**: Attack simulations should only be run in authorized testing environments!")
    
    # Simulation controls
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Simulation Categories")
        
        simulation_types = {
            "Ransomware Simulation": {
                "description": "Simulate ransomware behavior patterns",
                "attacks": ["File Encryption Simulation", "Registry Modification", "Network Share Encryption"]
            },
            "Network Intrusion": {
                "description": "Test network security defenses",
                "attacks": ["Port Scanning", "DDoS Simulation", "Man-in-the-Middle"]
            },
            "Endpoint Attacks": {
                "description": "Test endpoint protection systems",
                "attacks": ["Malware Simulation", "Process Injection", "Privilege Escalation"]
            },
            "Social Engineering": {
                "description": "Test human factor security",
                "attacks": ["Phishing Simulation", "USB Drop Attack", "Physical Breach"]
            },
            "Advanced Persistent Threats": {
                "description": "Multi-stage attack campaigns",
                "attacks": ["Lateral Movement", "Data Exfiltration", "Command & Control"]
            }
        }
        
        selected_category = st.selectbox("Select Attack Category", list(simulation_types.keys()))
        
        if selected_category:
            st.write(f"**Description**: {simulation_types[selected_category]['description']}")
            selected_attack = st.selectbox("Select Specific Attack", simulation_types[selected_category]['attacks'])
    
    with col2:
        st.subheader("⚙️ Simulation Parameters")
        
        # Target selection
        target_environment = st.selectbox(
            "Target Environment",
            ["Test Network", "Isolated Lab", "Sandbox Environment"]
        )
        
        intensity_level = st.slider("Attack Intensity", 1, 10, 5)
        duration = st.selectbox("Duration", ["1 minute", "5 minutes", "15 minutes", "30 minutes"])
        
        # Safety settings
        safe_mode = st.checkbox("Safe Mode (No actual system changes)", value=True)
        log_everything = st.checkbox("Detailed Logging", value=True)
        auto_cleanup = st.checkbox("Auto-cleanup after simulation", value=True)
    
    # Start simulation
    if st.button("🚀 Start Attack Simulation"):
        if not safe_mode:
            if not st.checkbox("I understand this will make actual system changes"):
                st.error("Please acknowledge the risks before proceeding without safe mode")
                return
        
        with st.spinner(f"Running {selected_attack} simulation..."):
            simulation_results = st.session_state.attack_simulator.run_simulation(
                category=selected_category,
                attack_type=selected_attack,
                target=target_environment,
                intensity=intensity_level,
                duration=duration,
                safe_mode=safe_mode
            )
            
            # Display results
            st.success("✅ Simulation completed successfully!")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📊 Detection Results")
                st.write(f"**Attacks Launched**: {simulation_results['attacks_launched']}")
                st.write(f"**Attacks Detected**: {simulation_results['attacks_detected']}")
                detection_rate = (simulation_results['attacks_detected'] / simulation_results['attacks_launched']) * 100
                st.metric("Detection Rate", f"{detection_rate:.1f}%")
                
                if simulation_results['missed_attacks']:
                    st.write("**Missed Attacks:**")
                    for missed in simulation_results['missed_attacks']:
                        st.write(f"• {missed}")
            
            with col2:
                st.subheader("🕒 Response Times")
                st.write(f"**Average Detection Time**: {simulation_results['avg_detection_time']}")
                st.write(f"**Fastest Response**: {simulation_results['fastest_response']}")
                st.write(f"**Slowest Response**: {simulation_results['slowest_response']}")
                
                if simulation_results['response_actions']:
                    st.write("**Automated Responses Triggered:**")
                    for action in simulation_results['response_actions']:
                        st.write(f"• {action}")
    
    # Penetration testing results
    st.subheader("🔍 Previous Simulation Results")
    
    simulation_history = st.session_state.attack_simulator.get_simulation_history()
    
    if simulation_history:
        df = pd.DataFrame(simulation_history)
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            avg_detection = df['detection_rate'].mean()
            st.metric("Average Detection Rate", f"{avg_detection:.1f}%")
        
        with col2:
            total_simulations = len(df)
            st.metric("Total Simulations", total_simulations)
        
        with col3:
            successful_blocks = df['attacks_blocked'].sum()
            st.metric("Total Attacks Blocked", successful_blocks)
        
        with col4:
            avg_response_time = df['avg_response_time'].mean()
            st.metric("Avg Response Time", f"{avg_response_time:.1f}s")
        
        # Detection rate trend
        fig = px.line(
            df,
            x='timestamp',
            y='detection_rate',
            title="Detection Rate Trend Over Time"
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Detailed results table
        st.dataframe(df, use_container_width=True)

def show_analytics_reports():
    """Analytics and reporting interface"""
    st.header("📈 Security Analytics & Reporting")
    
    # Report type selection
    col1, col2, col3 = st.columns(3)
    
    with col1:
        report_type = st.selectbox(
            "Report Type",
            ["Executive Summary", "Technical Analysis", "Compliance Report", "Threat Intelligence", "Custom Report"]
        )
    
    with col2:
        time_period = st.selectbox(
            "Time Period",
            ["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days", "Custom Range"]
        )
    
    with col3:
        if st.button("📊 Generate Report"):
            generate_security_report(report_type, time_period)
    
    # Key metrics dashboard
    st.subheader("🎯 Key Security Metrics")
    
    metrics = st.session_state.data_processor.get_security_metrics()
    
    # Top-level KPIs
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Mean Time to Detection (MTTD)", f"{metrics['mttd']:.1f}m", delta=f"{metrics['mttd_trend']:+.1f}m")
    
    with col2:
        st.metric("Mean Time to Response (MTTR)", f"{metrics['mttr']:.1f}m", delta=f"{metrics['mttr_trend']:+.1f}m")
    
    with col3:
        st.metric("Security Score", f"{metrics['security_score']:.1f}/10", delta=f"{metrics['score_trend']:+.1f}")
    
    with col4:
        st.metric("Threat Volume", metrics['threat_volume'], delta=f"{metrics['volume_trend']:+d}")
    
    with col5:
        st.metric("False Positive Rate", f"{metrics['false_positive_rate']:.1%}", delta=f"{metrics['fp_trend']:+.1%}")
    
    # Advanced analytics
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔥 Threat Heatmap")
        threat_heatmap = st.session_state.data_processor.get_threat_heatmap()
        
        if threat_heatmap:
            fig = px.imshow(
                threat_heatmap['data'],
                x=threat_heatmap['hours'],
                y=threat_heatmap['days'],
                title="Threat Activity Heatmap (24h x 7 days)"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("📊 Attack Vector Analysis")
        attack_vectors = st.session_state.data_processor.get_attack_vector_analysis()
        
        if attack_vectors:
            fig = px.treemap(
                values=list(attack_vectors.values()),
                names=list(attack_vectors.keys()),
                title="Attack Vectors Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Threat intelligence integration
    st.subheader("🌍 Threat Intelligence Dashboard")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Global Threat Landscape**")
        global_threats = st.session_state.threat_intel.get_global_threats()
        
        if global_threats:
            for threat in global_threats[:5]:
                severity_emoji = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(threat['severity'], '⚪')
                
                st.write(f"{severity_emoji} **{threat['name']}**")
                st.write(f"First Seen: {threat['first_seen']}")
                st.write(f"Affected Systems: {threat['affected_systems']}")
                st.write("---")
    
    with col2:
        st.write("**IOC Feed**")
        iocs = st.session_state.threat_intel.get_latest_iocs()
        
        if iocs:
            df_iocs = pd.DataFrame(iocs)
            st.dataframe(df_iocs, use_container_width=True)
    
    # Predictive analytics
    st.subheader("🔮 Predictive Threat Analysis")
    
    predictions = st.session_state.ai_analyzer.get_threat_predictions()
    
    if predictions:
        col1, col2 = st.columns(2)
        
        with col1:
            # Threat forecast
            fig = px.line(
                x=predictions['dates'],
                y=predictions['predicted_threats'],
                title="Predicted Threat Volume (Next 7 Days)"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk assessment
            st.write("**Predicted High-Risk Periods:**")
            for period in predictions['high_risk_periods']:
                st.write(f"• {period['date']}: {period['risk_level']} risk ({period['confidence']:.1%} confidence)")

def show_system_configuration():
    """System configuration interface"""
    st.header("⚙️ System Configuration & Settings")
    
    # Configuration tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔧 General Settings", "🤖 AI Models", "🔗 Integrations", "👥 User Management"])
    
    with tab1:
        st.subheader("General System Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Detection Settings**")
            global_sensitivity = st.slider("Global Detection Sensitivity", 0.1, 1.0, 0.7, 0.1)
            auto_response = st.checkbox("Enable Automatic Response", value=True)
            quarantine_malware = st.checkbox("Auto-quarantine Malware", value=True)
            block_malicious_ips = st.checkbox("Auto-block Malicious IPs", value=True)
            
            st.write("**Alert Settings**")
            email_alerts = st.checkbox("Email Alerts", value=True)
            sms_alerts = st.checkbox("SMS Alerts", value=False)
            webhook_alerts = st.checkbox("Webhook Alerts", value=True)
            
            if email_alerts:
                alert_email = st.text_input("Alert Email", value="admin@company.com")
            
            if webhook_alerts:
                webhook_url = st.text_input("Webhook URL", value="https://your-webhook-url.com")
        
        with col2:
            st.write("**Logging & Retention**")
            log_level = st.selectbox("Log Level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
            retention_days = st.number_input("Log Retention (days)", min_value=1, max_value=365, value=90)
            
            st.write("**Performance Settings**")
            max_concurrent_scans = st.number_input("Max Concurrent Scans", min_value=1, max_value=10, value=3)
            scan_timeout = st.number_input("Scan Timeout (minutes)", min_value=1, max_value=60, value=15)
            
            st.write("**Backup & Recovery**")
            if st.button("🔄 Backup Configuration"):
                st.success("Configuration backed up successfully")
            
            if st.button("📥 Export Logs"):
                st.success("Logs exported successfully")
    
    with tab2:
        st.subheader("AI Model Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Model Performance**")
            model_stats = st.session_state.ai_analyzer.get_model_statistics()
            
            st.metric("Detection Accuracy", f"{model_stats['accuracy']:.1%}")
            st.metric("False Positive Rate", f"{model_stats['false_positive_rate']:.1%}")
            st.metric("Model Training Date", model_stats['last_trained'])
            
            if st.button("🔄 Retrain Models"):
                with st.spinner("Retraining AI models..."):
                    st.session_state.ai_analyzer.retrain_models()
                    st.success("Models retrained successfully")
        
        with col2:
            st.write("**Model Selection**")
            
            available_models = ["Random Forest", "Isolation Forest", "LSTM", "Ensemble"]
            selected_models = st.multiselect("Active Models", available_models, default=available_models)
            
            st.write("**Model Parameters**")
            ensemble_weight = st.slider("Ensemble Weight", 0.1, 1.0, 0.8, 0.1)
            confidence_threshold = st.slider("Confidence Threshold", 0.1, 1.0, 0.7, 0.1)
            
            if st.button("💾 Save Model Configuration"):
                st.session_state.ai_analyzer.update_model_config(selected_models, ensemble_weight, confidence_threshold)
                st.success("Model configuration saved")
    
    with tab3:
        st.subheader("External Integrations")
        
        st.write("**Threat Intelligence Feeds**")
        
        # API configurations
        integrations = {
            "VirusTotal": {"enabled": True, "api_key": "vt_api_key"},
            "Shodan": {"enabled": False, "api_key": "shodan_api_key"},
            "IBM X-Force": {"enabled": False, "api_key": "xforce_api_key"},
            "OTX AlienVault": {"enabled": True, "api_key": "otx_api_key"},
            "Malware Bazaar": {"enabled": True, "api_key": ""},
        }
        
        for service, config in integrations.items():
            col1, col2, col3 = st.columns([1, 2, 1])
            
            with col1:
                enabled = st.checkbox(service, value=config["enabled"])
            
            with col2:
                if config["api_key"]:
                    api_key = st.text_input(f"{service} API Key", type="password", 
                                          value=os.getenv(config["api_key"], ""))
            
            with col3:
                if st.button(f"Test {service}"):
                    if enabled:
                        test_result = st.session_state.threat_intel.test_integration(service)
                        if test_result:
                            st.success("✅")
                        else:
                            st.error("❌")
        
        st.write("**SIEM Integration**")
        siem_type = st.selectbox("SIEM Platform", ["Splunk", "QRadar", "ArcSight", "LogRhythm", "Custom"])
        siem_endpoint = st.text_input("SIEM Endpoint URL")
        siem_auth = st.text_input("Authentication Token", type="password")
        
        if st.button("🔗 Test SIEM Connection"):
            st.success("SIEM connection test successful")
    
    with tab4:
        st.subheader("User Management & Access Control")
        
        # User roles and permissions
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**User Roles**")
            
            roles = {
                "Security Admin": ["Full access", "User management", "System configuration"],
                "Security Analyst": ["View dashboards", "Manage alerts", "Run scans"],
                "Incident Responder": ["View alerts", "Respond to incidents", "Access logs"],
                "Auditor": ["Read-only access", "Generate reports", "View configurations"]
            }
            
            for role, permissions in roles.items():
                with st.expander(f"👤 {role}"):
                    for permission in permissions:
                        st.write(f"• {permission}")
        
        with col2:
            st.write("**Active Users**")
            
            users = [
                {"name": "Admin User", "role": "Security Admin", "last_login": "2024-08-24 10:30"},
                {"name": "John Analyst", "role": "Security Analyst", "last_login": "2024-08-24 09:15"},
                {"name": "Jane Responder", "role": "Incident Responder", "last_login": "2024-08-23 16:45"}
            ]
            
            for user in users:
                st.write(f"**{user['name']}** - {user['role']}")
                st.write(f"Last Login: {user['last_login']}")
                st.write("---")
        
        # Add new user
        st.write("**Add New User**")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            new_username = st.text_input("Username")
        with col2:
            new_email = st.text_input("Email")
        with col3:
            new_role = st.selectbox("Role", list(roles.keys()))
        
        if st.button("➕ Add User"):
            if new_username and new_email:
                st.success(f"User {new_username} added successfully")

def generate_security_report(report_type, time_period):
    """Generate comprehensive security reports"""
    with st.spinner(f"Generating {report_type} for {time_period}..."):
        # Simulate report generation
        time.sleep(2)
        
        st.success(f"✅ {report_type} generated successfully!")
        
        # Executive Summary Report
        if report_type == "Executive Summary":
            st.subheader("📋 Executive Security Summary")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Key Highlights:**")
                st.write("• 347 security events processed")
                st.write("• 23 threats detected and mitigated")
                st.write("• 99.3% system uptime maintained")
                st.write("• 2.1% false positive rate achieved")
            
            with col2:
                st.write("**Risk Assessment:**")
                st.write("• Overall Risk Level: Medium")
                st.write("• Critical Vulnerabilities: 2")
                st.write("• Compliance Score: 94%")
                st.write("• Recommended Actions: 5")
        
        # Technical Analysis Report
        elif report_type == "Technical Analysis":
            st.subheader("🔧 Technical Security Analysis")
            
            # Threat distribution
            threat_data = {
                'Malware': 45,
                'Phishing': 23, 
                'Network Intrusion': 15,
                'Data Exfiltration': 8,
                'Privilege Escalation': 5,
                'Other': 4
            }
            
            fig = px.bar(
                x=list(threat_data.keys()),
                y=list(threat_data.values()),
                title="Threat Types Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Download report
        if st.button("📥 Download Report"):
            st.success("Report downloaded to your system")

def start_background_monitoring():
    """Start background monitoring processes"""
    def monitor_loop():
        while st.session_state.get('monitoring_active', False):
            try:
                # Run monitoring checks
                st.session_state.network_monitor.run_continuous_monitoring()
                st.session_state.endpoint_monitor.run_continuous_monitoring()
                st.session_state.iot_monitor.run_continuous_monitoring()
                st.session_state.mobile_monitor.run_continuous_monitoring()
                
                # Sleep for 30 seconds before next check
                time.sleep(30)
            except Exception as e:
                print(f"Background monitoring error: {e}")
                break
    
    # Start monitoring thread
    if not hasattr(st.session_state, 'monitoring_thread'):
        st.session_state.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        st.session_state.monitoring_thread.start()

if __name__ == "__main__":
    main()
