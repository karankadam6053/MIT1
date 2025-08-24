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
# Removed endpoint, IoT, and mobile monitoring modules as requested
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
    st.session_state.data_processor = DataProcessor()
    st.session_state.threat_intel = ThreatIntelligence()

def main():
    st.title("🛡️ AI-Powered Cybersecurity Threat Detection System")
    st.markdown("### Comprehensive Multi-Environment Security Monitoring & Response")
    
    # Sidebar navigation with direct buttons
    st.sidebar.title("🛡️ Security Center")
    
    # Initialize page selection
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "🏠 Dashboard Overview"
    
    # Dashboard & Monitoring section
    st.sidebar.markdown("### 📊 **Dashboard & Monitoring**")
    if st.sidebar.button("🏠 Dashboard Overview", use_container_width=True):
        st.session_state.current_page = "🏠 Dashboard Overview"
    if st.sidebar.button("🎯 Real-Time Threat Detection", use_container_width=True):
        st.session_state.current_page = "🎯 Real-Time Threat Detection"
    if st.sidebar.button("📊 Alert Management", use_container_width=True):
        st.session_state.current_page = "📊 Alert Management"
    
    # Analysis & Investigation section
    st.sidebar.markdown("### 🔍 **Analysis & Investigation**")
    if st.sidebar.button("🔍 Log Analysis", use_container_width=True):
        st.session_state.current_page = "🔍 Log Analysis"
    if st.sidebar.button("📈 Analytics & Reports", use_container_width=True):
        st.session_state.current_page = "📈 Analytics & Reports"
    
    # Protection Systems section
    st.sidebar.markdown("### 🛡️ **Protection Systems**")
    if st.sidebar.button("🌐 Network Security", use_container_width=True):
        st.session_state.current_page = "🌐 Network Security"
    
    # Testing & Configuration section
    st.sidebar.markdown("### ⚔️ **Testing & Configuration**")
    if st.sidebar.button("⚔️ Attack Simulation", use_container_width=True):
        st.session_state.current_page = "⚔️ Attack Simulation"
    if st.sidebar.button("⚙️ System Configuration", use_container_width=True):
        st.session_state.current_page = "⚙️ System Configuration"
    
    # Get current page
    page = st.session_state.current_page
    
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
        if alerts_timeline and alerts_timeline['timestamps'] and alerts_timeline['counts']:
            # Create DataFrame for plotly
            df_timeline = pd.DataFrame({
                'timestamps': alerts_timeline['timestamps'],
                'counts': alerts_timeline['counts']
            })
            fig = px.line(
                df_timeline,
                x='timestamps',
                y='counts',
                title="Alerts Over Time (Last 24h)",
                markers=True
            )
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📈 No alert timeline data available yet")
    
    # Recent threats table
    st.subheader("🔍 Recent Threat Activity")
    if active_threats:
        df = pd.DataFrame(active_threats)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No active threats detected in the current timeframe.")
    
    # Network Security Status
    st.subheader("🌐 Network Security Status")
    col1, col2, col3 = st.columns(3)
    
    network_status = st.session_state.network_monitor.get_status()
    
    with col1:
        st.metric("Monitored Devices", network_status['devices'])
    
    with col2:
        st.metric("Blocked IPs", network_status['blocked_ips'])
    
    with col3:
        st.metric("Active Connections", network_status['total_connections'])

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

# Removed endpoint protection and IoT/mobile security modules as requested

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
        selected_attack = None
        
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
        
        if not selected_attack:
            st.error("Please select an attack type before starting simulation")
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
