import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random
from services.api_client import SecurityFrameworkAPIClient

def show_security_monitoring(api_client: SecurityFrameworkAPIClient):
    st.title("🔍 Security Monitoring & SIEM")
    
    tab1, tab2, tab3 = st.tabs(["📊 Security Dashboard", "🚨 Event Management", "📈 Analytics & Reports"])
    
    with tab1:
        st.subheader("Real-time Security Dashboard")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Active Threats", "12", "3 new")
        
        with col2:
            st.metric("Security Events", "1,247", "15%")
        
        with col3:
            st.metric("Blocked Attacks", "89", "8%")
        
        with col4:
            st.metric("Response Time", "2.3s", "-0.5s")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Threat Level Distribution**")
            threat_data = {
                "Level": ["Critical", "High", "Medium", "Low", "Info"],
                "Count": [5, 12, 45, 120, 340]
            }
            df_threats = pd.DataFrame(threat_data)
            fig = px.pie(df_threats, values="Count", names="Level", 
                        color_discrete_sequence=px.colors.qualitative.Set3)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**Security Events Timeline**")
            dates = pd.date_range(start=datetime.now() - timedelta(days=7), end=datetime.now(), freq='H')
            events = [random.randint(0, 50) for _ in range(len(dates))]
            
            df_events = pd.DataFrame({
                'Time': dates,
                'Events': events
            })
            
            fig = px.line(df_events, x='Time', y='Events', title='Events Over Time')
            fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.subheader("Security Event Management")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("**Create Security Event**")
            with st.form("event_form"):
                event_type = st.selectbox("Event Type", ["Login Attempt", "Data Access", "System Alert", "Network Anomaly"])
                source = st.text_input("Source", placeholder="e.g., Firewall, IDS, User")
                severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
                description = st.text_area("Description", placeholder="Event description...")
                
                metadata = st.text_input("Metadata (JSON)", placeholder='{"ip": "192.168.1.1", "user": "admin"}')
                
                if st.form_submit_button("🚨 Create Event", use_container_width=True):
                    event_data = {
                        "event_type": event_type,
                        "source": source,
                        "severity": severity,
                        "description": description,
                        "metadata": metadata if metadata else {}
                    }
                    
                    with st.spinner("Creating event..."):
                        result = api_client.ingest_security_event(event_data)
                    
                    if result["success"]:
                        st.success("✅ Event created successfully!")
                    else:
                        st.error(f"Failed to create event: {result.get('error', 'Unknown error')}")
        
        with col2:
            st.markdown("**Quick Actions**")
            if st.button("🔄 Refresh Events", use_container_width=True):
                st.rerun()
            
            if st.button("📊 Generate Report", use_container_width=True):
                st.info("Report generation started...")
            
            if st.button("🚨 Alert Team", use_container_width=True):
                st.warning("Security team alerted!")
        
        st.markdown("---")
        
        result = api_client.get_security_events()
        if result["success"]:
            events_data = result["data"]
            if isinstance(events_data, list) and len(events_data) > 0:
                df_events = pd.DataFrame(events_data)
                st.dataframe(df_events, use_container_width=True, hide_index=True)
            else:
                st.info("No events found")
        else:
            st.error(f"Failed to load events: {result.get('error', 'Unknown error')}")
    
    with tab3:
        st.subheader("Security Analytics & Reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Top Security Sources**")
            sources_data = {
                "Source": ["Firewall", "IDS", "User Activity", "Network Scanner", "Antivirus"],
                "Events": [450, 320, 280, 150, 120],
                "Threats": [12, 8, 5, 3, 2]
            }
            df_sources = pd.DataFrame(sources_data)
            st.dataframe(df_sources, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**Security Metrics**")
            metrics_data = {
                "Metric": ["Detection Rate", "False Positives", "Response Time", "Coverage"],
                "Value": ["94.5%", "2.1%", "2.3s", "98%"],
                "Trend": ["↗️", "↘️", "↘️", "↗️"]
            }
            df_metrics = pd.DataFrame(metrics_data)
            st.dataframe(df_metrics, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Events (24h)", "1,247", "15%")
        
        with col2:
            st.metric("Threats Detected", "28", "3 new")
        
        with col3:
            st.metric("Response Rate", "98.5%", "2.1%")

def show_incident_response(api_client: SecurityFrameworkAPIClient):
    st.title("🚨 Incident Response & SOAR")
    
    tab1, tab2, tab3 = st.tabs(["🎯 Incident Dashboard", "🤖 Automated Workflows", "📋 Response Playbooks"])
    
    with tab1:
        st.subheader("Active Incidents")
        
        incidents_data = {
            "Incident ID": ["INC-001", "INC-002", "INC-003", "INC-004"],
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Status": ["Open", "Investigating", "Contained", "Resolved"],
            "Source": ["Firewall", "IDS", "User Report", "Automated"],
            "Created": ["2h ago", "4h ago", "1d ago", "2d ago"],
            "Assignee": ["Security Team", "SOC Analyst", "IT Admin", "Automated"]
        }
        
        df_incidents = pd.DataFrame(incidents_data)
        st.dataframe(df_incidents, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Active Incidents", "4", "1 new")
        
        with col2:
            st.metric("Avg Response Time", "15 min", "-5 min")
        
        with col3:
            st.metric("Resolution Rate", "95%", "3%")
        
        with col4:
            st.metric("Automation Rate", "78%", "12%")
    
    with tab2:
        st.subheader("SOAR Workflows")
        
        result = api_client.get_soar_workflows()
        if result["success"]:
            workflows_data = result["data"]
            if isinstance(workflows_data, list) and len(workflows_data) > 0:
                df_workflows = pd.DataFrame(workflows_data)
                st.dataframe(df_workflows, use_container_width=True, hide_index=True)
            else:
                st.info("No workflows found")
        else:
            st.error(f"Failed to load workflows: {result.get('error', 'Unknown error')}")
        
        st.markdown("---")
        
        st.markdown("**Create New Workflow**")
        with st.form("workflow_form"):
            workflow_name = st.text_input("Workflow Name")
            trigger_event = st.selectbox("Trigger Event", ["High Severity Alert", "Data Breach", "Unauthorized Access", "System Anomaly"])
            actions = st.multiselect("Actions", ["Block IP", "Notify Team", "Isolate Host", "Generate Report", "Update Firewall"])
            
            if st.form_submit_button("🤖 Create Workflow", use_container_width=True):
                workflow_data = {
                    "name": workflow_name,
                    "trigger_event": trigger_event,
                    "actions": actions
                }
                
                with st.spinner("Creating workflow..."):
                    result = api_client.create_soar_workflow(workflow_data)
                
                if result["success"]:
                    st.success("✅ Workflow created successfully!")
                else:
                    st.error(f"Failed to create workflow: {result.get('error', 'Unknown error')}")
    
    with tab3:
        st.subheader("Response Playbooks")
        
        playbooks = [
            {
                "Playbook": "Data Breach Response",
                "Severity": "Critical",
                "Steps": "1. Contain breach 2. Assess damage 3. Notify stakeholders 4. Document evidence",
                "Status": "Active"
            },
            {
                "Playbook": "Malware Incident",
                "Severity": "High",
                "Steps": "1. Isolate affected systems 2. Scan for malware 3. Remove threats 4. Update defenses",
                "Status": "Active"
            },
            {
                "Playbook": "Unauthorized Access",
                "Severity": "Medium",
                "Steps": "1. Revoke access 2. Investigate source 3. Strengthen controls 4. Monitor activity",
                "Status": "Active"
            }
        ]
        
        df_playbooks = pd.DataFrame(playbooks)
        st.dataframe(df_playbooks, use_container_width=True, hide_index=True)
