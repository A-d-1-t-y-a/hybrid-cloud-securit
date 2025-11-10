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
        
        # Get dynamic dashboard data
        dashboard_result = api_client.get_security_dashboard_data()
        
        if dashboard_result["success"]:
            dashboard_data = dashboard_result["data"]
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Events", dashboard_data.get("total_events", 0))
            
            with col2:
                st.metric("Critical Events", dashboard_data.get("critical_events", 0))
            
            with col3:
                st.metric("High Severity", dashboard_data.get("high_severity_events", 0))
            
            with col4:
                st.metric("Recent Events (24h)", dashboard_data.get("recent_events", 0))
        else:
            st.warning("Dashboard metrics unavailable")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Threat Level Distribution**")
            severity_result = api_client.get_severity_distribution()
            
            if severity_result["success"]:
                severity_data = severity_result["data"]
                if severity_data:
                    df_threats = pd.DataFrame([
                        {"Level": k, "Count": v} for k, v in severity_data.items()
                    ])
                    fig = px.pie(df_threats, values="Count", names="Level", 
                                color_discrete_sequence=px.colors.qualitative.Set3)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No severity data available")
            else:
                st.info("No severity distribution data")
        
        with col2:
            st.markdown("**Security Events Timeline")
            timeline_result = api_client.get_security_timeline(days=7)
            
            if timeline_result["success"] and timeline_result["data"]["timeline"]:
                timeline_data = timeline_result["data"]["timeline"]
                df_events = pd.DataFrame(timeline_data)
                df_events['date'] = pd.to_datetime(df_events['date'])
                
                fig = px.line(df_events, x='date', y='count', title='Events Over Time')
                fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No timeline data available")
    
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
            sources_result = api_client.get_event_sources()
            
            if sources_result["success"] and sources_result["data"]["sources"]:
                df_sources = pd.DataFrame(sources_result["data"]["sources"])
                df_sources.columns = ["Source", "Events"]
                st.dataframe(df_sources, use_container_width=True, hide_index=True)
            else:
                st.info("No event source data available")
        
        with col2:
            st.markdown("**Security Metrics Summary**")
            dashboard_result = api_client.get_security_dashboard_data()
            
            if dashboard_result["success"]:
                data = dashboard_result["data"]
                metrics_data = {
                    "Metric": ["Total Events", "Critical Events", "High Severity", "Recent (24h)"],
                    "Value": [
                        data.get("total_events", 0),
                        data.get("critical_events", 0),
                        data.get("high_severity_events", 0),
                        data.get("recent_events", 0)
                    ]
                }
                df_metrics = pd.DataFrame(metrics_data)
                st.dataframe(df_metrics, use_container_width=True, hide_index=True)
            else:
                st.info("No metrics data available")
        
        st.markdown("---")
        
        # Get threat summary for additional metrics
        threat_result = api_client.get_threat_summary()
        
        if threat_result["success"]:
            threat_data = threat_result["data"]
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Threats", threat_data.get("total_threats", 0))
            
            with col2:
                st.metric("Security Score", f"{threat_data.get('security_score', 0):.1f}%")
            
            with col3:
                events_result = api_client.get_security_events()
                event_count = len(events_result.get("data", [])) if events_result["success"] else 0
                st.metric("Total Events", event_count)

def show_incident_response(api_client: SecurityFrameworkAPIClient):
    st.title("🚨 Incident Response & SOAR")
    
    tab1, tab2, tab3 = st.tabs(["🎯 Incident Dashboard", "🤖 Automated Workflows", "📋 Response Playbooks"])
    
    with tab1:
        st.subheader("Active Incidents")
        
        # Get high-severity events as incidents
        events_result = api_client.get_security_events()
        
        if events_result["success"] and events_result["data"]:
            events_data = events_result["data"]
            # Filter for high and critical severity
            incidents = [e for e in events_data if e.get("severity", "").lower() in ["high", "critical"]]
            
            if incidents:
                df_incidents = pd.DataFrame(incidents)
                # Select relevant columns
                display_cols = [col for col in ["event_id", "severity", "event_type", "source", "description", "created_at"] if col in df_incidents.columns]
                st.dataframe(df_incidents[display_cols], use_container_width=True, hide_index=True)
            else:
                st.info("No high-severity incidents found")
        else:
            st.info("No incident data available")
        
        st.markdown("---")
        
        # Get metrics from dashboard
        dashboard_result = api_client.get_security_dashboard_data()
        threat_result = api_client.get_threat_summary()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if dashboard_result["success"]:
                critical = dashboard_result["data"].get("critical_events", 0)
                high = dashboard_result["data"].get("high_severity_events", 0)
                st.metric("Active Incidents", critical + high)
            else:
                st.metric("Active Incidents", "N/A")
        
        with col2:
            st.metric("Avg Response Time", "N/A")
        
        with col3:
            if threat_result["success"]:
                score = threat_result["data"].get("security_score", 0)
                st.metric("Security Score", f"{score:.1f}%")
            else:
                st.metric("Security Score", "N/A")
        
        with col4:
            workflows_result = api_client.get_soar_workflows()
            if workflows_result["success"]:
                workflow_count = len(workflows_result.get("data", []))
                st.metric("Active Workflows", workflow_count)
            else:
                st.metric("Active Workflows", "N/A")
    
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
