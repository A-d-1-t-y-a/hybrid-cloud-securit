import streamlit as st
import pandas as pd
import plotly.express as px
from services.api_client import SecurityFrameworkAPIClient

def show_security_monitoring(api_client: SecurityFrameworkAPIClient):
    st.title("Security Monitoring & SIEM")
    
    # Refresh button
    if st.button("Refresh", key="refresh_monitoring", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # Security Metrics
    dashboard_result = api_client.get_security_dashboard_data()
    
    if dashboard_result["success"]:
        data = dashboard_result["data"]
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Events", data.get("total_events", 0))
        
        with col2:
            st.metric("Critical Events", data.get("critical_events", 0))
        
        with col3:
            st.metric("High Severity", data.get("high_severity_events", 0))
        
        with col4:
            st.metric("Recent (24h)", data.get("recent_events", 0))
    else:
        st.warning("Unable to load security metrics")
    
    st.markdown("---")
    
    # Severity Distribution Chart
    st.subheader("Threat Level Distribution")
    
    col1, col2 = st.columns(2)
    
    with col1:
        severity_result = api_client.get_severity_distribution()
        
        if severity_result["success"] and severity_result["data"]:
            severity_data = severity_result["data"]
            
            df_severity = pd.DataFrame([
                {"Severity": k, "Count": v} for k, v in severity_data.items() if v > 0
            ])
            
            if not df_severity.empty:
                fig = px.pie(df_severity, values="Count", names="Severity",
                            title="Events by Severity",
                            color_discrete_sequence=px.colors.qualitative.Set3)
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='white'
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No severity data available")
        else:
            st.info("Unable to load severity distribution")
    
    with col2:
        sources_result = api_client.get_event_sources()
        
        if sources_result["success"] and sources_result["data"].get("sources"):
            sources = sources_result["data"]["sources"]
            
            df_sources = pd.DataFrame(sources, columns=["Source", "Count"])
            
            fig = px.bar(df_sources, x="Source", y="Count",
                        title="Top Event Sources",
                        color_discrete_sequence=["#636EFA"])
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No event source data available")
    
    st.markdown("---")
    
    # Security Events Table
    st.subheader("Recent Security Events")
    
    # Create Event Button
    if st.button("Create Security Event"):
        st.session_state.show_create_event = True
    
    # Create Event Form
    if st.session_state.get('show_create_event', False):
        with st.form("event_form"):
            st.markdown("### Create New Security Event")
            
            col1, col2 = st.columns(2)
            with col1:
                event_type = st.selectbox("Event Type*", 
                    ["Login Attempt", "Data Access", "System Alert", "Network Anomaly", "Unauthorized Access"])
                source = st.text_input("Source*", placeholder="e.g., Firewall, IDS, Application")
            
            with col2:
                severity = st.selectbox("Severity*", ["Low", "Medium", "High", "Critical"])
                description = st.text_area("Description*", placeholder="Event description...")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Create Event", use_container_width=True):
                    if event_type and source and severity and description:
                        event_data = {
                            "event_type": event_type,
                            "source": source,
                            "severity": severity,
                            "description": description
                        }
                        
                        result = api_client.ingest_security_event(event_data)
                        
                        if result["success"]:
                            st.success("Event created successfully!")
                            st.session_state.show_create_event = False
                            st.rerun()
                        else:
                            st.error(f"Error: {result.get('error', 'Failed to create event')}")
                    else:
                        st.error("Please fill in all required fields")
            
            with col2:
                if st.form_submit_button("Cancel", use_container_width=True):
                    st.session_state.show_create_event = False
                    st.rerun()
    
    # Display Events
    events_result = api_client.get_security_events()
    
    if events_result["success"]:
        events = events_result.get("data", [])
        
        if isinstance(events, list) and len(events) > 0:
            df_events = pd.DataFrame(events)
            
            # Select relevant columns
            display_cols = [col for col in ["event_id", "severity", "event_type", "source", "description", "timestamp"] 
                          if col in df_events.columns]
            
            if display_cols:
                st.dataframe(df_events[display_cols], use_container_width=True, hide_index=True)
            else:
                st.dataframe(df_events, use_container_width=True, hide_index=True)
        else:
            st.info("No security events found. Create your first event above.")
    else:
        st.error(f"Failed to load events: {events_result.get('error', 'Unknown error')}")


def show_incident_response(api_client: SecurityFrameworkAPIClient):
    st.title("Incident Response & SOAR")
    
    # Refresh button
    if st.button("Refresh", key="refresh_incident", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # Incident Metrics
    dashboard_result = api_client.get_security_dashboard_data()
    threat_result = api_client.get_threat_summary()
    workflows_result = api_client.get_soar_workflows()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if dashboard_result["success"]:
            critical = dashboard_result["data"].get("critical_events", 0)
            high = dashboard_result["data"].get("high_severity_events", 0)
            st.metric("Active Incidents", critical + high)
        else:
            st.metric("Active Incidents", "N/A")
    
    with col2:
        if workflows_result["success"] and workflows_result["data"] and isinstance(workflows_result["data"], list):
            active_count = len([w for w in workflows_result["data"] if isinstance(w, dict) and w.get("status") == "active"])
            st.metric("Active Workflows", active_count)
        else:
            st.metric("Active Workflows", 0)
    
    with col3:
        if threat_result["success"]:
            score = threat_result["data"].get("security_score", 0)
            st.metric("Security Score", f"{score:.1f}%")
        else:
            st.metric("Security Score", "N/A")
    
    with col4:
        if threat_result["success"]:
            threats = threat_result["data"].get("total_threats", 0)
            st.metric("Total Threats", threats)
        else:
            st.metric("Total Threats", "N/A")
    
    st.markdown("---")
    
    # High-Severity Incidents
    st.subheader("High-Severity Incidents")
    
    events_result = api_client.get_security_events()
    
    if events_result["success"]:
        events = events_result.get("data", [])
        
        if isinstance(events, list) and len(events) > 0:
            # Filter for high and critical severity
            incidents = [e for e in events if isinstance(e, dict) and e.get("severity", "").lower() in ["high", "critical"]]
            
            if incidents:
                df_incidents = pd.DataFrame(incidents)
                display_cols = [col for col in ["event_id", "severity", "event_type", "source", "description", "timestamp"] 
                              if col in df_incidents.columns]
                
                if display_cols:
                    st.dataframe(df_incidents[display_cols], use_container_width=True, hide_index=True)
                else:
                    st.dataframe(df_incidents, use_container_width=True, hide_index=True)
            else:
                st.info("No high-severity incidents found")
        else:
            st.info("No security events available. Create events in the Security Monitoring section.")
    else:
        st.error(f"Failed to load incidents: {events_result.get('error', 'Unknown error')}")
    
    st.markdown("---")
    
    # SOAR Workflows
    st.subheader("SOAR Workflows")
    
    # Create Workflow Button
    if st.button("Create Workflow"):
        st.session_state.show_create_workflow = True
    
    # Create Workflow Form
    if st.session_state.get('show_create_workflow', False):
        with st.form("workflow_form"):
            st.markdown("### Create New Workflow")
            
            col1, col2 = st.columns(2)
            with col1:
                workflow_name = st.text_input("Workflow Name*")
                trigger_event = st.selectbox("Trigger Event*", 
                    ["High Severity Alert", "Data Breach", "Unauthorized Access", "System Anomaly", "Malware Detection"])
            
            with col2:
                actions = st.multiselect("Actions*", 
                    ["Block IP", "Notify Team", "Isolate Host", "Generate Report", "Update Firewall", "Quarantine File"])
                status = st.selectbox("Status", ["active", "inactive"])
            
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Create Workflow", use_container_width=True):
                    if workflow_name and trigger_event and actions:
                        workflow_data = {
                            "name": workflow_name,
                            "trigger_event": trigger_event,
                            "actions": actions,
                            "status": status
                        }
                        
                        result = api_client.create_soar_workflow(workflow_data)
                        
                        if result["success"]:
                            st.success("Workflow created successfully!")
                            st.session_state.show_create_workflow = False
                            st.rerun()
                        else:
                            st.error(f"Error: {result.get('error', 'Failed to create workflow')}")
                    else:
                        st.error("Please fill in all required fields")
            
            with col2:
                if st.form_submit_button("Cancel", use_container_width=True):
                    st.session_state.show_create_workflow = False
                    st.rerun()
    
    # Display Workflows
    if workflows_result["success"]:
        workflows = workflows_result.get("data", [])
        
        if isinstance(workflows, list) and len(workflows) > 0:
            df_workflows = pd.DataFrame(workflows)
            
            display_cols = [col for col in ["workflow_id", "name", "trigger_event", "actions", "status", "created_at"] 
                          if col in df_workflows.columns]
            
            if display_cols:
                st.dataframe(df_workflows[display_cols], use_container_width=True, hide_index=True)
            else:
                st.dataframe(df_workflows, use_container_width=True, hide_index=True)
        else:
            st.info("No workflows found. Create your first workflow above.")
    else:
        st.error(f"Failed to load workflows: {workflows_result.get('error', 'Unknown error')}")
