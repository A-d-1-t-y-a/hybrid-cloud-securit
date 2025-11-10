import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from services.api_client import SecurityFrameworkAPIClient

def show_compliance_management(api_client: SecurityFrameworkAPIClient):
    st.title("Compliance & Governance")
    
    # Refresh button
    if st.button("Refresh", key="refresh_compliance", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # Compliance Status Overview
    st.subheader("Compliance Status Overview")
    
    compliance_result = api_client.get_compliance_status_overview()
    
    if compliance_result["success"]:
        compliance_data = compliance_result["data"]
        
        # Key Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            overall_score = compliance_data.get("overall_score", 0)
            st.metric("Overall Compliance", f"{overall_score}%")
        
        with col2:
            standards_count = len(compliance_data.get("standards", {}))
            st.metric("Standards Tracked", standards_count)
        
        with col3:
            if "standards" in compliance_data:
                compliant = sum(1 for s in compliance_data["standards"].values() if s.get("score", 0) >= 90)
                st.metric("Compliant Standards", compliant)
            else:
                st.metric("Compliant Standards", 0)
        
        with col4:
            if "standards" in compliance_data:
                non_compliant = sum(1 for s in compliance_data["standards"].values() if s.get("score", 0) < 90)
                st.metric("Non-Compliant", non_compliant)
            else:
                st.metric("Non-Compliant", 0)
        
        st.markdown("---")
        
        # Compliance by Standard
        if "standards" in compliance_data and compliance_data["standards"]:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Compliance Scores by Standard**")
                
                standards_list = []
                for std_name, std_data in compliance_data["standards"].items():
                    standards_list.append({
                        "Standard": std_name,
                        "Score": std_data.get("score", 0)
                    })
                
                df_standards = pd.DataFrame(standards_list)
                
                fig = px.bar(df_standards, x="Standard", y="Score",
                            color="Score",
                            color_continuous_scale=["#ff4444", "#ffaa00", "#44ff44"],
                            range_color=[0, 100])
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='white',
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("**Compliance Status Details**")
                
                status_data = []
                for std_name, std_data in compliance_data["standards"].items():
                    score = std_data.get("score", 0)
                    status_data.append({
                        "Standard": std_name,
                        "Score": f"{score}%",
                        "Status": "Compliant" if score >= 90 else "At Risk" if score >= 70 else "Non-Compliant"
                    })
                
                df_status = pd.DataFrame(status_data)
                st.dataframe(df_status, use_container_width=True, hide_index=True)
        else:
            st.info("No compliance standards data available")
    else:
        st.error(f"Failed to load compliance status: {compliance_result.get('error', 'Unknown error')}")
    
    st.markdown("---")
    
    # Policy Management
    st.subheader("Policy Management")
    
    policies_result = api_client.get_compliance_policies_list()
    
    if policies_result["success"]:
        policies = policies_result.get("data", [])
        
        if isinstance(policies, list) and len(policies) > 0:
            # Policy Metrics
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Policies", len(policies))
            
            with col2:
                active_count = sum(1 for p in policies if p.get("is_active", True))
                st.metric("Active Policies", active_count)
            
            with col3:
                inactive_count = len(policies) - active_count
                st.metric("Inactive Policies", inactive_count)
            
            st.markdown("---")
            
            # Policies Table
            df_policies = pd.DataFrame(policies)
            
            # Select relevant columns
            display_cols = [col for col in ["policy_id", "name", "framework", "description", "is_active", "created_at"] 
                          if col in df_policies.columns]
            
            if display_cols:
                st.dataframe(df_policies[display_cols], use_container_width=True, hide_index=True)
            else:
                st.dataframe(df_policies, use_container_width=True, hide_index=True)
            
            st.markdown("---")
            
            # Policy Distribution by Framework
            if "framework" in df_policies.columns:
                st.markdown("**Policy Distribution by Framework**")
                
                framework_counts = df_policies["framework"].value_counts().reset_index()
                framework_counts.columns = ["Framework", "Count"]
                
                fig = px.pie(framework_counts, values="Count", names="Framework",
                            title="Policies by Framework")
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='white'
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No policies found. Policies will be created based on compliance requirements.")
    else:
        st.error(f"Failed to load policies: {policies_result.get('error', 'Unknown error')}")


def show_risk_management(api_client: SecurityFrameworkAPIClient):
    st.title("Risk Management & Assessment")
    
    # Refresh button
    if st.button("Refresh", key="refresh_risk", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # Risk Overview
    st.subheader("Risk Overview")
    
    # Get security events and severity data
    events_result = api_client.get_security_events()
    severity_result = api_client.get_severity_distribution()
    threat_result = api_client.get_threat_summary()
    
    # Risk Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if severity_result["success"]:
            severity_data = severity_result["data"]
            critical_high = severity_data.get("Critical", 0) + severity_data.get("High", 0)
            st.metric("Critical/High Risks", critical_high)
        else:
            st.metric("Critical/High Risks", "N/A")
    
    with col2:
        if severity_result["success"]:
            medium = severity_data.get("Medium", 0)
            st.metric("Medium Risks", medium)
        else:
            st.metric("Medium Risks", "N/A")
    
    with col3:
        if severity_result["success"]:
            low = severity_data.get("Low", 0) + severity_data.get("Info", 0)
            st.metric("Low Risks", low)
        else:
            st.metric("Low Risks", "N/A")
    
    with col4:
        if threat_result["success"]:
            security_score = threat_result["data"].get("security_score", 0)
            st.metric("Security Score", f"{security_score:.1f}%")
        else:
            st.metric("Security Score", "N/A")
    
    st.markdown("---")
    
    # Risk Distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Risk Distribution by Severity**")
        
        if severity_result["success"] and severity_result["data"]:
            severity_data = severity_result["data"]
            
            # Filter out zero values
            filtered_data = {k: v for k, v in severity_data.items() if v > 0}
            
            if filtered_data:
                df_severity = pd.DataFrame([
                    {"Severity": k, "Count": v} for k, v in filtered_data.items()
                ])
                
                # Define colors for severity levels
                color_map = {
                    "Critical": "#ff0000",
                    "High": "#ff6600",
                    "Medium": "#ffaa00",
                    "Low": "#ffff00",
                    "Info": "#00ff00"
                }
                
                colors = [color_map.get(s, "#888888") for s in df_severity["Severity"]]
                
                fig = px.pie(df_severity, values="Count", names="Severity",
                            color_discrete_sequence=colors)
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='white'
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No risk data available")
        else:
            st.info("Risk distribution data unavailable")
    
    with col2:
        st.markdown("**Risk Summary**")
        
        if severity_result["success"]:
            severity_data = severity_result["data"]
            
            summary_data = {
                "Risk Level": ["Critical", "High", "Medium", "Low", "Info"],
                "Count": [
                    severity_data.get("Critical", 0),
                    severity_data.get("High", 0),
                    severity_data.get("Medium", 0),
                    severity_data.get("Low", 0),
                    severity_data.get("Info", 0)
                ],
                "Priority": ["Immediate", "High", "Medium", "Low", "Informational"]
            }
            
            df_summary = pd.DataFrame(summary_data)
            st.dataframe(df_summary, use_container_width=True, hide_index=True)
        else:
            st.info("Risk summary unavailable")
    
    st.markdown("---")
    
    # High-Priority Risks
    st.subheader("High-Priority Risks")
    
    if events_result["success"]:
        events = events_result.get("data", [])
        
        if isinstance(events, list) and len(events) > 0:
            # Filter for high and critical severity
            high_risks = [e for e in events if isinstance(e, dict) and e.get("severity", "").lower() in ["high", "critical"]]
            
            if high_risks:
                df_risks = pd.DataFrame(high_risks)
                
                display_cols = [col for col in ["event_id", "severity", "event_type", "source", "description", "timestamp"] 
                              if col in df_risks.columns]
                
                if display_cols:
                    st.dataframe(df_risks[display_cols], use_container_width=True, hide_index=True)
                else:
                    st.dataframe(df_risks, use_container_width=True, hide_index=True)
            else:
                st.info("No high-priority risks identified")
        else:
            st.info("No risk events available. Create security events in the Security Monitoring section.")
    else:
        st.error(f"Failed to load risk data: {events_result.get('error', 'Unknown error')}")
    
    st.markdown("---")
    
    # Risk Mitigation
    st.subheader("Risk Mitigation Strategies")
    
    workflows_result = api_client.get_soar_workflows()
    
    if workflows_result["success"]:
        workflows = workflows_result.get("data", [])
        
        if isinstance(workflows, list) and len(workflows) > 0:
            # Mitigation Metrics
            col1, col2, col3 = st.columns(3)
            
            with col1:
                active_workflows = len([w for w in workflows if isinstance(w, dict) and w.get("status") == "active"])
                st.metric("Active Workflows", active_workflows)
            
            with col2:
                total_workflows = len(workflows)
                mitigation_rate = int((active_workflows / total_workflows * 100)) if total_workflows > 0 else 0
                st.metric("Mitigation Coverage", f"{mitigation_rate}%")
            
            with col3:
                st.metric("Total Strategies", total_workflows)
            
            st.markdown("---")
            
            # Mitigation Strategies Table
            mitigation_data = []
            for workflow in workflows:
                if isinstance(workflow, dict):
                    mitigation_data.append({
                        "Workflow": workflow.get("name", "Unnamed"),
                        "Trigger": workflow.get("trigger_event", "N/A"),
                        "Actions": ", ".join(workflow.get("actions", [])) if workflow.get("actions") else "No actions",
                        "Status": workflow.get("status", "unknown").capitalize()
                    })
            
            if mitigation_data:
                df_mitigation = pd.DataFrame(mitigation_data)
                st.dataframe(df_mitigation, use_container_width=True, hide_index=True)
        else:
            st.info("No mitigation strategies found. Create SOAR workflows in the Security Monitoring section.")
    else:
        st.error(f"Failed to load mitigation strategies: {workflows_result.get('error', 'Unknown error')}")
