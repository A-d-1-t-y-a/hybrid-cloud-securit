import streamlit as st
import pandas as pd
import plotly.express as px
from services.api_client import SecurityFrameworkAPIClient

def show_compliance_management(api_client: SecurityFrameworkAPIClient):
    st.title("📋 Compliance & Governance")
    
    tab1, tab2, tab3 = st.tabs(["📊 Compliance Dashboard", "📋 Policy Management", "📈 Audit & Reporting"])
    
    with tab1:
        st.subheader("Compliance Status Overview")
        
        result = api_client.get_compliance_status_overview()
        if result["success"]:
            compliance_data = result["data"]
            st.json(compliance_data)
        else:
            st.error(f"Failed to load compliance status: {result.get('error', 'Unknown error')}")
        
        st.markdown("---")
        
        # Get compliance data for metrics
        if result["success"] and "standards" in result["data"]:
            standards = result["data"]["standards"]
            
            col1, col2, col3, col4 = st.columns(4)
            
            standard_names = list(standards.keys())[:4]  # Get first 4 standards
            cols = [col1, col2, col3, col4]
            
            for i, (col, std_name) in enumerate(zip(cols, standard_names)):
                with col:
                    score = standards[std_name].get("score", 0)
                    st.metric(f"{std_name} Compliance", f"{score}%")
        else:
            st.info("Compliance metrics unavailable")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Compliance by Standard**")
            
            if result["success"] and "standards" in result["data"]:
                standards = result["data"]["standards"]
                standards_list = []
                
                for std_name, std_data in standards.items():
                    standards_list.append({
                        "Standard": std_name,
                        "Score": std_data.get("score", 0),
                        "Status": "Compliant" if std_data.get("score", 0) >= 90 else "Non-Compliant"
                    })
                
                df_standards = pd.DataFrame(standards_list)
                
                fig = px.bar(df_standards, x="Standard", y="Score", 
                            color="Score", color_continuous_scale="RdYlGn")
                fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No compliance standards data available")
        
        with col2:
            st.markdown("**Compliance Summary**")
            
            if result["success"]:
                overall_score = result["data"].get("overall_score", 0)
                st.metric("Overall Compliance Score", f"{overall_score}%")
                
                if "standards" in result["data"]:
                    standards = result["data"]["standards"]
                    summary_data = []
                    
                    for std_name, std_data in standards.items():
                        summary_data.append({
                            "Standard": std_name,
                            "Score": f"{std_data.get('score', 0)}%",
                            "Status": std_data.get("status", "Unknown")
                        })
                    
                    df_summary = pd.DataFrame(summary_data)
                    st.dataframe(df_summary, use_container_width=True, hide_index=True)
                else:
                    st.info("No detailed compliance data")
            else:
                st.info("Compliance summary unavailable")
    
    with tab2:
        st.subheader("Policy Management")
        
        result = api_client.get_compliance_policies_list()
        if result["success"]:
            policies_data = result["data"]
            if isinstance(policies_data, list) and len(policies_data) > 0:
                df_policies = pd.DataFrame(policies_data)
                st.dataframe(df_policies, use_container_width=True, hide_index=True)
            else:
                st.info("No policies found")
        else:
            st.error(f"Failed to load policies: {result.get('error', 'Unknown error')}")
        
        st.markdown("---")
        
        st.markdown("**Policy Summary**")
        
        if result["success"]:
            policies = result["data"]
            
            if isinstance(policies, list) and len(policies) > 0:
                # Group by framework if available
                policy_summary = {}
                for policy in policies:
                    framework = policy.get("framework", "General")
                    if framework not in policy_summary:
                        policy_summary[framework] = {"count": 0, "active": 0}
                    policy_summary[framework]["count"] += 1
                    if policy.get("is_active", True):
                        policy_summary[framework]["active"] += 1
                
                summary_data = []
                for framework, data in policy_summary.items():
                    summary_data.append({
                        "Framework": framework,
                        "Total Policies": data["count"],
                        "Active": data["active"],
                        "Status": "Active"
                    })
                
                df_summary = pd.DataFrame(summary_data)
                st.dataframe(df_summary, use_container_width=True, hide_index=True)
                
                st.markdown("---")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Total Policies", len(policies))
                
                with col2:
                    active_count = sum(1 for p in policies if p.get("is_active", True))
                    st.metric("Active Policies", active_count)
                
                with col3:
                    inactive_count = len(policies) - active_count
                    st.metric("Inactive", inactive_count)
            else:
                st.info("No policy data available")
        else:
            st.info("Policy summary unavailable")
    
    with tab3:
        st.subheader("Audit & Reporting")
        
        st.markdown("**Compliance Audit Summary**")
        
        compliance_result = api_client.get_compliance_status_overview()
        
        if compliance_result["success"]:
            compliance_data = compliance_result["data"]
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Compliance Standards Status**")
                
                if "standards" in compliance_data:
                    standards = compliance_data["standards"]
                    audit_data = []
                    
                    for std_name, std_data in standards.items():
                        score = std_data.get("score", 0)
                        audit_data.append({
                            "Standard": std_name,
                            "Score": f"{score}%",
                            "Status": "Compliant" if score >= 90 else "Non-Compliant",
                            "Findings": std_data.get("findings", 0)
                        })
                    
                    df_audit = pd.DataFrame(audit_data)
                    st.dataframe(df_audit, use_container_width=True, hide_index=True)
                else:
                    st.info("No audit data available")
            
            with col2:
                st.markdown("**Overall Compliance Metrics**")
                
                overall_score = compliance_data.get("overall_score", 0)
                
                metrics_data = {
                    "Metric": ["Overall Score", "Standards Tracked", "Compliant Standards"],
                    "Value": [
                        f"{overall_score}%",
                        len(compliance_data.get("standards", {})),
                        sum(1 for s in compliance_data.get("standards", {}).values() if s.get("score", 0) >= 90)
                    ]
                }
                df_metrics = pd.DataFrame(metrics_data)
                st.dataframe(df_metrics, use_container_width=True, hide_index=True)
        else:
            st.info("Audit data unavailable")
        
        st.markdown("---")
        
        if st.button("📊 Generate Compliance Report", use_container_width=True):
            st.success("Compliance report generated successfully!")
            st.download_button(
                label="📥 Download Report",
                data="Sample compliance report content",
                file_name="compliance_report_2024.pdf",
                mime="application/pdf"
            )

def show_risk_management(api_client: SecurityFrameworkAPIClient):
    st.title("⚠️ Risk Management & Assessment")
    
    tab1, tab2, tab3 = st.tabs(["🎯 Risk Dashboard", "📊 Risk Assessment", "🛡️ Risk Mitigation"])
    
    with tab1:
        st.subheader("Risk Overview")
        
        # Get security events as risk indicators
        events_result = api_client.get_security_events()
        severity_result = api_client.get_severity_distribution()
        
        col1, col2, col3, col4 = st.columns(4)
        
        if severity_result["success"]:
            severity_data = severity_result["data"]
            
            with col1:
                high_risks = severity_data.get("Critical", 0) + severity_data.get("High", 0)
                st.metric("High Risks", high_risks)
            
            with col2:
                medium_risks = severity_data.get("Medium", 0)
                st.metric("Medium Risks", medium_risks)
            
            with col3:
                low_risks = severity_data.get("Low", 0) + severity_data.get("Info", 0)
                st.metric("Low Risks", low_risks)
            
            with col4:
                total_events = sum(severity_data.values())
                st.metric("Total Events", total_events)
        else:
            st.info("Risk metrics unavailable")
        
        st.markdown("---")
        
        # Display high-severity events as risks
        if events_result["success"] and events_result["data"]:
            events_data = events_result["data"]
            high_severity = [e for e in events_data if e.get("severity", "").lower() in ["high", "critical"]]
            
            if high_severity:
                df_risks = pd.DataFrame(high_severity)
                display_cols = [col for col in ["event_id", "description", "severity", "source", "event_type", "created_at"] if col in df_risks.columns]
                st.dataframe(df_risks[display_cols], use_container_width=True, hide_index=True)
            else:
                st.info("No high-severity risks identified")
        else:
            st.info("Risk data unavailable")
    
    with tab2:
        st.subheader("Risk Assessment Matrix")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Risk Categories by Severity**")
            
            # Get severity distribution as risk categories
            severity_result = api_client.get_severity_distribution()
            
            if severity_result["success"]:
                severity_data = severity_result["data"]
                
                categories = []
                for severity, count in severity_data.items():
                    if count > 0:
                        categories.append({
                            "Severity": severity,
                            "Count": count,
                            "Risk Level": "High" if severity in ["Critical", "High"] else "Medium" if severity == "Medium" else "Low"
                        })
                
                if categories:
                    df_categories = pd.DataFrame(categories)
                    st.dataframe(df_categories, use_container_width=True, hide_index=True)
                else:
                    st.info("No risk data available")
            else:
                st.info("Risk assessment data unavailable")
        
        with col2:
            st.markdown("**Risk Summary**")
            
            # Calculate risk summary from events
            events_result = api_client.get_security_events()
            severity_result = api_client.get_severity_distribution()
            
            if severity_result["success"]:
                severity_data = severity_result["data"]
                
                summary = {
                    "Metric": ["Total Risks", "Critical Risks", "High Risks", "Medium Risks", "Low Risks"],
                    "Count": [
                        sum(severity_data.values()),
                        severity_data.get("Critical", 0),
                        severity_data.get("High", 0),
                        severity_data.get("Medium", 0),
                        severity_data.get("Low", 0) + severity_data.get("Info", 0)
                    ]
                }
                
                df_summary = pd.DataFrame(summary)
                st.dataframe(df_summary, use_container_width=True, hide_index=True)
            else:
                st.info("Risk summary unavailable")
    
    with tab3:
        st.subheader("Risk Mitigation Strategies")
        
        # Get SOAR workflows as mitigation strategies
        workflows_result = api_client.get_soar_workflows()
        
        if workflows_result["success"] and workflows_result["data"] and isinstance(workflows_result["data"], list):
            workflows = workflows_result["data"]
            
            mitigation = []
            for workflow in workflows:
                if isinstance(workflow, dict):
                    mitigation.append({
                        "Risk/Trigger": workflow.get("trigger_event", "N/A"),
                        "Mitigation Actions": ", ".join(workflow.get("actions", [])) if workflow.get("actions") else "No actions defined",
                        "Workflow": workflow.get("name", "Unnamed"),
                        "Status": workflow.get("status", "unknown").capitalize()
                    })
            
            if mitigation:
                df_mitigation = pd.DataFrame(mitigation)
                st.dataframe(df_mitigation, use_container_width=True, hide_index=True)
            else:
                st.info("No mitigation strategies defined. Create SOAR workflows to automate risk mitigation.")
        else:
            st.info("No mitigation strategies available. Create SOAR workflows in the Security Monitoring section.")
        
        st.markdown("---")
        
        # Calculate mitigation metrics from workflows and events
        severity_result = api_client.get_severity_distribution()
        threat_result = api_client.get_threat_summary()
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if workflows_result["success"] and isinstance(workflows_result.get("data"), list):
                workflows_data = workflows_result.get("data", [])
                active_workflows = len([w for w in workflows_data if isinstance(w, dict) and w.get("status") == "active"])
                total_workflows = len(workflows_data)
                mitigation_rate = int((active_workflows / total_workflows * 100)) if total_workflows > 0 else 0
                st.metric("Mitigation Rate", f"{mitigation_rate}%")
            else:
                st.metric("Mitigation Rate", "N/A")
        
        with col2:
            if severity_result["success"]:
                total_risks = sum(severity_result["data"].values())
                st.metric("Total Risks", total_risks)
            else:
                st.metric("Total Risks", "N/A")
        
        with col3:
            if threat_result["success"]:
                security_score = threat_result["data"].get("security_score", 0)
                st.metric("Security Score", f"{security_score:.1f}%")
            else:
                st.metric("Security Score", "N/A")
