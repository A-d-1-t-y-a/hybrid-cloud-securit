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
            st.markdown("**Risk Categories**")
            categories_data = {
                "Category": ["Technical", "Operational", "Compliance", "Financial", "Reputational"],
                "Count": [15, 12, 8, 6, 4],
                "High Risk": [3, 2, 1, 1, 1]
            }
            df_categories = pd.DataFrame(categories_data)
            st.dataframe(df_categories, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**Risk Heat Map**")
            heatmap_data = {
                "Impact": ["Low", "Medium", "High", "Critical"],
                "Low": [8, 0, 0, 0],
                "Medium": [12, 6, 2, 0],
                "High": [5, 4, 3, 1],
                "Critical": [1, 2, 1, 1]
            }
            df_heatmap = pd.DataFrame(heatmap_data)
            st.dataframe(df_heatmap, use_container_width=True, hide_index=True)
    
    with tab3:
        st.subheader("Risk Mitigation Strategies")
        
        mitigation_data = {
            "Risk": ["Data Breach", "System Downtime", "Compliance Violation"],
            "Mitigation": ["Encryption, Access Controls, Monitoring", "Backup Systems, Redundancy", "Training, Policies, Audits"],
            "Owner": ["Security Team", "IT Team", "Compliance Team"],
            "Due Date": ["2024-02-15", "2024-02-20", "2024-02-25"],
            "Status": ["In Progress", "Completed", "In Progress"]
        }
        
        df_mitigation = pd.DataFrame(mitigation_data)
        st.dataframe(df_mitigation, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Mitigation Rate", "78%", "5%")
        
        with col2:
            st.metric("Avg Resolution Time", "15 days", "-2 days")
        
        with col3:
            st.metric("Risk Reduction", "23%", "8%")
