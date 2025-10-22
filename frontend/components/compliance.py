import streamlit as st
import pandas as pd
import plotly.express as px
from services.api_client import APIClient

def show_compliance_management(api_client: APIClient):
    st.title("📋 Compliance & Governance")
    
    tab1, tab2, tab3 = st.tabs(["📊 Compliance Dashboard", "📋 Policy Management", "📈 Audit & Reporting"])
    
    with tab1:
        st.subheader("Compliance Status Overview")
        
        result = api_client.get_compliance_status()
        if result["success"]:
            compliance_data = result["data"]
            st.json(compliance_data)
        else:
            st.error(f"Failed to load compliance status: {result.get('error', 'Unknown error')}")
        
        st.markdown("---")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("GDPR Compliance", "98%", "2%")
        
        with col2:
            st.metric("HIPAA Compliance", "95%", "3%")
        
        with col3:
            st.metric("SOX Compliance", "92%", "5%")
        
        with col4:
            st.metric("ISO 27001", "96%", "1%")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Compliance by Standard**")
            standards_data = {
                "Standard": ["GDPR", "HIPAA", "SOX", "ISO 27001", "PCI DSS"],
                "Score": [98, 95, 92, 96, 94],
                "Status": ["Compliant", "Compliant", "Compliant", "Compliant", "Compliant"]
            }
            df_standards = pd.DataFrame(standards_data)
            
            fig = px.bar(df_standards, x="Standard", y="Score", 
                        color="Score", color_continuous_scale="RdYlGn")
            fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**Compliance Trends**")
            trends_data = {
                "Month": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
                "GDPR": [95, 96, 97, 98, 98, 98],
                "HIPAA": [92, 93, 94, 95, 95, 95],
                "SOX": [88, 89, 90, 91, 92, 92]
            }
            df_trends = pd.DataFrame(trends_data)
            
            fig = px.line(df_trends, x="Month", y=["GDPR", "HIPAA", "SOX"], 
                        title="Compliance Score Trends")
            fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.subheader("Policy Management")
        
        result = api_client.get_compliance_policies()
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
        
        st.markdown("**Policy Categories**")
        policy_categories = {
            "Category": ["Data Protection", "Access Control", "Incident Response", "Risk Management", "Audit"],
            "Policies": [15, 12, 8, 10, 6],
            "Status": ["Active", "Active", "Active", "Active", "Active"],
            "Last Updated": ["2 days ago", "1 week ago", "3 days ago", "5 days ago", "1 day ago"]
        }
        
        df_categories = pd.DataFrame(policy_categories)
        st.dataframe(df_categories, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Policies", "51")
        
        with col2:
            st.metric("Active Policies", "48")
        
        with col3:
            st.metric("Under Review", "3")
    
    with tab3:
        st.subheader("Audit & Reporting")
        
        st.markdown("**Recent Audit Results**")
        audit_results = {
            "Audit Date": ["2024-01-15", "2024-01-10", "2024-01-05", "2024-01-01"],
            "Audit Type": ["GDPR Compliance", "Security Controls", "Data Protection", "Access Review"],
            "Status": ["Passed", "Passed", "Minor Issues", "Passed"],
            "Score": ["98%", "95%", "88%", "96%"],
            "Findings": [0, 0, 2, 0]
        }
        
        df_audit = pd.DataFrame(audit_results)
        st.dataframe(df_audit, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Audit Schedule**")
            schedule_data = {
                "Audit": ["GDPR Assessment", "Security Review", "Data Classification", "Access Control"],
                "Due Date": ["2024-02-15", "2024-02-20", "2024-02-25", "2024-03-01"],
                "Status": ["Scheduled", "Scheduled", "Scheduled", "Scheduled"]
            }
            df_schedule = pd.DataFrame(schedule_data)
            st.dataframe(df_schedule, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**Compliance Metrics**")
            metrics_data = {
                "Metric": ["Policy Coverage", "Training Completion", "Incident Response", "Risk Assessment"],
                "Score": ["96%", "94%", "98%", "92%"],
                "Target": ["95%", "95%", "95%", "90%"]
            }
            df_metrics = pd.DataFrame(metrics_data)
            st.dataframe(df_metrics, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        if st.button("📊 Generate Compliance Report", use_container_width=True):
            st.success("Compliance report generated successfully!")
            st.download_button(
                label="📥 Download Report",
                data="Sample compliance report content",
                file_name="compliance_report_2024.pdf",
                mime="application/pdf"
            )

def show_risk_management(api_client: APIClient):
    st.title("⚠️ Risk Management & Assessment")
    
    tab1, tab2, tab3 = st.tabs(["🎯 Risk Dashboard", "📊 Risk Assessment", "🛡️ Risk Mitigation"])
    
    with tab1:
        st.subheader("Risk Overview")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("High Risks", "3", "1 new")
        
        with col2:
            st.metric("Medium Risks", "12", "2 new")
        
        with col3:
            st.metric("Low Risks", "28", "5 new")
        
        with col4:
            st.metric("Mitigated", "45", "8 this week")
        
        st.markdown("---")
        
        risk_data = {
            "Risk ID": ["R-001", "R-002", "R-003", "R-004", "R-005"],
            "Description": ["Data Breach", "System Downtime", "Compliance Violation", "Insider Threat", "Cyber Attack"],
            "Severity": ["High", "Medium", "High", "Medium", "Critical"],
            "Probability": ["Medium", "Low", "High", "Low", "Medium"],
            "Impact": ["High", "Medium", "High", "High", "Critical"],
            "Status": ["Open", "Mitigated", "Open", "Monitoring", "Open"]
        }
        
        df_risks = pd.DataFrame(risk_data)
        st.dataframe(df_risks, use_container_width=True, hide_index=True)
    
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
