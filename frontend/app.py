import streamlit as st
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import SecurityFrameworkConfig
from services.api_client import SecurityFrameworkAPIClient
from components.auth import display_user_authentication_form, display_user_logout_button, check_user_authentication_status
from components.dashboard import show_dashboard
from components.iam import show_user_management
from components.data_protection import show_data_classification
from components.monitoring import show_security_monitoring, show_incident_response
from components.compliance import show_compliance_management, show_risk_management
from components.aws_integration import show_aws_integration, show_cloud_analytics

def main():
    st.set_page_config(
        page_title=SecurityFrameworkConfig.APP_TITLE,
        page_icon=SecurityFrameworkConfig.APP_ICON,
        layout=SecurityFrameworkConfig.LAYOUT,
        initial_sidebar_state="expanded"
    )
    
    st.markdown(SecurityFrameworkConfig.SIDEBAR_STYLE, unsafe_allow_html=True)
    st.markdown(SecurityFrameworkConfig.MAIN_STYLE, unsafe_allow_html=True)
    
    security_framework_api_client = SecurityFrameworkAPIClient(SecurityFrameworkConfig.API_BASE_URL)
    
    if not check_user_authentication_status():
        st.title(f"{SecurityFrameworkConfig.APP_ICON} {SecurityFrameworkConfig.APP_TITLE}")
        st.markdown("### Secure Your Hybrid Cloud Environment")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.markdown("""
            **🔐 Security Features:**
            - Identity & Access Management
            - Data Protection & Classification
            - Security Monitoring & SIEM
            - Compliance & Governance
            - SOAR Automation
            - AWS Cloud Integration
            """)
        
        with col2:
            display_user_authentication_form(security_framework_api_client)
    else:
        with st.sidebar:
            st.title(f"{SecurityFrameworkConfig.APP_ICON} Security Framework")
            st.markdown(f"Welcome, **{st.session_state.get('current_username', 'User')}**")
            
            st.markdown("---")
            
            selected_page = st.selectbox(
                "Navigate",
                [
                    "🏠 Dashboard",
                    "👥 Identity & Access",
                    "🔍 Data Protection",
                    "🔍 Security Monitoring",
                    "📋 Compliance",
                    "☁️ AWS Integration",
                    "⚙️ Settings"
                ]
            )
            
            st.markdown("---")
            display_user_logout_button()
        
        if selected_page == "🏠 Dashboard":
            show_dashboard(security_framework_api_client)
        
        elif selected_page == "👥 Identity & Access":
            show_user_management(security_framework_api_client)
        
        elif selected_page == "🔍 Data Protection":
            show_data_classification(security_framework_api_client)
        
        elif selected_page == "🔍 Security Monitoring":
            show_security_monitoring(security_framework_api_client)
            
            st.markdown("---")
            st.markdown("---")
            
            show_incident_response(security_framework_api_client)
        
        elif selected_page == "📋 Compliance":
            show_compliance_management(security_framework_api_client)
            
            st.markdown("---")
            st.markdown("---")
            
            show_risk_management(security_framework_api_client)
        
        elif selected_page == "☁️ AWS Integration":
            show_aws_integration(security_framework_api_client)
            
            st.markdown("---")
            st.markdown("---")
            
            show_cloud_analytics(security_framework_api_client)
        
        elif selected_page == "⚙️ Settings":
            st.title("⚙️ System Settings")
            
            tab1, tab2, tab3 = st.tabs(["🔧 API Configuration", "🛡️ Security Settings", "📊 System Status"])
            
            with tab1:
                st.subheader("API Configuration")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.text_input("API Base URL", value=SecurityFrameworkConfig.API_BASE_URL, disabled=True)
                    st.text_input("API Version", value="v1", disabled=True)
                    st.text_input("Authentication", value="JWT Bearer Token", disabled=True)
                
                with col2:
                    st.metric("API Status", "Online", "✅")
                    st.metric("Response Time", "45ms", "-5ms")
                    st.metric("Uptime", "99.9%", "0.1%")
            
            with tab2:
                st.subheader("Security Settings")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Authentication Settings**")
                    st.checkbox("Enable MFA", value=True)
                    st.checkbox("Session Timeout", value=True)
                    st.checkbox("IP Whitelist", value=False)
                    st.checkbox("Password Complexity", value=True)
                
                with col2:
                    st.markdown("**Encryption Settings**")
                    st.selectbox("Encryption Algorithm", ["AES-256", "AES-128", "RSA-4096"], index=0)
                    st.selectbox("Key Rotation", ["30 days", "60 days", "90 days"], index=2)
                    st.checkbox("Data at Rest Encryption", value=True)
                    st.checkbox("Data in Transit Encryption", value=True)
            
            with tab3:
                st.subheader("System Status")
                
                framework_status_result = security_framework_api_client.get_security_framework_status()
                if framework_status_result["success"]:
                    framework_status_data = framework_status_result["data"]
                    
                    st.markdown("**Framework Components**")
                    framework_components = framework_status_data.get("components", {})
                    
                    for component_name, component_status in framework_components.items():
                        if isinstance(component_status, dict):
                            component_status_value = component_status.get("status", "unknown")
                            endpoint_count = component_status.get("endpoints", 0)
                            st.metric(f"{component_name.replace('_', ' ').title()}", f"{endpoint_count} endpoints", component_status_value)
                        else:
                            st.metric(f"{component_name.replace('_', ' ').title()}", component_status)
                    
                    st.markdown("---")
                    
                    st.markdown("**Security Standards**")
                    security_standards = framework_status_data.get("security_standards", [])
                    for standard_name in security_standards:
                        st.markdown(f"- ✅ {standard_name}")
                    
                    st.markdown("---")
                    
                    st.markdown("**AWS Integration**")
                    aws_integration_services = framework_status_data.get("aws_integration", {})
                    for service_name, service_status in aws_integration_services.items():
                        st.metric(f"AWS {service_name.replace('_', ' ').title()}", service_status)
                else:
                    st.error(f"Failed to load framework status: {framework_status_result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    main()
