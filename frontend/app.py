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
from components.settings import show_settings
def main():
    st.set_page_config(
        page_title=SecurityFrameworkConfig.APP_TITLE,
        page_icon=SecurityFrameworkConfig.APP_ICON,
        layout=SecurityFrameworkConfig.LAYOUT,
        initial_sidebar_state="expanded"
    )
    
    st.markdown(SecurityFrameworkConfig.SIDEBAR_STYLE, unsafe_allow_html=True)
    st.markdown(SecurityFrameworkConfig.MAIN_STYLE, unsafe_allow_html=True)
    
    # Initialize session state
    if 'authentication_token' not in st.session_state:
        st.session_state.authentication_token = None
    if 'current_username' not in st.session_state:
        st.session_state.current_username = None
    if 'user_role' not in st.session_state:
        st.session_state.user_role = None
    if 'is_authenticated' not in st.session_state:
        st.session_state.is_authenticated = False
    
    security_framework_api_client = SecurityFrameworkAPIClient(SecurityFrameworkConfig.API_BASE_URL)
    
    if not check_user_authentication_status():
        st.title(SecurityFrameworkConfig.APP_TITLE)
        st.markdown("### Secure Your Hybrid Cloud Environment")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.markdown("""
            **Security Features:**
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
            st.title("Security Framework")
            st.markdown(f"Welcome, **{st.session_state.get('current_username', 'User')}**")
            
            st.markdown("---")
            
            selected_page = st.selectbox(
                "Navigate",
                [
                    "Dashboard",
                    "Identity & Access",
                    "Data Protection",
                    "Security Monitoring",
                    "Compliance",
                    "AWS Integration",
                    "Settings"
                ]
            )
            
            st.markdown("---")
            display_user_logout_button()
        
        if selected_page == "Dashboard":
            show_dashboard(security_framework_api_client)
        
        elif selected_page == "Identity & Access":
            show_user_management(security_framework_api_client)
        
        elif selected_page == "Data Protection":
            show_data_classification(security_framework_api_client)
        
        elif selected_page == "Security Monitoring":
            show_security_monitoring(security_framework_api_client)
            
            st.markdown("---")
            st.markdown("---")
            
            show_incident_response(security_framework_api_client)
        
        elif selected_page == "Compliance":
            show_compliance_management(security_framework_api_client)
            
            st.markdown("---")
            st.markdown("---")
            
            show_risk_management(security_framework_api_client)
        
        elif selected_page == "AWS Integration":
            show_aws_integration(security_framework_api_client)
            
            st.markdown("---")
            st.markdown("---")
            
            show_cloud_analytics(security_framework_api_client)
        
        elif selected_page == "Settings":
            show_settings(security_framework_api_client)

if __name__ == "__main__":
    main()
