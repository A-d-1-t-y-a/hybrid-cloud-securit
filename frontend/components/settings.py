import streamlit as st
import pandas as pd
from services.api_client import SecurityFrameworkAPIClient
from config import SecurityFrameworkConfig

def show_settings(api_client: SecurityFrameworkAPIClient):
    st.title("System Settings")
    
    # Refresh button
    if st.button("Refresh", key="refresh_settings", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # API Configuration
    st.subheader("API Configuration")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("API Base URL", SecurityFrameworkConfig.API_BASE_URL)
    
    with col2:
        st.metric("API Version", "v1")
    
    with col3:
        st.metric("Authentication", "JWT")
    
    st.markdown("---")
    
    # System Status
    st.subheader("System Status")
    
    framework_result = api_client.get_security_framework_status()
    
    if framework_result["success"]:
        framework_data = framework_result["data"]
        
        # Framework Components
        if "components" in framework_data:
            st.markdown("**Framework Components**")
            
            components = framework_data["components"]
            
            # Display components in a grid
            cols = st.columns(3)
            col_idx = 0
            
            for component_name, component_status in components.items():
                with cols[col_idx % 3]:
                    if isinstance(component_status, dict):
                        status = component_status.get("status", "unknown")
                        endpoints = component_status.get("endpoints", 0)
                        st.metric(
                            component_name.replace("_", " ").title(),
                            f"{endpoints} endpoints",
                            status.capitalize()
                        )
                    else:
                        st.metric(
                            component_name.replace("_", " ").title(),
                            component_status
                        )
                col_idx += 1
            
            st.markdown("---")
        
        # Security Standards
        if "security_standards" in framework_data:
            st.markdown("**Security Standards Compliance**")
            
            standards = framework_data["security_standards"]
            
            if isinstance(standards, list) and len(standards) > 0:
                # Display as table
                standards_data = []
                for standard in standards:
                    standards_data.append({
                        "Standard": standard,
                        "Status": "Implemented",
                        "Compliance": "Active"
                    })
                
                df_standards = pd.DataFrame(standards_data)
                st.dataframe(df_standards, use_container_width=True, hide_index=True)
            else:
                st.info("No security standards configured")
            
            st.markdown("---")
        
        # AWS Integration Status
        if "aws_integration" in framework_data:
            st.markdown("**AWS Integration Services**")
            
            aws_services = framework_data["aws_integration"]
            
            if isinstance(aws_services, dict) and len(aws_services) > 0:
                # Display AWS services in columns
                cols = st.columns(4)
                col_idx = 0
                
                for service_name, service_status in aws_services.items():
                    with cols[col_idx % 4]:
                        st.metric(
                            service_name.replace("_", " ").title(),
                            service_status.capitalize()
                        )
                    col_idx += 1
            else:
                st.info("No AWS integration services configured")
    else:
        st.error(f"Failed to load system status: {framework_result.get('error', 'Unknown error')}")
    
    st.markdown("---")
    
    # Session Information
    st.subheader("Session Information")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if "username" in st.session_state:
            st.metric("Logged in as", st.session_state.username)
        else:
            st.metric("User", "Unknown")
    
    with col2:
        if "token" in st.session_state:
            st.metric("Authentication", "Active")
        else:
            st.metric("Authentication", "Inactive")
    
    with col3:
        st.metric("Session", "Active")
    
    st.markdown("---")
    
    # Configuration Details
    st.subheader("Configuration Details")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**API Endpoints**")
        
        endpoints = [
            {"Endpoint": "/api/v1/auth", "Status": "Active"},
            {"Endpoint": "/api/v1/dashboard", "Status": "Active"},
            {"Endpoint": "/api/v1/iam", "Status": "Active"},
            {"Endpoint": "/api/v1/monitoring", "Status": "Active"},
            {"Endpoint": "/api/v1/compliance", "Status": "Active"},
            {"Endpoint": "/api/v1/soar", "Status": "Active"},
            {"Endpoint": "/api/v1/aws", "Status": "Active"}
        ]
        
        df_endpoints = pd.DataFrame(endpoints)
        st.dataframe(df_endpoints, use_container_width=True, hide_index=True)
    
    with col2:
        st.markdown("**Security Features**")
        
        features = [
            {"Feature": "JWT Authentication", "Status": "Enabled"},
            {"Feature": "Data Encryption", "Status": "Enabled"},
            {"Feature": "HTTPS Only", "Status": "Enabled"},
            {"Feature": "Session Management", "Status": "Enabled"},
            {"Feature": "Access Control", "Status": "Enabled"},
            {"Feature": "Audit Logging", "Status": "Enabled"}
        ]
        
        df_features = pd.DataFrame(features)
        st.dataframe(df_features, use_container_width=True, hide_index=True)
    
    st.markdown("---")
    
    # Logout Button
    st.subheader("Session Management")
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("Logout", type="primary", use_container_width=True):
            # Clear session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.success("Logged out successfully!")
            st.rerun()
