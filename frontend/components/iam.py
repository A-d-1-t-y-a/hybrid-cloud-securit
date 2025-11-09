import streamlit as st
import pandas as pd
from services.api_client import SecurityFrameworkAPIClient

def show_user_management(api_client: SecurityFrameworkAPIClient):
    st.title("👥 Identity & Access Management")
    
    tab1, tab2, tab3 = st.tabs(["👤 User Management", "🔐 Role Management", "📊 Access Analytics"])
    
    with tab1:
        st.subheader("User Management")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            if st.button("🔄 Refresh Users", use_container_width=True):
                st.rerun()
        
        with col2:
            if st.button("➕ Add New User", use_container_width=True):
                st.session_state.show_add_user = True
        
        if st.session_state.get('show_add_user', False):
            with st.expander("Add New User", expanded=True):
                with st.form("add_user_form"):
                    new_username = st.text_input("Username")
                    new_email = st.text_input("Email")
                    new_password = st.text_input("Password", type="password")
                    new_role = st.selectbox("Role", ["user", "admin", "auditor"])
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.form_submit_button("Create User", use_container_width=True):
                            if new_username and new_email and new_password:
                                result = api_client.register(new_username, new_email, new_password, new_role)
                                if result["success"]:
                                    st.success("User created successfully!")
                                    st.session_state.show_add_user = False
                                    st.rerun()
                                else:
                                    st.error(f"Error: {result.get('error', 'Unknown error')}")
                            else:
                                st.error("Please fill in all fields")
                    
                    with col2:
                        if st.form_submit_button("Cancel", use_container_width=True):
                            st.session_state.show_add_user = False
                            st.rerun()
        
        result = api_client.get_users()
        if result["success"]:
            users_data = result["data"]
            if isinstance(users_data, list) and len(users_data) > 0:
                df = pd.DataFrame(users_data)
                
                st.dataframe(
                    df,
                    use_container_width=True,
                    hide_index=True
                )
                
                st.markdown(f"**Total Users: {len(users_data)}**")
            else:
                st.info("No users found")
        else:
            st.error(f"Failed to load users: {result.get('error', 'Unknown error')}")
    
    with tab2:
        st.subheader("Role Management")
        
        roles_data = {
            "Role": ["Admin", "User", "Auditor", "Security Analyst"],
            "Permissions": [
                "Full system access, user management, system configuration",
                "Standard user access, view own data",
                "Read-only access, audit logs, compliance reports",
                "Security monitoring, threat analysis, incident response"
            ],
            "Users": [2, 45, 8, 12],
            "Status": ["Active", "Active", "Active", "Active"]
        }
        
        df_roles = pd.DataFrame(roles_data)
        st.dataframe(df_roles, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Roles", "4")
        
        with col2:
            st.metric("Active Users", "67")
        
        with col3:
            st.metric("Permission Sets", "12")
    
    with tab3:
        st.subheader("Access Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Login Activity (Last 24h)**")
            login_data = {
                "Time": ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
                "Logins": [5, 2, 15, 25, 18, 12]
            }
            df_login = pd.DataFrame(login_data)
            st.line_chart(df_login.set_index("Time"))
        
        with col2:
            st.markdown("**Access Patterns**")
            access_data = {
                "Resource": ["API Endpoints", "Dashboard", "Reports", "Admin Panel"],
                "Access Count": [1250, 890, 340, 45]
            }
            df_access = pd.DataFrame(access_data)
            st.bar_chart(df_access.set_index("Resource"))

def show_authentication_settings(api_client: SecurityFrameworkAPIClient):
    st.title("🔐 Authentication Settings")
    
    tab1, tab2, tab3 = st.tabs(["🔑 JWT Settings", "🛡️ Security Policies", "📱 MFA Configuration"])
    
    with tab1:
        st.subheader("JWT Token Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Token Expiry", "30 minutes")
            st.metric("Refresh Token", "7 days")
            st.metric("Algorithm", "HS256")
        
        with col2:
            st.metric("Issuer", "Hybrid Cloud Security")
            st.metric("Audience", "Security Framework")
            st.metric("Key Rotation", "90 days")
        
        if st.button("🔄 Rotate JWT Keys", use_container_width=True):
            st.success("JWT keys rotated successfully!")
    
    with tab2:
        st.subheader("Security Policies")
        
        policies = [
            {"Policy": "Password Complexity", "Status": "Active", "Description": "Minimum 8 characters, mixed case, numbers, symbols"},
            {"Policy": "Account Lockout", "Status": "Active", "Description": "Lock after 5 failed attempts for 30 minutes"},
            {"Policy": "Session Timeout", "Status": "Active", "Description": "Auto-logout after 30 minutes of inactivity"},
            {"Policy": "IP Whitelist", "Status": "Inactive", "Description": "Restrict access to specific IP addresses"}
        ]
        
        df_policies = pd.DataFrame(policies)
        st.dataframe(df_policies, use_container_width=True, hide_index=True)
    
    with tab3:
        st.subheader("Multi-Factor Authentication")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**MFA Status**")
            st.metric("Enabled Users", "45")
            st.metric("MFA Methods", "3")
            st.metric("Success Rate", "98.5%")
        
        with col2:
            st.markdown("**Available Methods**")
            methods = ["SMS", "Email", "TOTP", "Hardware Token"]
            for method in methods:
                st.checkbox(f"Enable {method}", value=True, key=f"mfa_{method}")
        
        if st.button("💾 Save MFA Settings", use_container_width=True):
            st.success("MFA settings saved successfully!")
