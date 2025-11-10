import streamlit as st
from services.api_client import SecurityFrameworkAPIClient
from config import SecurityFrameworkConfig

def display_user_authentication_form(api_client: SecurityFrameworkAPIClient):
    st.markdown("### Login to Hybrid Cloud Security Framework")
    
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit_button = st.form_submit_button("Login", use_container_width=True)
        
        if submit_button:
            if username and password:
                with st.spinner("Authenticating..."):
                    authentication_result = api_client.authenticate_user(username, password)
                    
                if authentication_result["success"]:
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error(f"Login failed: {authentication_result.get('error', 'Unknown error')}")
            else:
                st.error("Please fill in all fields")
    
    st.markdown("---")
    st.markdown("### New User? Register Here")
    
    with st.form("register_form"):
        reg_username = st.text_input("New Username", key="reg_username")
        reg_email = st.text_input("Email", key="reg_email")
        reg_password = st.text_input("New Password", type="password", key="reg_password")
        reg_role = st.selectbox("Role", ["user", "admin", "auditor"], key="reg_role")
        reg_submit = st.form_submit_button("Register", use_container_width=True)
        
        if reg_submit:
            if reg_username and reg_email and reg_password:
                with st.spinner("Creating account..."):
                    registration_result = api_client.register_new_user(reg_username, reg_email, reg_password, reg_role)
                    
                if registration_result["success"]:
                    st.success("Registration successful! Please login.")
                else:
                    st.error(f"Registration failed: {registration_result.get('error', 'Unknown error')}")
            else:
                st.error("Please fill in all fields")

def display_user_logout_button():
    if st.button("Logout", key="logout_button", use_container_width=True):
        # Clear all authentication session state
        st.session_state.authentication_token = None
        st.session_state.current_username = None
        st.session_state.user_role = None
        st.session_state.is_authenticated = False
        st.rerun()

def check_user_authentication_status():
    # Check if user is authenticated via session state
    return (
        st.session_state.get('is_authenticated', False) and
        st.session_state.get('authentication_token') is not None
    )
