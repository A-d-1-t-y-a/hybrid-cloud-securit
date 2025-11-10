import streamlit as st
import pandas as pd
import plotly.express as px
from services.api_client import SecurityFrameworkAPIClient

def show_user_management(api_client: SecurityFrameworkAPIClient):
    st.title("Identity & Access Management")
    
    # Refresh button
    if st.button("Refresh", key="refresh_iam", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # User Overview Metrics
    result = api_client.get_all_users()
    
    if result["success"] and result["data"]:
        users = result["data"]
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Users", len(users))
        
        with col2:
            admin_count = len([u for u in users if u.get("role") == "admin"])
            st.metric("Admin Users", admin_count)
        
        with col3:
            user_count = len([u for u in users if u.get("role") == "user"])
            st.metric("Regular Users", user_count)
        
        with col4:
            unique_roles = len(set(u.get("role", "user") for u in users))
            st.metric("Unique Roles", unique_roles)
        
        st.markdown("---")
        
        # Users Table
        st.subheader("Users")
        
        # Add user button
        if st.button("Add New User"):
            st.session_state.show_add_user = True
        
        # Add user form
        if st.session_state.get('show_add_user', False):
            with st.form("add_user_form"):
                st.markdown("### Create New User")
                
                col1, col2 = st.columns(2)
                with col1:
                    new_username = st.text_input("Username*")
                    new_email = st.text_input("Email*")
                
                with col2:
                    new_password = st.text_input("Password*", type="password")
                    new_role = st.selectbox("Role*", ["user", "admin", "auditor"])
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("Create User", use_container_width=True):
                        if new_username and new_email and new_password:
                            create_result = api_client.register_new_user(new_username, new_email, new_password, new_role)
                            if create_result["success"]:
                                st.success("User created successfully!")
                                st.session_state.show_add_user = False
                                st.rerun()
                            else:
                                st.error(f"Error: {create_result.get('error', 'Failed to create user')}")
                        else:
                            st.error("Please fill in all required fields")
                
                with col2:
                    if st.form_submit_button("Cancel", use_container_width=True):
                        st.session_state.show_add_user = False
                        st.rerun()
        
        # Display users table
        df = pd.DataFrame(users)
        
        # Select relevant columns
        display_cols = [col for col in ["username", "email", "role", "created_at"] if col in df.columns]
        if display_cols:
            st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        # Role Distribution Chart
        st.subheader("Role Distribution")
        
        role_counts = {}
        for user in users:
            role = user.get("role", "user")
            role_counts[role] = role_counts.get(role, 0) + 1
        
        if role_counts:
            df_roles = pd.DataFrame(list(role_counts.items()), columns=["Role", "Count"])
            
            fig = px.pie(df_roles, values="Count", names="Role", 
                        title="Users by Role",
                        color_discrete_sequence=px.colors.qualitative.Set3)
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white'
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Unable to load user data")
