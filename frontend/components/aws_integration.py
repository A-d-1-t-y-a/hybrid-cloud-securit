import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from services.api_client import SecurityFrameworkAPIClient

def show_aws_integration(api_client: SecurityFrameworkAPIClient):
    st.title("AWS Cloud Integration")
    
    # Refresh button
    if st.button("Refresh", key="refresh_aws", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # AWS Connection Status
    st.subheader("AWS Connection Status")
    
    status_result = api_client.get_aws_cloud_status()
    
    if status_result["success"]:
        status_data = status_result["data"]
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            connection_status = status_data.get("status", "Unknown")
            status_color = "🟢" if connection_status == "connected" else "🔴"
            st.metric("Connection Status", connection_status.capitalize())
        
        with col2:
            region = status_data.get("region", "N/A")
            st.metric("AWS Region", region)
        
        with col3:
            account = status_data.get("account_id", "N/A")
            if account and len(account) > 8:
                account = f"***{account[-4:]}"
            st.metric("Account ID", account)
    else:
        st.error(f"Failed to connect to AWS: {status_result.get('error', 'Unknown error')}")
    
    st.markdown("---")
    
    # S3 Data Storage
    st.subheader("S3 Data Storage")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("**Store Data in S3**")
        
        with st.form("store_s3_form"):
            data_content = st.text_area(
                "Data to store:",
                placeholder="Enter data to store in AWS S3...",
                height=100
            )
            data_key = st.text_input(
                "S3 Key:",
                placeholder="e.g., security-logs/2024/event.json"
            )
            
            col_a, col_b = st.columns(2)
            with col_a:
                if st.form_submit_button("Store in S3", use_container_width=True):
                    if data_content and data_key:
                        with st.spinner("Storing data in AWS S3..."):
                            result = api_client.store_data_in_aws_s3(data_content, data_key)
                        
                        if result["success"]:
                            st.success("Data stored successfully in AWS S3!")
                            st.info(f"Key: {data_key}")
                        else:
                            st.error(f"Error: {result.get('error', 'Failed to store data')}")
                    else:
                        st.error("Please provide both data content and S3 key")
    
    with col2:
        st.markdown("**Retrieve Data from S3**")
        
        with st.form("retrieve_s3_form"):
            retrieve_key = st.text_input(
                "S3 Key to retrieve:",
                placeholder="e.g., security-logs/2024/event.json"
            )
            
            st.text("")  # Spacer to align with left column
            st.text("")
            
            col_a, col_b = st.columns(2)
            with col_a:
                if st.form_submit_button("Retrieve from S3", use_container_width=True):
                    if retrieve_key:
                        with st.spinner("Retrieving data from AWS S3..."):
                            result = api_client.retrieve_data_from_aws_s3(retrieve_key)
                        
                        if result["success"]:
                            st.success("Data retrieved successfully!")
                            st.code(result["data"], language="text")
                        else:
                            st.error(f"Error: {result.get('error', 'Failed to retrieve data')}")
                    else:
                        st.error("Please provide S3 key to retrieve")
    
    st.markdown("---")
    
    # CloudWatch Metrics
    st.subheader("CloudWatch Metrics")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("**Send Metrics to CloudWatch**")
        
        with st.form("cloudwatch_form"):
            namespace = st.text_input("Namespace:", value="HybridCloudSecurity")
            metric_name = st.text_input("Metric Name:", value="SecurityEvent")
            metric_value = st.number_input("Metric Value:", value=1.0, min_value=0.0)
            unit = st.selectbox("Unit:", ["Count", "Percent", "Seconds", "Bytes", "Megabytes"])
            
            if st.form_submit_button("Send to CloudWatch", use_container_width=True):
                metrics_data = {
                    "namespace": namespace,
                    "metric_name": metric_name,
                    "value": metric_value,
                    "unit": unit
                }
                
                with st.spinner("Sending metrics to CloudWatch..."):
                    result = api_client.send_cloudwatch_metrics(metrics_data)
                
                if result["success"]:
                    st.success("Metrics sent successfully to CloudWatch!")
                    st.info(f"Namespace: {namespace} | Metric: {metric_name}")
                else:
                    st.error(f"Error: {result.get('error', 'Failed to send metrics')}")
    
    with col2:
        st.markdown("**CloudWatch Security Metrics**")
        
        metrics_result = api_client.get_aws_security_metrics_data()
        
        if metrics_result["success"]:
            metrics_data = metrics_result["data"]
            
            if isinstance(metrics_data, dict) and metrics_data:
                # Display metrics as cards
                for metric_name, metric_value in metrics_data.items():
                    st.metric(metric_name.replace("_", " ").title(), metric_value)
            elif isinstance(metrics_data, list) and len(metrics_data) > 0:
                # Display as table
                df_metrics = pd.DataFrame(metrics_data)
                st.dataframe(df_metrics, use_container_width=True, hide_index=True)
            else:
                st.info("No CloudWatch metrics available")
        else:
            st.info("No security metrics available from CloudWatch")


def show_cloud_analytics(api_client: SecurityFrameworkAPIClient):
    st.title("Cloud Analytics & Insights")
    
    # Refresh button
    if st.button("Refresh", key="refresh_analytics", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # AWS Status Overview
    st.subheader("AWS Service Overview")
    
    status_result = api_client.get_aws_cloud_status()
    
    if status_result["success"]:
        status_data = status_result["data"]
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Connection", status_data.get("status", "Unknown").capitalize())
        
        with col2:
            st.metric("Region", status_data.get("region", "N/A"))
        
        with col3:
            services = status_data.get("services", {})
            active_services = sum(1 for s in services.values() if s == "available")
            st.metric("Active Services", active_services)
        
        with col4:
            st.metric("Integration", "Enabled")
        
        st.markdown("---")
        
        # Service Status Details
        if "services" in status_data and status_data["services"]:
            st.markdown("**AWS Services Status**")
            
            services_data = []
            for service_name, service_status in status_data["services"].items():
                services_data.append({
                    "Service": service_name.upper(),
                    "Status": service_status.capitalize(),
                    "Health": "Healthy" if service_status == "available" else "Unavailable"
                })
            
            df_services = pd.DataFrame(services_data)
            st.dataframe(df_services, use_container_width=True, hide_index=True)
    else:
        st.warning("Unable to load AWS analytics data")
    
    st.markdown("---")
    
    # Security Metrics from CloudWatch
    st.subheader("Security Metrics Analytics")
    
    metrics_result = api_client.get_aws_security_metrics_data()
    
    if metrics_result["success"]:
        metrics_data = metrics_result["data"]
        
        if isinstance(metrics_data, dict) and metrics_data:
            # Create metrics visualization
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Security Metrics Summary**")
                
                metrics_list = []
                for metric_name, metric_value in metrics_data.items():
                    metrics_list.append({
                        "Metric": metric_name.replace("_", " ").title(),
                        "Value": metric_value
                    })
                
                if metrics_list:
                    df_metrics = pd.DataFrame(metrics_list)
                    st.dataframe(df_metrics, use_container_width=True, hide_index=True)
            
            with col2:
                st.markdown("**Metrics Visualization**")
                
                if len(metrics_data) > 0:
                    # Create bar chart
                    df_chart = pd.DataFrame([
                        {"Metric": k.replace("_", " ").title(), "Value": v} 
                        for k, v in metrics_data.items()
                    ])
                    
                    fig = px.bar(df_chart, x="Metric", y="Value",
                                color="Value",
                                color_continuous_scale="Blues")
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font_color='white',
                        showlegend=False
                    )
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No security metrics data available from CloudWatch")
    else:
        st.info("Security metrics unavailable")
    
    st.markdown("---")
    
    # Integration Summary
    st.subheader("Integration Summary")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Available Features**")
        features = [
            "S3 Data Storage & Retrieval",
            "CloudWatch Metrics Integration",
            "Security Event Monitoring",
            "Encrypted Data Storage",
            "Real-time Metrics Tracking"
        ]
        
        for feature in features:
            st.markdown(f"- {feature}")
    
    with col2:
        st.markdown("**Integration Status**")
        
        integration_status = {
            "Component": ["S3 Storage", "CloudWatch", "IAM", "Encryption"],
            "Status": ["Active", "Active", "Active", "Active"],
            "Health": ["Healthy", "Healthy", "Healthy", "Healthy"]
        }
        
        df_integration = pd.DataFrame(integration_status)
        st.dataframe(df_integration, use_container_width=True, hide_index=True)
