import streamlit as st
import pandas as pd
import plotly.express as px
from services.api_client import SecurityFrameworkAPIClient

def show_aws_integration(api_client: SecurityFrameworkAPIClient):
    st.title("☁️ AWS Cloud Integration")
    
    tab1, tab2, tab3 = st.tabs(["🔧 AWS Services", "📊 Cloud Metrics", "🛡️ Security Controls"])
    
    with tab1:
        st.subheader("AWS Services Status")
        
        result = api_client.get_aws_cloud_status()
        if result["success"]:
            aws_status = result["data"]
            st.json(aws_status)
        else:
            st.error(f"Failed to load AWS status: {result.get('error', 'Unknown error')}")
        
        st.markdown("---")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("S3 Buckets", "12", "2 new")
        
        with col2:
            st.metric("Lambda Functions", "8", "1 new")
        
        with col3:
            st.metric("CloudWatch Alarms", "24", "3 new")
        
        with col4:
            st.metric("IAM Users", "45", "5 new")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**S3 Storage Management**")
            s3_data = {
                "Bucket": ["security-logs", "backup-data", "compliance-reports", "user-data"],
                "Size (GB)": [245, 1200, 89, 156],
                "Objects": [12500, 45000, 2300, 8900],
                "Encryption": ["Enabled", "Enabled", "Enabled", "Enabled"]
            }
            df_s3 = pd.DataFrame(s3_data)
            st.dataframe(df_s3, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**Lambda Functions**")
            lambda_data = {
                "Function": ["Security-Scanner", "Log-Processor", "Alert-Handler", "Backup-Manager"],
                "Runtime": ["Python 3.9", "Python 3.9", "Node.js 18", "Python 3.9"],
                "Memory": ["512 MB", "1024 MB", "256 MB", "512 MB"],
                "Last Invoked": ["2 min ago", "5 min ago", "1 hour ago", "3 hours ago"]
            }
            df_lambda = pd.DataFrame(lambda_data)
            st.dataframe(df_lambda, use_container_width=True, hide_index=True)
    
    with tab2:
        st.subheader("Cloud Metrics & Monitoring")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**CloudWatch Metrics**")
            metrics_data = {
                "Metric": ["CPU Utilization", "Memory Usage", "Network I/O", "Disk I/O"],
                "Value": ["45%", "67%", "125 MB/s", "89 MB/s"],
                "Status": ["Normal", "Warning", "Normal", "Normal"],
                "Trend": ["↗️", "↘️", "→", "↗️"]
            }
            df_metrics = pd.DataFrame(metrics_data)
            st.dataframe(df_metrics, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**Cost Analysis**")
            cost_data = {
                "Service": ["EC2", "S3", "Lambda", "CloudWatch", "RDS"],
                "Monthly Cost": ["$245", "$89", "$34", "$12", "$156"],
                "Usage": ["High", "Medium", "Low", "Low", "Medium"]
            }
            df_cost = pd.DataFrame(cost_data)
            st.dataframe(df_cost, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        st.markdown("**AWS Data Storage**")
        with st.form("aws_storage_form"):
            data_content = st.text_area("Data to store in S3:", placeholder="Enter data to store in AWS S3...")
            data_key = st.text_input("S3 Key:", placeholder="my-data-key")
            
            if st.form_submit_button("☁️ Store in AWS S3", use_container_width=True):
                if data_content and data_key:
                    with st.spinner("Storing data in AWS S3..."):
                        result = api_client.store_data_in_aws_s3(data_content, data_key)
                    
                    if result["success"]:
                        st.success("✅ Data stored successfully in AWS S3!")
                    else:
                        st.error(f"Failed to store data: {result.get('error', 'Unknown error')}")
                else:
                    st.error("Please provide both data content and S3 key")
        
        st.markdown("---")
        
        st.markdown("**Retrieve Data from AWS**")
        with st.form("aws_retrieve_form"):
            retrieve_key = st.text_input("S3 Key to retrieve:", placeholder="my-data-key")
            
            if st.form_submit_button("📥 Retrieve from AWS S3", use_container_width=True):
                if retrieve_key:
                    with st.spinner("Retrieving data from AWS S3..."):
                        result = api_client.retrieve_data_from_aws_s3(retrieve_key)
                    
                    if result["success"]:
                        st.success("✅ Data retrieved successfully!")
                        st.text_area("Retrieved Data:", result["data"], height=100, disabled=True)
                    else:
                        st.error(f"Failed to retrieve data: {result.get('error', 'Unknown error')}")
                else:
                    st.error("Please provide S3 key to retrieve")
    
    with tab3:
        st.subheader("AWS Security Controls")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Security Groups**")
            sg_data = {
                "Group": ["Web-SG", "DB-SG", "Admin-SG", "API-SG"],
                "Rules": [8, 4, 12, 6],
                "Status": ["Active", "Active", "Active", "Active"],
                "Last Modified": ["2 days ago", "1 week ago", "3 days ago", "5 days ago"]
            }
            df_sg = pd.DataFrame(sg_data)
            st.dataframe(df_sg, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**IAM Policies**")
            iam_data = {
                "Policy": ["S3-ReadOnly", "EC2-FullAccess", "CloudWatch-Logs", "Lambda-Execute"],
                "Users": [15, 3, 8, 5],
                "Status": ["Active", "Active", "Active", "Active"]
            }
            df_iam = pd.DataFrame(iam_data)
            st.dataframe(df_iam, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        st.markdown("**Send Security Metrics to CloudWatch**")
        with st.form("cloudwatch_metrics_form"):
            namespace = st.text_input("Namespace:", value="HybridCloudSecurity")
            metric_name = st.text_input("Metric Name:", value="SecurityEvent")
            metric_value = st.number_input("Metric Value:", value=1.0)
            unit = st.selectbox("Unit:", ["Count", "Percent", "Seconds", "Bytes"])
            
            if st.form_submit_button("📊 Send to CloudWatch", use_container_width=True):
                metrics_data = {
                    "namespace": namespace,
                    "metric_name": metric_name,
                    "value": metric_value,
                    "unit": unit
                }
                
                with st.spinner("Sending metrics to CloudWatch..."):
                    result = api_client.send_cloudwatch_metrics(metrics_data)
                
                if result["success"]:
                    st.success("✅ Metrics sent successfully to CloudWatch!")
                else:
                    st.error(f"Failed to send metrics: {result.get('error', 'Unknown error')}")
        
        st.markdown("---")
        
        result = api_client.get_aws_security_metrics_data()
        if result["success"]:
            st.markdown("**Security Metrics from CloudWatch**")
            metrics_data = result["data"]
            st.json(metrics_data)
        else:
            st.error(f"Failed to load security metrics: {result.get('error', 'Unknown error')}")

def show_cloud_analytics(api_client: SecurityFrameworkAPIClient):
    st.title("📈 Cloud Analytics & Insights")
    
    tab1, tab2, tab3 = st.tabs(["📊 Usage Analytics", "💰 Cost Optimization", "🔍 Performance Monitoring"])
    
    with tab1:
        st.subheader("AWS Usage Analytics")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Requests", "1,234,567", "12%")
        
        with col2:
            st.metric("Data Transfer", "2.4 TB", "8%")
        
        with col3:
            st.metric("API Calls", "45,678", "15%")
        
        st.markdown("---")
        
        usage_data = {
            "Service": ["S3", "Lambda", "CloudWatch", "IAM", "EC2"],
            "Requests": [45678, 12345, 8901, 5678, 2345],
            "Data (GB)": [1200, 45, 12, 0, 89],
            "Cost ($)": [89, 34, 12, 0, 156]
        }
        
        df_usage = pd.DataFrame(usage_data)
        st.dataframe(df_usage, use_container_width=True, hide_index=True)
    
    with tab2:
        st.subheader("Cost Optimization")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Cost Breakdown**")
            cost_breakdown = {
                "Service": ["EC2", "S3", "Lambda", "CloudWatch", "RDS"],
                "Cost": [245, 89, 34, 12, 156],
                "Percentage": [45, 16, 6, 2, 29]
            }
            df_cost = pd.DataFrame(cost_breakdown)
            
            fig = px.pie(df_cost, values="Cost", names="Service", title="Cost Distribution")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("**Optimization Recommendations**")
            recommendations = [
                "💡 Consider Reserved Instances for EC2",
                "💡 Enable S3 Intelligent Tiering",
                "💡 Optimize Lambda memory allocation",
                "💡 Use CloudWatch Logs retention policies",
                "💡 Review RDS instance sizes"
            ]
            
            for rec in recommendations:
                st.markdown(rec)
    
    with tab3:
        st.subheader("Performance Monitoring")
        
        performance_data = {
            "Metric": ["Response Time", "Throughput", "Error Rate", "Availability"],
            "Current": ["2.3s", "1,200 req/s", "0.1%", "99.9%"],
            "Target": ["<2s", ">1,000 req/s", "<0.5%", ">99.5%"],
            "Status": ["⚠️", "✅", "✅", "✅"]
        }
        
        df_performance = pd.DataFrame(performance_data)
        st.dataframe(df_performance, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Avg Response Time", "2.3s", "-0.2s")
        
        with col2:
            st.metric("Error Rate", "0.1%", "-0.05%")
        
        with col3:
            st.metric("Uptime", "99.9%", "0.1%")
