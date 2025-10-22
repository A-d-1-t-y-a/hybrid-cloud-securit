import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import random

def create_metrics_cards(api_client):
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🔐 Active Users",
            value="1,247",
            delta="12%"
        )
    
    with col2:
        st.metric(
            label="🛡️ Security Events",
            value="3,456",
            delta="-5%"
        )
    
    with col3:
        st.metric(
            label="📊 Compliance Score",
            value="98.5%",
            delta="2.1%"
        )
    
    with col4:
        st.metric(
            label="☁️ AWS Resources",
            value="156",
            delta="8%"
        )

def create_security_chart():
    st.subheader("🔒 Security Events Timeline")
    
    dates = pd.date_range(start=datetime.now() - timedelta(days=30), end=datetime.now(), freq='D')
    events = [random.randint(10, 100) for _ in range(len(dates))]
    
    df = pd.DataFrame({
        'Date': dates,
        'Events': events
    })
    
    fig = px.line(df, x='Date', y='Events', title='Security Events Over Time')
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white'
    )
    
    st.plotly_chart(fig, use_container_width=True)

def create_compliance_chart():
    st.subheader("📋 Compliance Status")
    
    compliance_data = {
        'GDPR': 98,
        'HIPAA': 95,
        'SOX': 92,
        'ISO 27001': 96,
        'PCI DSS': 94
    }
    
    fig = go.Figure(data=[
        go.Bar(
            x=list(compliance_data.keys()),
            y=list(compliance_data.values()),
            marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']
        )
    ])
    
    fig.update_layout(
        title="Compliance Scores by Standard",
        xaxis_title="Compliance Standards",
        yaxis_title="Score (%)",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white'
    )
    
    st.plotly_chart(fig, use_container_width=True)

def create_threat_intelligence():
    st.subheader("🎯 Threat Intelligence")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Recent Threats**")
        threats = [
            "🚨 High: Suspicious login attempts from unknown IP",
            "⚠️ Medium: Unusual data access pattern detected",
            "ℹ️ Low: New device registered in network",
            "🔍 Info: Security scan completed successfully"
        ]
        
        for threat in threats:
            st.markdown(f"- {threat}")
    
    with col2:
        st.markdown("**Security Score**")
        
        score = 87
        st.progress(score / 100)
        st.markdown(f"**Overall Security Score: {score}%**")
        
        if score >= 90:
            st.success("🟢 Excellent security posture")
        elif score >= 70:
            st.warning("🟡 Good security posture")
        else:
            st.error("🔴 Security improvements needed")

def create_aws_resources():
    st.subheader("☁️ AWS Resources Status")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**S3 Buckets**")
        st.metric("Active", "12", "2 new")
        st.metric("Storage Used", "2.4 TB", "15%")
    
    with col2:
        st.markdown("**Lambda Functions**")
        st.metric("Active", "8", "1 new")
        st.metric("Executions", "1,234", "23%")
    
    with col3:
        st.markdown("**CloudWatch**")
        st.metric("Alarms", "24", "3 new")
        st.metric("Logs", "45.6 GB", "8%")

def show_dashboard(api_client):
    st.title("🏠 Security Dashboard")
    
    create_metrics_cards(api_client)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        create_security_chart()
    
    with col2:
        create_compliance_chart()
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        create_threat_intelligence()
    
    with col2:
        create_aws_resources()
