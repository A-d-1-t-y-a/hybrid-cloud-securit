import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta

def create_metrics_cards(api_client):
    """Create dynamic metrics cards from real data"""
    result = api_client.get_dashboard_metrics()
    
    if result["success"]:
        metrics = result["data"]
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label=metrics['active_users']['label'],
                value=metrics['active_users']['value'],
                delta=metrics['active_users']['delta']
            )
        
        with col2:
            st.metric(
                label=metrics['security_events']['label'],
                value=metrics['security_events']['value'],
                delta=metrics['security_events']['delta']
            )
        
        with col3:
            st.metric(
                label=metrics['compliance_score']['label'],
                value=f"{metrics['compliance_score']['value']}%",
                delta=metrics['compliance_score']['delta']
            )
        
        with col4:
            st.metric(
                label=metrics['active_workflows']['label'],
                value=metrics['active_workflows']['value'],
                delta=metrics['active_workflows']['delta']
            )
    else:
        st.error("Failed to load dashboard metrics")

def create_security_chart(api_client):
    """Create dynamic security events timeline from real data"""
    st.subheader("Security Events Timeline")
    
    result = api_client.get_security_timeline(days=30)
    
    if result["success"] and result["data"]["timeline"]:
        timeline_data = result["data"]["timeline"]
        
        df = pd.DataFrame(timeline_data)
        df['date'] = pd.to_datetime(df['date'])
        
        fig = px.line(df, x='date', y='count', title='Security Events Over Time')
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            xaxis_title="Date",
            yaxis_title="Event Count"
        )
        
        st.plotly_chart(fig, use_container_width=True)
        st.info(f"Total Events (30 days): {result['data']['total_events']}")
    else:
        st.info("No security events data available. Start by creating some security events in the Monitoring section.")

def create_compliance_chart(api_client):
    """Create dynamic compliance status chart from real data"""
    st.subheader("Compliance Status")
    
    result = api_client.get_compliance_status_overview()
    
    if result["success"]:
        compliance_data = result["data"].get("standards", {})
        
        if compliance_data:
            standards = list(compliance_data.keys())
            scores = [compliance_data[std].get("score", 0) for std in standards]
            
            fig = go.Figure(data=[
                go.Bar(
                    x=standards,
                    y=scores,
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
            st.info(f"Overall Compliance Score: {result['data'].get('overall_score', 0)}%")
        else:
            st.info("No compliance data available")
    else:
        st.error("Failed to load compliance data")

def create_threat_intelligence(api_client):
    """Create dynamic threat intelligence from real data"""
    st.subheader("Threat Intelligence")
    
    result = api_client.get_threat_summary()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Recent Threats**")
        
        if result["success"] and result["data"]["threats"]:
            threats = result["data"]["threats"]
            for threat in threats[:10]:  # Show top 10
                st.markdown(f"- {threat['icon']} {threat['severity'].capitalize()}: {threat['description']}")
        else:
            st.info("No recent threats detected")
    
    with col2:
        st.markdown("**Security Score**")
        
        if result["success"]:
            score = int(result["data"]["security_score"])
            st.progress(score / 100)
            st.markdown(f"**Overall Security Score: {score}%**")
            
            if score >= 90:
                st.success("Excellent security posture")
            elif score >= 70:
                st.warning("Good security posture")
            else:
                st.error("Security improvements needed")
        else:
            st.info("Security score unavailable")

def create_event_sources(api_client):
    """Create dynamic event sources chart from real data"""
    st.subheader("Top Event Sources")
    
    result = api_client.get_event_sources()
    
    if result["success"] and result["data"]["sources"]:
        sources_data = result["data"]["sources"]
        df = pd.DataFrame(sources_data)
        
        fig = px.bar(df, x='source', y='count', title='Events by Source')
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            xaxis_title="Source",
            yaxis_title="Event Count"
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No event source data available")

def show_dashboard(api_client):
    """Main dashboard with dynamic data from backend"""
    st.title("Security Dashboard")
    
    # Refresh button
    if st.button("Refresh Dashboard", key="refresh_dashboard", use_container_width=False):
        st.rerun()
    
    create_metrics_cards(api_client)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        create_security_chart(api_client)
    
    with col2:
        create_compliance_chart(api_client)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        create_threat_intelligence(api_client)
    
    with col2:
        create_event_sources(api_client)
