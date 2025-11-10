import streamlit as st
import pandas as pd
from services.api_client import SecurityFrameworkAPIClient

def show_data_classification(api_client: SecurityFrameworkAPIClient):
    st.title("Data Classification & Protection")
    
    # Refresh button
    if st.button("Refresh", key="refresh_data_protection", use_container_width=False):
        st.rerun()
    
    st.markdown("---")
    
    # Data Classification Section
    st.subheader("Data Classification")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        content = st.text_area(
            "Enter data to classify:",
            placeholder="Enter sensitive data content here...",
            height=120
        )
        
        if st.button("Classify Data", use_container_width=True):
            if content:
                with st.spinner("Analyzing data..."):
                    result = api_client.classify_sensitive_data(content, None)
                
                if result["success"]:
                    classification = result["data"]
                    st.success("Classification completed!")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Classification", classification.get("classification", "Unknown"))
                    with col2:
                        st.metric("Confidence", f"{classification.get('confidence', 0):.1f}%")
                    with col3:
                        st.metric("Risk Level", classification.get("risk_level", "Unknown"))
                else:
                    st.error(f"Classification failed: {result.get('error', 'Unknown error')}")
            else:
                st.error("Please enter data to classify")
    
    with col2:
        st.markdown("**Classification Levels**")
        st.markdown("**Confidential**: Highly sensitive")
        st.markdown("**Internal**: Company use only")
        st.markdown("**Public**: General access")
    
    st.markdown("---")
    
    # Encryption & Decryption Section
    st.subheader("Encryption & Decryption")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Encrypt Data**")
        data_to_encrypt = st.text_area(
            "Data to encrypt:",
            placeholder="Enter sensitive data to encrypt...",
            height=100,
            key="encrypt_data"
        )
        
        if st.button("Encrypt", use_container_width=True):
            if data_to_encrypt:
                with st.spinner("Encrypting..."):
                    result = api_client.encrypt_sensitive_data(data_to_encrypt)
                
                if result["success"]:
                    encrypted_data = result["data"]
                    st.success("Encrypted successfully!")
                    st.code(encrypted_data, language="text")
                else:
                    st.error(f"Error: {result.get('error', 'Encryption failed')}")
            else:
                st.error("Please enter data to encrypt")
    
    with col2:
        st.markdown("**Decrypt Data**")
        encrypted_data = st.text_area(
            "Encrypted data:",
            placeholder="Enter encrypted data to decrypt...",
            height=100,
            key="decrypt_data"
        )
        
        if st.button("Decrypt", use_container_width=True):
            if encrypted_data:
                with st.spinner("Decrypting..."):
                    result = api_client.decrypt_encrypted_data(encrypted_data)
                
                if result["success"]:
                    decrypted_data = result["data"]
                    st.success("Decrypted successfully!")
                    st.code(decrypted_data, language="text")
                else:
                    st.error(f"Error: {result.get('error', 'Decryption failed')}")
            else:
                st.error("Please enter encrypted data to decrypt")
