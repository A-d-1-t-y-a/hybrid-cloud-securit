import streamlit as st
import pandas as pd
from services.api_client import APIClient

def show_data_classification(api_client: APIClient):
    st.title("🔍 Data Classification & Protection")
    
    tab1, tab2, tab3 = st.tabs(["🏷️ Data Classification", "🔐 Encryption Tools", "📊 Data Analytics"])
    
    with tab1:
        st.subheader("Data Classification Engine")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("**Classify Data Content**")
            content = st.text_area(
                "Enter data to classify:",
                placeholder="Enter sensitive data content here...",
                height=150
            )
            
            metadata = st.text_input("Metadata (optional)", placeholder="source, department, etc.")
            
            if st.button("🔍 Classify Data", use_container_width=True):
                if content:
                    with st.spinner("Analyzing data..."):
                        result = api_client.classify_data(content, {"metadata": metadata} if metadata else None)
                    
                    if result["success"]:
                        classification = result["data"]
                        st.success("✅ Classification completed!")
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Classification", classification.get("classification", "Unknown"))
                        with col2:
                            st.metric("Confidence", f"{classification.get('confidence', 0):.1f}%")
                        with col3:
                            st.metric("Risk Level", classification.get("risk_level", "Unknown"))
                        
                        if "suggestions" in classification:
                            st.markdown("**Recommendations:**")
                            for suggestion in classification["suggestions"]:
                                st.markdown(f"- {suggestion}")
                    else:
                        st.error(f"Classification failed: {result.get('error', 'Unknown error')}")
                else:
                    st.error("Please enter data to classify")
        
        with col2:
            st.markdown("**Classification Rules**")
            rules = [
                "🔴 **Confidential**: SSN, Credit Cards, Medical Records",
                "🟡 **Internal**: Employee Data, Financial Reports",
                "🟢 **Public**: Marketing Materials, Documentation"
            ]
            for rule in rules:
                st.markdown(rule)
    
    with tab2:
        st.subheader("Encryption & Decryption Tools")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Encrypt Data**")
            data_to_encrypt = st.text_area(
                "Data to encrypt:",
                placeholder="Enter sensitive data to encrypt...",
                height=100,
                key="encrypt_data"
            )
            
            if st.button("🔐 Encrypt", use_container_width=True):
                if data_to_encrypt:
                    with st.spinner("Encrypting data..."):
                        result = api_client.encrypt_data(data_to_encrypt)
                    
                    if result["success"]:
                        encrypted_data = result["data"]
                        st.success("✅ Data encrypted successfully!")
                        st.text_area("Encrypted Data:", encrypted_data, height=100, disabled=True)
                        
                        st.code(encrypted_data, language="text")
                    else:
                        st.error(f"Encryption failed: {result.get('error', 'Unknown error')}")
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
            
            if st.button("🔓 Decrypt", use_container_width=True):
                if encrypted_data:
                    with st.spinner("Decrypting data..."):
                        result = api_client.decrypt_data(encrypted_data)
                    
                    if result["success"]:
                        decrypted_data = result["data"]
                        st.success("✅ Data decrypted successfully!")
                        st.text_area("Decrypted Data:", decrypted_data, height=100, disabled=True)
                    else:
                        st.error(f"Decryption failed: {result.get('error', 'Unknown error')}")
                else:
                    st.error("Please enter encrypted data to decrypt")
    
    with tab3:
        st.subheader("Data Protection Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Data Classification Summary**")
            classification_summary = {
                "Classification": ["Confidential", "Internal", "Public", "Restricted"],
                "Count": [1250, 3400, 8900, 450],
                "Percentage": [8.5, 23.1, 60.4, 3.0]
            }
            df_classification = pd.DataFrame(classification_summary)
            st.dataframe(df_classification, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**Encryption Status**")
            encryption_status = {
                "Data Type": ["Database", "Files", "Backups", "Transit"],
                "Encrypted": ["Yes", "Yes", "Yes", "Yes"],
                "Algorithm": ["AES-256", "AES-256", "AES-256", "TLS 1.3"]
            }
            df_encryption = pd.DataFrame(encryption_status)
            st.dataframe(df_encryption, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Data Items", "15,000")
        
        with col2:
            st.metric("Encrypted Items", "14,250")
        
        with col3:
            st.metric("Encryption Rate", "95%")
        
        with col4:
            st.metric("Compliance Score", "98.5%")

def show_data_governance(api_client: APIClient):
    st.title("📋 Data Governance & Compliance")
    
    tab1, tab2, tab3 = st.tabs(["📊 Data Inventory", "🛡️ Privacy Controls", "📈 Compliance Metrics"])
    
    with tab1:
        st.subheader("Data Inventory")
        
        inventory_data = {
            "Data Source": ["Customer Database", "Employee Records", "Financial Data", "Health Records", "Log Files"],
            "Data Type": ["PII", "HR Data", "Financial", "PHI", "System Logs"],
            "Classification": ["Confidential", "Internal", "Confidential", "Restricted", "Internal"],
            "Retention": ["7 years", "5 years", "10 years", "6 years", "1 year"],
            "Owner": ["Data Team", "HR Team", "Finance", "Medical", "IT Team"]
        }
        
        df_inventory = pd.DataFrame(inventory_data)
        st.dataframe(df_inventory, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Data Sources", "25")
        
        with col2:
            st.metric("PII Records", "45,000")
        
        with col3:
            st.metric("Compliance Rate", "96%")
    
    with tab2:
        st.subheader("Privacy Controls")
        
        controls = [
            {"Control": "Data Minimization", "Status": "Active", "Coverage": "95%"},
            {"Control": "Purpose Limitation", "Status": "Active", "Coverage": "98%"},
            {"Control": "Storage Limitation", "Status": "Active", "Coverage": "92%"},
            {"Control": "Accuracy & Quality", "Status": "Active", "Coverage": "97%"},
            {"Control": "Security Safeguards", "Status": "Active", "Coverage": "99%"},
            {"Control": "Accountability", "Status": "Active", "Coverage": "94%"}
        ]
        
        df_controls = pd.DataFrame(controls)
        st.dataframe(df_controls, use_container_width=True, hide_index=True)
    
    with tab3:
        st.subheader("Compliance Metrics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**GDPR Compliance**")
            gdpr_metrics = {
                "Requirement": ["Lawful Basis", "Consent Management", "Data Subject Rights", "DPIA", "Breach Notification"],
                "Status": ["✅", "✅", "✅", "✅", "✅"],
                "Score": ["98%", "95%", "92%", "96%", "99%"]
            }
            df_gdpr = pd.DataFrame(gdpr_metrics)
            st.dataframe(df_gdpr, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("**HIPAA Compliance**")
            hipaa_metrics = {
                "Safeguard": ["Administrative", "Physical", "Technical"],
                "Implementation": ["Complete", "Complete", "Complete"],
                "Score": ["97%", "94%", "96%"]
            }
            df_hipaa = pd.DataFrame(hipaa_metrics)
            st.dataframe(df_hipaa, use_container_width=True, hide_index=True)
