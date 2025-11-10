import requests
import streamlit as st
from typing import Dict, List, Optional, Any
import json
from datetime import datetime
from utils.session_manager import set_query_params

class SecurityFrameworkAPIClient:
    def __init__(self, api_base_url: str):
        self.api_base_url = api_base_url
        self.http_session = requests.Session()
        
    def _get_authentication_headers(self) -> Dict[str, str]:
        if 'authentication_token' in st.session_state and st.session_state.authentication_token:
            return {"Authorization": f"Bearer {st.session_state.authentication_token}"}
        return {}
    
    def _process_api_response(self, response: requests.Response) -> Dict[str, Any]:
        try:
            if 200 <= response.status_code < 300:
                # Treat all 2xx as success
                return {"success": True, "data": response.json()}
            elif response.status_code == 401:
                return {"success": False, "error": "Authentication required. Please login again."}
            elif response.status_code == 403:
                return {"success": False, "error": "Access forbidden. Insufficient permissions."}
            else:
                return {"success": False, "error": f"API Error {response.status_code}: {response.text}"}
        except Exception as e:
            return {"success": False, "error": f"Connection error: {str(e)}"}
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        login_url = f"{self.api_base_url}/api/v1/iam/login"
        login_payload = {"username": username, "password": password}
        response = self.http_session.post(login_url, json=login_payload)
        result = self._process_api_response(response)
        
        if result["success"] and "access_token" in result["data"]:
            st.session_state.authentication_token = result["data"]["access_token"]
            st.session_state.current_username = username
            # Role is nested under user in API response
            st.session_state.user_role = result["data"].get("user", {}).get("role", "user")
            
            # Save to query parameters for persistence across browser refresh (with cross-version support)
            set_query_params({
                'token': result["data"]["access_token"],
                'username': username,
                'role': result["data"].get("user", {}).get("role", "user")
            })
        
        return result
    
    def register_new_user(self, username: str, email: str, password: str, user_role: str = "user") -> Dict[str, Any]:
        registration_url = f"{self.api_base_url}/api/v1/iam/register"
        registration_payload = {"username": username, "email": email, "password": password, "role": user_role}
        response = self.http_session.post(registration_url, json=registration_payload)
        return self._process_api_response(response)
    
    def get_all_users(self) -> Dict[str, Any]:
        users_url = f"{self.api_base_url}/api/v1/iam/users"
        response = self.http_session.get(users_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def classify_sensitive_data(self, data_content: str, metadata: Dict = None) -> Dict[str, Any]:
        classification_url = f"{self.api_base_url}/api/v1/data-protection/classify"
        classification_payload = {"content": data_content, "metadata": metadata or {}}
        response = self.http_session.post(classification_url, json=classification_payload, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def encrypt_sensitive_data(self, data_to_encrypt: str) -> Dict[str, Any]:
        encryption_url = f"{self.api_base_url}/api/v1/data-protection/encrypt"
        encryption_payload = {"data": data_to_encrypt}
        response = self.http_session.post(encryption_url, json=encryption_payload, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def decrypt_encrypted_data(self, encrypted_data: str) -> Dict[str, Any]:
        decryption_url = f"{self.api_base_url}/api/v1/data-protection/decrypt"
        decryption_payload = {"encrypted_data": encrypted_data}
        response = self.http_session.post(decryption_url, json=decryption_payload, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def ingest_security_event(self, security_event_data: Dict[str, Any]) -> Dict[str, Any]:
        event_ingestion_url = f"{self.api_base_url}/api/v1/monitoring/events/ingest"
        response = self.http_session.post(event_ingestion_url, json=security_event_data, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_security_dashboard_data(self) -> Dict[str, Any]:
        dashboard_url = f"{self.api_base_url}/api/v1/monitoring/dashboard"
        response = self.http_session.get(dashboard_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_security_events(self) -> Dict[str, Any]:
        events_url = f"{self.api_base_url}/api/v1/monitoring/events"
        response = self.http_session.get(events_url, headers=self._get_authentication_headers())
        result = self._process_api_response(response)
        # Extract events list from response
        if result["success"] and isinstance(result["data"], dict) and "events" in result["data"]:
            result["data"] = result["data"]["events"]
        return result
    
    def get_compliance_status_overview(self) -> Dict[str, Any]:
        compliance_status_url = f"{self.api_base_url}/api/v1/compliance/status"
        response = self.http_session.get(compliance_status_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_compliance_policies_list(self) -> Dict[str, Any]:
        compliance_policies_url = f"{self.api_base_url}/api/v1/compliance/policies"
        response = self.http_session.get(compliance_policies_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_soar_workflows(self) -> Dict[str, Any]:
        soar_workflows_url = f"{self.api_base_url}/api/v1/soar/workflows"
        response = self.http_session.get(soar_workflows_url, headers=self._get_authentication_headers())
        result = self._process_api_response(response)
        # Extract workflows list from response
        if result["success"] and isinstance(result["data"], dict) and "workflows" in result["data"]:
            result["data"] = result["data"]["workflows"]
        return result
    
    def create_soar_workflow(self, workflow_configuration: Dict[str, Any]) -> Dict[str, Any]:
        soar_workflow_creation_url = f"{self.api_base_url}/api/v1/soar/workflows"
        response = self.http_session.post(soar_workflow_creation_url, json=workflow_configuration, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_soar_automation_status(self) -> Dict[str, Any]:
        soar_automation_status_url = f"{self.api_base_url}/api/v1/soar/automation/status"
        response = self.http_session.get(soar_automation_status_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_aws_cloud_status(self) -> Dict[str, Any]:
        aws_status_url = f"{self.api_base_url}/api/v1/aws/status"
        response = self.http_session.get(aws_status_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def store_data_in_aws_s3(self, data_content: str, s3_key: str) -> Dict[str, Any]:
        aws_s3_storage_url = f"{self.api_base_url}/api/v1/aws/store-data"
        s3_storage_payload = {"data": data_content, "key": s3_key}
        response = self.http_session.post(aws_s3_storage_url, json=s3_storage_payload, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def retrieve_data_from_aws_s3(self, s3_key: str) -> Dict[str, Any]:
        aws_s3_retrieval_url = f"{self.api_base_url}/api/v1/aws/retrieve-data/{s3_key}"
        response = self.http_session.get(aws_s3_retrieval_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def send_cloudwatch_metrics(self, cloudwatch_metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        cloudwatch_metrics_url = f"{self.api_base_url}/api/v1/aws/send-metrics"
        response = self.http_session.post(cloudwatch_metrics_url, json=cloudwatch_metrics_data, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_aws_security_metrics_data(self) -> Dict[str, Any]:
        aws_security_metrics_url = f"{self.api_base_url}/api/v1/aws/security-metrics"
        response = self.http_session.get(aws_security_metrics_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_security_framework_status(self) -> Dict[str, Any]:
        framework_status_url = f"{self.api_base_url}/api/v1/framework/status"
        response = self.http_session.get(framework_status_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def perform_health_check(self) -> Dict[str, Any]:
        health_check_url = f"{self.api_base_url}/health"
        response = self.http_session.get(health_check_url)
        return self._process_api_response(response)
    
    def get_dashboard_metrics(self) -> Dict[str, Any]:
        metrics_url = f"{self.api_base_url}/api/v1/dashboard/metrics"
        response = self.http_session.get(metrics_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_security_timeline(self, days: int = 30) -> Dict[str, Any]:
        timeline_url = f"{self.api_base_url}/api/v1/dashboard/security-timeline?days={days}"
        response = self.http_session.get(timeline_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_threat_summary(self) -> Dict[str, Any]:
        threat_url = f"{self.api_base_url}/api/v1/dashboard/threat-summary"
        response = self.http_session.get(threat_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_severity_distribution(self) -> Dict[str, Any]:
        severity_url = f"{self.api_base_url}/api/v1/dashboard/severity-distribution"
        response = self.http_session.get(severity_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
    
    def get_event_sources(self) -> Dict[str, Any]:
        sources_url = f"{self.api_base_url}/api/v1/dashboard/event-sources"
        response = self.http_session.get(sources_url, headers=self._get_authentication_headers())
        return self._process_api_response(response)
