import pytest
from fastapi import status

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "operational"

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "healthy"

def test_register_user(client, test_user_data):
    response = client.post("/api/v1/iam/register", json=test_user_data)
    assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST]

def test_login(client, test_user_data):
    client.post("/api/v1/iam/register", json=test_user_data)
    response = client.post("/api/v1/iam/login", json={
        "username": test_user_data["username"],
        "password": test_user_data["password"]
    })
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()

def test_get_users(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/iam/users", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)

def test_classify_data(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(
        "/api/v1/data-protection/classify",
        json={"content": "This is a test email: user@example.com"},
        headers=headers
    )
    assert response.status_code == status.HTTP_200_OK
    assert "sensitivity_level" in response.json()

def test_encrypt_data(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(
        "/api/v1/data-protection/encrypt",
        json={"data": "Sensitive information"},
        headers=headers
    )
    assert response.status_code == status.HTTP_200_OK
    assert "encrypted_data" in response.json()

def test_decrypt_data(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    encrypt_response = client.post(
        "/api/v1/data-protection/encrypt",
        json={"data": "Test data"},
        headers=headers
    )
    encrypted_data = encrypt_response.json()["encrypted_data"]
    
    response = client.post(
        "/api/v1/data-protection/decrypt",
        json={"encrypted_data": encrypted_data},
        headers=headers
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["decrypted_data"] == "Test data"

def test_ingest_event(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(
        "/api/v1/monitoring/events/ingest",
        json={
            "source": "test_source",
            "event_type": "security_alert",
            "severity": "high",
            "description": "Test security event"
        },
        headers=headers
    )
    assert response.status_code == status.HTTP_200_OK

def test_get_security_dashboard(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/monitoring/dashboard", headers=headers)
    assert response.status_code == status.HTTP_200_OK

def test_get_events(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/monitoring/events", headers=headers)
    assert response.status_code == status.HTTP_200_OK

def test_get_compliance_status(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/compliance/status", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert "overall_score" in response.json()

def test_get_policies(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/compliance/policies", headers=headers)
    assert response.status_code == status.HTTP_200_OK

def test_create_workflow(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(
        "/api/v1/soar/workflows",
        json={
            "name": "Test Workflow",
            "description": "Test workflow description",
            "trigger_conditions": ["condition1"],
            "actions": ["action1"]
        },
        headers=headers
    )
    assert response.status_code == status.HTTP_200_OK

def test_get_workflows(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/soar/workflows", headers=headers)
    assert response.status_code == status.HTTP_200_OK

def test_get_automation_status(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/soar/automation/status", headers=headers)
    assert response.status_code == status.HTTP_200_OK

def test_aws_status(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/aws/status", headers=headers)
    assert response.status_code == status.HTTP_200_OK

def test_framework_status(client):
    response = client.get("/api/v1/framework/status")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "operational"

