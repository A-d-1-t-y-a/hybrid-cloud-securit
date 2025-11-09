import pytest
from fastapi import status

def test_register_duplicate_user(client, test_user_data):
    client.post("/api/v1/iam/register", json=test_user_data)
    response = client.post("/api/v1/iam/register", json=test_user_data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

def test_login_invalid_credentials(client, test_user_data):
    client.post("/api/v1/iam/register", json=test_user_data)
    response = client.post("/api/v1/iam/login", json={
        "username": test_user_data["username"],
        "password": "WrongPassword"
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_protected_endpoint_without_token(client):
    response = client.get("/api/v1/iam/users")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_protected_endpoint_with_invalid_token(client):
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/api/v1/iam/users", headers=headers)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_protected_endpoint_with_valid_token(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/api/v1/iam/users", headers=headers)
    assert response.status_code == status.HTTP_200_OK

