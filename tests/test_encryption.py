import pytest
from fastapi import status

def test_encrypt_decrypt_roundtrip(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    original_data = "Highly sensitive information"
    
    encrypt_response = client.post(
        "/api/v1/data-protection/encrypt",
        json={"data": original_data},
        headers=headers
    )
    assert encrypt_response.status_code == status.HTTP_200_OK
    encrypted_data = encrypt_response.json()["encrypted_data"]
    assert encrypted_data != original_data
    
    decrypt_response = client.post(
        "/api/v1/data-protection/decrypt",
        json={"encrypted_data": encrypted_data},
        headers=headers
    )
    assert decrypt_response.status_code == status.HTTP_200_OK
    assert decrypt_response.json()["decrypted_data"] == original_data

def test_classify_sensitive_data(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(
        "/api/v1/data-protection/classify",
        json={"content": "Patient medical record: SSN 123-45-6789"},
        headers=headers
    )
    assert response.status_code == status.HTTP_200_OK
    result = response.json()
    assert result["sensitivity_level"] in ["Sensitive", "Highly Sensitive"]
    assert result["confidence"] > 0.7

def test_classify_public_data(client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post(
        "/api/v1/data-protection/classify",
        json={"content": "This is a public blog post about technology"},
        headers=headers
    )
    assert response.status_code == status.HTTP_200_OK
    result = response.json()
    assert result["sensitivity_level"] == "Public"

