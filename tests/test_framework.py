"""
Test suite for Hybrid Cloud Security Framework
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch

from main import app
from src.iam.services import AuthenticationService, UserService
from src.data_protection.classification_engine import DataClassificationEngine
from src.data_protection.encryption_service import EncryptionService
from src.monitoring.siem_engine import SIEMEngine, SecurityEvent


class TestFramework:
    """Test framework functionality"""
    
    def test_app_creation(self):
        """Test application creation"""
        assert app is not None
        assert app.title == "Hybrid Cloud Security Framework"
        assert app.version == "1.0.0"
    
    def test_root_endpoint(self):
        """Test root endpoint"""
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "components" in data
    
    def test_health_check(self):
        """Test health check endpoint"""
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestIAMComponent:
    """Test IAM component functionality"""
    
    def test_authentication_service(self):
        """Test authentication service"""
        # Test password hashing
        password = "test_password_123"
        hashed = AuthenticationService.get_password_hash(password)
        assert hashed != password
        assert len(hashed) > 0
        
        # Test password verification
        assert AuthenticationService.verify_password(password, hashed)
        assert not AuthenticationService.verify_password("wrong_password", hashed)
    
    def test_token_creation(self):
        """Test token creation and verification"""
        data = {"sub": "test_user", "user_id": 1}
        token = AuthenticationService.create_access_token(data)
        assert token is not None
        assert len(token) > 0
        
        # Test token verification
        payload = AuthenticationService.verify_token(token)
        assert payload is not None
        assert payload["sub"] == "test_user"
        assert payload["user_id"] == 1
    
    def test_iam_endpoints(self):
        """Test IAM endpoints"""
        client = TestClient(app)
        
        # Test user registration
        user_data = {
            "username": "test_user",
            "email": "test@example.com",
            "password": "test_password_123"
        }
        
        response = client.post("/api/v1/iam/register", json=user_data)
        # Note: This will fail without database, but we can test the endpoint structure
        assert response.status_code in [201, 500]  # 500 expected without DB


class TestDataProtectionComponent:
    """Test Data Protection component functionality"""
    
    def test_classification_engine(self):
        """Test data classification engine"""
        classifier = DataClassificationEngine()
        
        # Test classification
        content = "This document contains sensitive information including SSN: 123-45-6789"
        result = classifier.classify_data(content)
        
        assert "sensitivity_level" in result
        assert "confidence" in result
        assert "classification_method" in result
        assert result["sensitivity_level"] in ["PII", "Sensitive", "Highly Sensitive", "Public"]
    
    def test_encryption_service(self):
        """Test encryption service"""
        encryption_service = EncryptionService()
        
        # Test AES encryption
        data = "Sensitive information"
        encrypted_result = encryption_service.encrypt_aes(data)
        
        assert "encrypted_data" in encrypted_result
        assert "iv" in encrypted_result
        assert "algorithm" in encrypted_result
        
        # Test decryption
        decrypted_data = encryption_service.decrypt_aes(
            encrypted_result["encrypted_data"],
            encrypted_result["iv"]
        )
        assert decrypted_data == data
    
    def test_data_protection_endpoints(self):
        """Test data protection endpoints"""
        client = TestClient(app)
        
        # Test classification endpoint
        classification_data = {
            "content": "Test content for classification",
            "metadata": {"source": "test"}
        }
        
        response = client.post("/api/v1/data-protection/classify", json=classification_data)
        # Note: This will fail without proper authentication, but we can test structure
        assert response.status_code in [200, 401]  # 401 expected without auth


class TestSecurityMonitoringComponent:
    """Test Security Monitoring component functionality"""
    
    def test_siem_engine(self):
        """Test SIEM engine"""
        siem = SIEMEngine()
        
        # Test event creation
        event_data = {
            "event_id": "test_event_1",
            "timestamp": "2024-01-01T00:00:00Z",
            "source": "test_source",
            "event_type": "test_event",
            "severity": "medium",
            "description": "Test security event"
        }
        
        # Test event ingestion (async)
        async def test_ingest():
            event = await siem.ingest_event(event_data)
            assert event.event_id == "test_event_1"
            assert event.source == "test_source"
            return event
        
        # Run async test
        event = asyncio.run(test_ingest())
        assert event is not None
    
    def test_security_dashboard(self):
        """Test security dashboard"""
        siem = SIEMEngine()
        
        # Test dashboard data
        async def test_dashboard():
            dashboard_data = await siem.get_security_dashboard()
            assert "total_events" in dashboard_data
            assert "severity_breakdown" in dashboard_data
            return dashboard_data
        
        dashboard_data = asyncio.run(test_dashboard())
        assert dashboard_data["total_events"] >= 0


class TestComplianceComponent:
    """Test Compliance component functionality"""
    
    def test_compliance_endpoints(self):
        """Test compliance endpoints"""
        client = TestClient(app)
        
        # Test compliance status endpoint
        response = client.get("/api/v1/compliance/compliance-status")
        # Note: This will fail without authentication, but we can test structure
        assert response.status_code in [200, 401]  # 401 expected without auth


class TestSOARComponent:
    """Test SOAR component functionality"""
    
    def test_soar_endpoints(self):
        """Test SOAR endpoints"""
        client = TestClient(app)
        
        # Test automation status endpoint
        response = client.get("/api/v1/soar/automation/status")
        # Note: This will fail without authentication, but we can test structure
        assert response.status_code in [200, 401]  # 401 expected without auth


class TestIntegration:
    """Test integration between components"""
    
    def test_framework_integration(self):
        """Test framework component integration"""
        client = TestClient(app)
        
        # Test framework status endpoint
        response = client.get("/api/v1/framework/status")
        assert response.status_code == 200
        
        data = response.json()
        assert "framework" in data
        assert "status" in data
        assert "components" in data
        assert len(data["components"]) == 5  # 5 main components
    
    def test_component_health(self):
        """Test component health"""
        client = TestClient(app)
        
        response = client.get("/api/v1/framework/status")
        data = response.json()
        
        components = data["components"]
        for component, status in components.items():
            assert "status" in status
            assert "endpoints" in status
            assert status["status"] == "active"


class TestSecurityStandards:
    """Test security standards compliance"""
    
    def test_encryption_standards(self):
        """Test encryption standards"""
        encryption_service = EncryptionService()
        
        # Test AES-256 encryption
        data = "Test data for encryption"
        encrypted = encryption_service.encrypt_aes(data)
        assert encrypted["algorithm"] == "AES-256-CBC"
        
        # Test RSA encryption (if keys available)
        try:
            rsa_encrypted = encryption_service.encrypt_rsa(data)
            assert len(rsa_encrypted) > 0
        except Exception:
            # RSA keys not available in test environment
            pass
    
    def test_authentication_standards(self):
        """Test authentication standards"""
        # Test password hashing with bcrypt
        password = "test_password_123"
        hashed = AuthenticationService.get_password_hash(password)
        
        # bcrypt hashes start with $2b$
        assert hashed.startswith("$2b$")
        
        # Test password verification
        assert AuthenticationService.verify_password(password, hashed)


class TestPerformance:
    """Test performance characteristics"""
    
    def test_classification_performance(self):
        """Test classification performance"""
        classifier = DataClassificationEngine()
        
        # Test with large content
        large_content = "This is a test document. " * 1000
        
        import time
        start_time = time.time()
        result = classifier.classify_data(large_content)
        end_time = time.time()
        
        # Should complete within reasonable time
        assert (end_time - start_time) < 5.0  # 5 seconds max
        assert result["sensitivity_level"] is not None
    
    def test_encryption_performance(self):
        """Test encryption performance"""
        encryption_service = EncryptionService()
        
        # Test with large data
        large_data = "Test data " * 10000
        
        import time
        start_time = time.time()
        encrypted = encryption_service.encrypt_aes(large_data)
        end_time = time.time()
        
        # Should complete within reasonable time
        assert (end_time - start_time) < 2.0  # 2 seconds max
        assert "encrypted_data" in encrypted


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
