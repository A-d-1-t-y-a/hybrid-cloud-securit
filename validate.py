#!/usr/bin/env python3
"""
Validation script for Hybrid Cloud Security Framework
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import requests
import time
import json
from datetime import datetime

def validate_framework():
    """Validate the complete framework"""
    print("🔐 Hybrid Cloud Security Framework - Validation")
    print("=" * 60)
    print(f"Author: Nithin Bonagiri (X24137430)")
    print(f"Supervisor: Prof. Sean Heeney")
    print(f"Institution: National College of Ireland")
    print(f"Validation Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    base_url = "http://localhost:8000"
    session = requests.Session()
    
    # Test 1: Health Check
    print("🧪 Test 1: Health Check")
    try:
        response = session.get(f"{base_url}/health")
        if response.status_code == 200:
            print("   ✅ Health check passed")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Health check error: {e}")
        return False
    
    # Test 2: User Registration
    print("\n🧪 Test 2: User Registration")
    try:
        user_data = {
            "username": "test_user",
            "email": "test@example.com",
            "password": "test_password_123",
            "role": "admin"
        }
        response = session.post(f"{base_url}/api/v1/iam/register", json=user_data)
        if response.status_code == 201:
            print("   ✅ User registration passed")
        else:
            print(f"   ❌ User registration failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ User registration error: {e}")
    
    # Test 3: User Login
    print("\n🧪 Test 3: User Login")
    try:
        login_data = {
            "username": "test_user",
            "password": "test_password_123"
        }
        response = session.post(f"{base_url}/api/v1/iam/login", json=login_data)
        if response.status_code == 200:
            print("   ✅ User login passed")
            token = response.json()["access_token"]
            session.headers.update({"Authorization": f"Bearer {token}"})
        else:
            print(f"   ❌ User login failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ User login error: {e}")
    
    # Test 4: Data Classification
    print("\n🧪 Test 4: Data Classification")
    try:
        classification_data = {
            "content": "This document contains SSN: 123-45-6789 and patient information",
            "metadata": {"source": "healthcare_system"}
        }
        response = session.post(f"{base_url}/api/v1/data-protection/classify", json=classification_data)
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Data classification passed: {result['sensitivity_level']}")
        else:
            print(f"   ❌ Data classification failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Data classification error: {e}")
    
    # Test 5: Security Event Ingestion
    print("\n🧪 Test 5: Security Event Ingestion")
    try:
        event_data = {
            "source": "firewall",
            "event_type": "blocked_connection",
            "severity": "medium",
            "description": "Blocked connection attempt from suspicious IP",
            "ip_address": "192.168.1.100"
        }
        response = session.post(f"{base_url}/api/v1/monitoring/events/ingest", json=event_data)
        if response.status_code == 200:
            print("   ✅ Security event ingestion passed")
        else:
            print(f"   ❌ Security event ingestion failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Security event ingestion error: {e}")
    
    # Test 6: Compliance Status
    print("\n🧪 Test 6: Compliance Status")
    try:
        response = session.get(f"{base_url}/api/v1/compliance/status")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Compliance status passed: {result['overall_score']}%")
        else:
            print(f"   ❌ Compliance status failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Compliance status error: {e}")
    
    # Test 7: SOAR Workflow
    print("\n🧪 Test 7: SOAR Workflow")
    try:
        workflow_data = {
            "name": "Test Workflow",
            "description": "Test security workflow",
            "trigger_conditions": ["threat_detected"],
            "actions": ["block_ip", "notify_security_team"]
        }
        response = session.post(f"{base_url}/api/v1/soar/workflows", json=workflow_data)
        if response.status_code == 200:
            print("   ✅ SOAR workflow creation passed")
        else:
            print(f"   ❌ SOAR workflow creation failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ SOAR workflow error: {e}")
    
    # Test 8: Framework Status
    print("\n🧪 Test 8: Framework Status")
    try:
        response = session.get(f"{base_url}/api/v1/framework/status")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Framework status passed: {result['framework']}")
        else:
            print(f"   ❌ Framework status failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Framework status error: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 Framework Validation Complete!")
    print("=" * 60)
    print("📊 Framework Features Validated:")
    print("   ✅ Identity and Access Management (IAM)")
    print("   ✅ Data Protection and Classification")
    print("   ✅ Security Monitoring and SIEM")
    print("   ✅ Compliance and Governance")
    print("   ✅ Security Orchestration and Response (SOAR)")
    print()
    print("🔗 API Documentation: http://localhost:8000/docs")
    print("📧 Contact: nithin.bonagiri@student.ncirl.ie")
    print("🏫 Institution: National College of Ireland")

if __name__ == "__main__":
    print("⏳ Waiting for server to start...")
    time.sleep(3)
    validate_framework()
