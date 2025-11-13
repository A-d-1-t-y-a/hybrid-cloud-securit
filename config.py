#!/usr/bin/env python3
"""
Configuration settings for Hybrid Cloud Security Framework
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Settings:
    """Application settings"""
    
    # Application
    APP_NAME = "Hybrid Cloud Security Framework"
    APP_VERSION = "1.0.0"
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    
    # Server
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 8000))
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key-here")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_framework.db")
    
    # Redis
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Encryption
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "your-encryption-key-here")
    AES_KEY = os.getenv("AES_KEY", "your-aes-key-here")
    
    # AWS Configuration
    # Strip whitespace and remove quotes if present
    _aws_access_key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
    _aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
    AWS_ACCESS_KEY_ID = _aws_access_key.strip('"').strip("'").strip()
    AWS_SECRET_ACCESS_KEY = _aws_secret_key.strip('"').strip("'").strip()
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1").strip().strip('"').strip("'")
    AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "").strip().strip('"').strip("'")
    
    # Monitoring
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    # Compliance
    COMPLIANCE_STANDARDS = os.getenv("COMPLIANCE_STANDARDS", "GDPR,HIPAA,SOX,ISO27001,PCI_DSS").split(",")
    AUDIT_LOG_LEVEL = os.getenv("AUDIT_LOG_LEVEL", "INFO")
    POLICY_ENFORCEMENT = os.getenv("POLICY_ENFORCEMENT", "true").lower() == "true"
    
    # SOAR
    SOAR_ENABLED = os.getenv("SOAR_ENABLED", "true").lower() == "true"
    THREAT_INTELLIGENCE_ENABLED = os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() == "true"
    AUTOMATION_ENABLED = os.getenv("AUTOMATION_ENABLED", "true").lower() == "true"
    WORKFLOW_ENGINE_ENABLED = os.getenv("WORKFLOW_ENGINE_ENABLED", "true").lower() == "true"

# Create settings instance
settings = Settings()
