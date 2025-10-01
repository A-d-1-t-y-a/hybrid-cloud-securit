"""
Configuration management for Hybrid Cloud Security Framework
"""

import os
from typing import List, Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "Hybrid Cloud Security Framework"
    VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # Database
    DATABASE_URL: str = Field(env="DATABASE_URL", default="postgresql://localhost:5432/hybrid_cloud_security")
    REDIS_URL: str = Field(env="REDIS_URL", default="redis://localhost:6379/0")
    
    # Security
    SECRET_KEY: str = Field(env="SECRET_KEY", default="your-secret-key-here")
    JWT_SECRET_KEY: str = Field(env="JWT_SECRET_KEY", default="your-jwt-secret-key-here")
    JWT_ALGORITHM: str = Field(env="JWT_ALGORITHM", default="HS256")
    JWT_EXPIRE_MINUTES: int = Field(env="JWT_EXPIRE_MINUTES", default=30)
    
    # Encryption
    AES_KEY: str = Field(env="AES_KEY", default="your-aes-256-key-here")
    RSA_PRIVATE_KEY: Optional[str] = Field(env="RSA_PRIVATE_KEY", default=None)
    RSA_PUBLIC_KEY: Optional[str] = Field(env="RSA_PUBLIC_KEY", default=None)
    
    # Cloud Providers
    AWS_ACCESS_KEY_ID: Optional[str] = Field(env="AWS_ACCESS_KEY_ID", default=None)
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(env="AWS_SECRET_ACCESS_KEY", default=None)
    AWS_REGION: str = Field(env="AWS_REGION", default="us-east-1")
    
    AZURE_CLIENT_ID: Optional[str] = Field(env="AZURE_CLIENT_ID", default=None)
    AZURE_CLIENT_SECRET: Optional[str] = Field(env="AZURE_CLIENT_SECRET", default=None)
    AZURE_TENANT_ID: Optional[str] = Field(env="AZURE_TENANT_ID", default=None)
    
    GCP_PROJECT_ID: Optional[str] = Field(env="GCP_PROJECT_ID", default=None)
    GCP_CREDENTIALS_PATH: Optional[str] = Field(env="GCP_CREDENTIALS_PATH", default=None)
    
    # Monitoring
    ELASTICSEARCH_URL: str = Field(env="ELASTICSEARCH_URL", default="http://localhost:9200")
    PROMETHEUS_URL: str = Field(env="PROMETHEUS_URL", default="http://localhost:9090")
    LOG_LEVEL: str = Field(env="LOG_LEVEL", default="INFO")
    
    # CORS
    ALLOWED_ORIGINS: List[str] = Field(
        env="ALLOWED_ORIGINS", 
        default=["http://localhost:3000", "http://localhost:8080"]
    )
    
    # Expert Panel
    EXPERT_PANEL_SIZE: int = Field(env="EXPERT_PANEL_SIZE", default=10)
    VALIDATION_PHASES: int = Field(env="VALIDATION_PHASES", default=4)
    
    # Case Studies
    CASE_STUDY_ORGANIZATIONS: int = Field(env="CASE_STUDY_ORGANIZATIONS", default=5)
    IMPLEMENTATION_TIMELINE: int = Field(env="IMPLEMENTATION_TIMELINE", default=24)
    
    # Security Standards
    ENABLE_SAML: bool = Field(env="ENABLE_SAML", default=True)
    ENABLE_OAUTH: bool = Field(env="ENABLE_OAUTH", default=True)
    ENABLE_OPENID: bool = Field(env="ENABLE_OPENID", default=True)
    ENABLE_MFA: bool = Field(env="ENABLE_MFA", default=True)
    
    # Compliance Standards
    ENABLE_GDPR: bool = Field(env="ENABLE_GDPR", default=True)
    ENABLE_HIPAA: bool = Field(env="ENABLE_HIPAA", default=True)
    ENABLE_SOX: bool = Field(env="ENABLE_SOX", default=True)
    ENABLE_ISO27001: bool = Field(env="ENABLE_ISO27001", default=True)
    ENABLE_PCI_DSS: bool = Field(env="ENABLE_PCI_DSS", default=True)
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get application settings"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
