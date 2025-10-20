#!/usr/bin/env python3
"""
Database models for Hybrid Cloud Security Framework
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class User(Base):
    """User model for IAM"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class SecurityEvent(Base):
    """Security event model for monitoring"""
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(100), unique=True, index=True)
    source = Column(String(100), nullable=False)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text)
    user_id = Column(String(100))
    ip_address = Column(String(45))
    metadata = Column(JSON)
    created_at = Column(DateTime, default=func.now())

class DataClassification(Base):
    """Data classification model"""
    __tablename__ = "data_classifications"
    
    id = Column(Integer, primary_key=True, index=True)
    content_hash = Column(String(255), unique=True, index=True)
    sensitivity_level = Column(String(50), nullable=False)
    confidence = Column(String(10), nullable=False)
    classification_method = Column(String(50), nullable=False)
    metadata = Column(JSON)
    created_at = Column(DateTime, default=func.now())

class CompliancePolicy(Base):
    """Compliance policy model"""
    __tablename__ = "compliance_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(String(100), unique=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    policy_type = Column(String(50), nullable=False)
    compliance_standards = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class SOARWorkflow(Base):
    """SOAR workflow model"""
    __tablename__ = "soar_workflows"
    
    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(String(100), unique=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    trigger_conditions = Column(JSON)
    actions = Column(JSON)
    status = Column(String(20), default="active")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class AuditLog(Base):
    """Audit log model"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100))
    action = Column(String(100), nullable=False)
    resource = Column(String(200))
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    metadata = Column(JSON)
    created_at = Column(DateTime, default=func.now())
