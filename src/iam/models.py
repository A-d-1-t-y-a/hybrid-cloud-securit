"""
IAM Models for Hybrid Cloud Security Framework
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from src.core.database import Base


class User(Base):
    """User model for IAM"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    roles = relationship("UserRole", back_populates="user")
    sessions = relationship("UserSession", back_populates="user")


class Role(Base):
    """Role model for RBAC"""
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    users = relationship("UserRole", back_populates="role")
    permissions = relationship("RolePermission", back_populates="role")


class Permission(Base):
    """Permission model for fine-grained access control"""
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    resource = Column(String(100), nullable=False)
    action = Column(String(50), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    roles = relationship("RolePermission", back_populates="permission")


class UserRole(Base):
    """User-Role association"""
    __tablename__ = "user_roles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    role_id = Column(Integer, nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow)
    assigned_by = Column(Integer)
    
    # Relationships
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")


class RolePermission(Base):
    """Role-Permission association"""
    __tablename__ = "role_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, nullable=False)
    permission_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")


class UserSession(Base):
    """User session model"""
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    session_token = Column(String(255), unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")


class FederatedIdentity(Base):
    """Federated identity model for SSO"""
    __tablename__ = "federated_identities"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    provider = Column(String(50), nullable=False)  # saml, oauth, openid
    external_id = Column(String(255), nullable=False)
    provider_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)


class MFAFactor(Base):
    """Multi-factor authentication factor"""
    __tablename__ = "mfa_factors"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    factor_type = Column(String(50), nullable=False)  # totp, sms, email, hardware
    factor_data = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime)
