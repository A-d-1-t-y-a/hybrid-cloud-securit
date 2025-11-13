#!/usr/bin/env python3
"""
Authentication and authorization services
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import JWTError, jwt
from config import settings
import hashlib
import base64

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token handling
security = HTTPBearer(auto_error=False)

def _prepare_password_for_bcrypt(password: str) -> str:
    """
    Prepare password for bcrypt hashing.
    Bcrypt has a 72-byte limit, so we ensure the password is always <= 72 bytes.
    For passwords longer than 72 bytes, we hash with SHA256 first and encode as base64.
    """
    password_bytes = password.encode('utf-8')
    
    # Bcrypt limit is 72 bytes
    if len(password_bytes) > 72:
        # Hash with SHA256 first if password is too long
        password_hash = hashlib.sha256(password_bytes).digest()
        # Encode as base64 to get a safe string representation (44 chars = 44 bytes, well under 72)
        password_str = base64.b64encode(password_hash).decode('utf-8')
        return password_str
    else:
        # Password is already <= 72 bytes, return as-is
        return password

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    try:
        prepared_password = _prepare_password_for_bcrypt(plain_password)
        return pwd_context.verify(prepared_password, hashed_password)
    except Exception:
        # Fallback: try original password (for backward compatibility with existing passwords)
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            return False

def get_password_hash(password: str) -> str:
    """Hash password"""
    prepared_password = _prepare_password_for_bcrypt(password)
    return pwd_context.hash(prepared_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from Authorization header or HttpOnly cookie."""
    token: Optional[str] = None
    # Prefer Authorization header if present
    if credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
    # Fall back to cookie
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"username": username, "role": payload.get("role", "user")}

def require_admin(current_user: dict = Depends(get_current_user)):
    """Require admin role"""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user
