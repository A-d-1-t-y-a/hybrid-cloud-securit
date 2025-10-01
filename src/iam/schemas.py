"""
IAM Pydantic schemas for request/response validation
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    """Base user schema"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    is_active: bool = True


class UserCreate(UserBase):
    """User creation schema"""
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    """User update schema"""
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """User response schema"""
    id: int
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class RoleBase(BaseModel):
    """Base role schema"""
    name: str = Field(..., min_length=3, max_length=50)
    description: Optional[str] = None


class RoleCreate(RoleBase):
    """Role creation schema"""
    pass


class RoleResponse(RoleBase):
    """Role response schema"""
    id: int
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class PermissionBase(BaseModel):
    """Base permission schema"""
    name: str = Field(..., min_length=3, max_length=100)
    resource: str = Field(..., min_length=3, max_length=100)
    action: str = Field(..., min_length=3, max_length=50)
    description: Optional[str] = None


class PermissionCreate(PermissionBase):
    """Permission creation schema"""
    pass


class PermissionResponse(PermissionBase):
    """Permission response schema"""
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    """Login request schema"""
    username: str
    password: str
    remember_me: bool = False


class LoginResponse(BaseModel):
    """Login response schema"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenData(BaseModel):
    """Token data schema"""
    username: Optional[str] = None
    user_id: Optional[int] = None
    roles: List[str] = []
    permissions: List[str] = []


class MFARequest(BaseModel):
    """MFA request schema"""
    user_id: int
    factor_type: str = Field(..., regex="^(totp|sms|email|hardware)$")
    factor_data: dict


class MFAVerify(BaseModel):
    """MFA verification schema"""
    user_id: int
    factor_id: int
    code: str


class FederatedLoginRequest(BaseModel):
    """Federated login request schema"""
    provider: str = Field(..., regex="^(saml|oauth|openid)$")
    external_id: str
    provider_data: dict


class SessionInfo(BaseModel):
    """Session information schema"""
    session_id: str
    user_id: int
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    is_active: bool


class AccessControlRequest(BaseModel):
    """Access control request schema"""
    user_id: int
    resource: str
    action: str
    context: Optional[dict] = None


class AccessControlResponse(BaseModel):
    """Access control response schema"""
    allowed: bool
    reason: Optional[str] = None
    required_roles: List[str] = []
    required_permissions: List[str] = []
