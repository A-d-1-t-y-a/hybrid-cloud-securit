from pydantic import BaseModel, EmailStr
from typing import Dict, List, Optional, Any

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ClassificationRequest(BaseModel):
    content: str
    metadata: Optional[Dict] = None

class ClassificationResponse(BaseModel):
    sensitivity_level: str
    confidence: float
    classification_method: str
    timestamp: str

class SecurityEventRequest(BaseModel):
    source: str
    event_type: str
    severity: str
    description: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None

class ComplianceStatus(BaseModel):
    overall_score: int
    standards: Dict[str, Dict[str, Any]]
    recommendations: List[str]

class SOARWorkflowRequest(BaseModel):
    name: str
    description: str
    trigger_conditions: List[str]
    actions: List[str]
    status: str = "active"

