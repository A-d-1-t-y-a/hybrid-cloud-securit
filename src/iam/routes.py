"""
IAM API Routes for Hybrid Cloud Security Framework
"""

from datetime import timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.iam.services import (
    UserService, RoleService, PermissionService, 
    SessionService, MFAService, AuthenticationService
)
from src.iam.schemas import (
    UserCreate, UserResponse, UserUpdate, RoleCreate, RoleResponse,
    PermissionCreate, PermissionResponse, LoginRequest, LoginResponse,
    MFARequest, MFAVerify, SessionInfo, AccessControlRequest, AccessControlResponse
)

router = APIRouter()
security = HTTPBearer()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """Register new user"""
    user_service = UserService(db)
    
    # Check if user already exists
    existing_user = await user_service.get_user_by_username(user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    existing_email = await user_service.get_user_by_email(user_data.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    user = await user_service.create_user(user_data)
    return user


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """User login"""
    user_service = UserService(db)
    session_service = SessionService(db)
    
    # Authenticate user
    user = await user_service.authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Create access token
    access_token = AuthenticationService.create_access_token(
        data={"sub": user.username, "user_id": user.id}
    )
    
    # Create session
    session = await session_service.create_session(
        user.id, 
        expires_in_hours=24 if login_data.remember_me else 8
    )
    
    return LoginResponse(
        access_token=access_token,
        expires_in=30 * 60,  # 30 minutes
        user=user
    )


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get user by ID"""
    user_service = UserService(db)
    user = await user_service.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Update user"""
    user_service = UserService(db)
    user = await user_service.update_user(user_id, user_data)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Create new role"""
    role_service = RoleService(db)
    
    # Check if role already exists
    existing_role = await role_service.get_role_by_name(role_data.name)
    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role already exists"
        )
    
    role = await role_service.create_role(role_data)
    return role


@router.get("/roles", response_model=List[RoleResponse])
async def get_roles(
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get all roles"""
    role_service = RoleService(db)
    # This would need to be implemented in RoleService
    return []


@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    permission_data: PermissionCreate,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Create new permission"""
    permission_service = PermissionService(db)
    permission = await permission_service.create_permission(permission_data)
    return permission


@router.post("/mfa/add", status_code=status.HTTP_201_CREATED)
async def add_mfa_factor(
    mfa_data: MFARequest,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Add MFA factor for user"""
    mfa_service = MFAService(db)
    mfa_factor = await mfa_service.add_mfa_factor(
        mfa_data.user_id,
        mfa_data.factor_type,
        mfa_data.factor_data
    )
    return {"message": "MFA factor added successfully", "factor_id": mfa_factor.id}


@router.post("/mfa/verify")
async def verify_mfa(
    mfa_data: MFAVerify,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Verify MFA code"""
    mfa_service = MFAService(db)
    is_valid = await mfa_service.verify_mfa_code(
        mfa_data.user_id,
        mfa_data.factor_id,
        mfa_data.code
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code"
        )
    
    return {"message": "MFA verification successful"}


@router.get("/sessions/{session_token}", response_model=SessionInfo)
async def get_session_info(
    session_token: str,
    db: AsyncSession = Depends(get_db)
):
    """Get session information"""
    session_service = SessionService(db)
    session = await session_service.get_session(session_token)
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired"
        )
    
    return session


@router.post("/access-control", response_model=AccessControlResponse)
async def check_access_control(
    access_request: AccessControlRequest,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Check access control for user"""
    permission_service = PermissionService(db)
    user_permissions = await permission_service.get_user_permissions(access_request.user_id)
    
    # Check if user has required permission
    required_permission = f"{access_request.resource}:{access_request.action}"
    has_permission = any(
        f"{perm.resource}:{perm.action}" == required_permission 
        for perm in user_permissions
    )
    
    return AccessControlResponse(
        allowed=has_permission,
        reason="Permission granted" if has_permission else "Insufficient permissions",
        required_permissions=[required_permission] if not has_permission else []
    )


@router.post("/logout")
async def logout(
    session_token: str,
    db: AsyncSession = Depends(get_db)
):
    """Logout user"""
    session_service = SessionService(db)
    success = await session_service.invalidate_session(session_token)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return {"message": "Logout successful"}
