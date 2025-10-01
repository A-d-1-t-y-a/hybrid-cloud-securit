"""
IAM Services for Hybrid Cloud Security Framework
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from src.core.config import get_settings
from src.iam.models import User, Role, Permission, UserRole, RolePermission, UserSession, MFAFactor
from src.iam.schemas import UserCreate, UserUpdate, RoleCreate, PermissionCreate

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthenticationService:
    """Authentication service"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Hash password"""
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """Verify token"""
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            return payload
        except JWTError:
            return None


class UserService:
    """User management service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_user(self, user_data: UserCreate) -> User:
        """Create new user"""
        hashed_password = AuthenticationService.get_password_hash(user_data.password)
        user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            is_active=user_data.is_active
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        result = await self.db.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()
    
    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()
    
    async def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        """Update user"""
        user = await self.get_user_by_id(user_id)
        if not user:
            return None
        
        update_data = user_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user"""
        user = await self.get_user_by_username(username)
        if not user or not user.is_active:
            return None
        
        if not AuthenticationService.verify_password(password, user.hashed_password):
            return None
        
        return user


class RoleService:
    """Role management service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_role(self, role_data: RoleCreate) -> Role:
        """Create new role"""
        role = Role(**role_data.dict())
        self.db.add(role)
        await self.db.commit()
        await self.db.refresh(role)
        return role
    
    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Get role by name"""
        result = await self.db.execute(select(Role).where(Role.name == name))
        return result.scalar_one_or_none()
    
    async def assign_role_to_user(self, user_id: int, role_id: int, assigned_by: int) -> UserRole:
        """Assign role to user"""
        user_role = UserRole(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by
        )
        self.db.add(user_role)
        await self.db.commit()
        await self.db.refresh(user_role)
        return user_role
    
    async def get_user_roles(self, user_id: int) -> List[Role]:
        """Get user roles"""
        result = await self.db.execute(
            select(Role)
            .join(UserRole)
            .where(UserRole.user_id == user_id)
        )
        return result.scalars().all()


class PermissionService:
    """Permission management service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_permission(self, permission_data: PermissionCreate) -> Permission:
        """Create new permission"""
        permission = Permission(**permission_data.dict())
        self.db.add(permission)
        await self.db.commit()
        await self.db.refresh(permission)
        return permission
    
    async def assign_permission_to_role(self, role_id: int, permission_id: int) -> RolePermission:
        """Assign permission to role"""
        role_permission = RolePermission(
            role_id=role_id,
            permission_id=permission_id
        )
        self.db.add(role_permission)
        await self.db.commit()
        await self.db.refresh(role_permission)
        return role_permission
    
    async def get_user_permissions(self, user_id: int) -> List[Permission]:
        """Get user permissions through roles"""
        result = await self.db.execute(
            select(Permission)
            .join(RolePermission)
            .join(Role)
            .join(UserRole)
            .where(UserRole.user_id == user_id)
        )
        return result.scalars().all()


class SessionService:
    """Session management service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_session(self, user_id: int, expires_in_hours: int = 24) -> UserSession:
        """Create user session"""
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
        
        session = UserSession(
            user_id=user_id,
            session_token=session_token,
            expires_at=expires_at
        )
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        return session
    
    async def get_session(self, session_token: str) -> Optional[UserSession]:
        """Get session by token"""
        result = await self.db.execute(
            select(UserSession)
            .where(
                and_(
                    UserSession.session_token == session_token,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def invalidate_session(self, session_token: str) -> bool:
        """Invalidate session"""
        session = await self.get_session(session_token)
        if session:
            session.is_active = False
            await self.db.commit()
            return True
        return False


class MFAService:
    """Multi-factor authentication service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def add_mfa_factor(self, user_id: int, factor_type: str, factor_data: dict) -> MFAFactor:
        """Add MFA factor for user"""
        mfa_factor = MFAFactor(
            user_id=user_id,
            factor_type=factor_type,
            factor_data=factor_data
        )
        self.db.add(mfa_factor)
        await self.db.commit()
        await self.db.refresh(mfa_factor)
        return mfa_factor
    
    async def get_user_mfa_factors(self, user_id: int) -> List[MFAFactor]:
        """Get user MFA factors"""
        result = await self.db.execute(
            select(MFAFactor)
            .where(
                and_(
                    MFAFactor.user_id == user_id,
                    MFAFactor.is_active == True
                )
            )
        )
        return result.scalars().all()
    
    async def verify_mfa_code(self, user_id: int, factor_id: int, code: str) -> bool:
        """Verify MFA code"""
        # This would implement actual MFA verification logic
        # For demo purposes, we'll return True
        return True
