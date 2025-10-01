"""
Data Protection API Routes for Hybrid Cloud Security Framework
"""

from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from src.core.database import get_db
from src.data_protection.classification_engine import DataClassificationEngine
from src.data_protection.encryption_service import EncryptionService

router = APIRouter()
security = HTTPBearer()


class ClassificationRequest(BaseModel):
    """Data classification request"""
    content: str
    metadata: Optional[Dict] = None


class ClassificationResponse(BaseModel):
    """Data classification response"""
    sensitivity_level: str
    confidence: float
    classification_method: str
    timestamp: str
    content_hash: str


class EncryptionRequest(BaseModel):
    """Encryption request"""
    data: str
    algorithm: str = "AES-256"
    key: Optional[str] = None


class EncryptionResponse(BaseModel):
    """Encryption response"""
    encrypted_data: str
    algorithm: str
    iv: Optional[str] = None
    encrypted_key: Optional[str] = None


class DecryptionRequest(BaseModel):
    """Decryption request"""
    encrypted_data: str
    algorithm: str = "AES-256"
    key: Optional[str] = None
    iv: Optional[str] = None
    encrypted_key: Optional[str] = None


class DecryptionResponse(BaseModel):
    """Decryption response"""
    decrypted_data: str
    algorithm: str


@router.post("/classify", response_model=ClassificationResponse)
async def classify_data(
    request: ClassificationRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Classify data content for sensitivity level"""
    try:
        classifier = DataClassificationEngine()
        result = classifier.classify_data(request.content, request.metadata)
        
        return ClassificationResponse(
            sensitivity_level=result["sensitivity_level"],
            confidence=result["confidence"],
            classification_method=result["classification_method"],
            timestamp=result["timestamp"],
            content_hash=result["content_hash"]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Classification error: {str(e)}"
        )


@router.post("/encrypt", response_model=EncryptionResponse)
async def encrypt_data(
    request: EncryptionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Encrypt data using specified algorithm"""
    try:
        encryption_service = EncryptionService()
        
        if request.algorithm == "AES-256":
            result = encryption_service.encrypt_aes(request.data, request.key)
            return EncryptionResponse(
                encrypted_data=result["encrypted_data"],
                algorithm=result["algorithm"],
                iv=result["iv"]
            )
        elif request.algorithm == "RSA-4096":
            encrypted_data = encryption_service.encrypt_rsa(request.data)
            return EncryptionResponse(
                encrypted_data=encrypted_data,
                algorithm="RSA-4096"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported encryption algorithm"
            )
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption error: {str(e)}"
        )


@router.post("/decrypt", response_model=DecryptionResponse)
async def decrypt_data(
    request: DecryptionRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Decrypt data using specified algorithm"""
    try:
        encryption_service = EncryptionService()
        
        if request.algorithm == "AES-256":
            if not request.iv:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="IV required for AES decryption"
                )
            decrypted_data = encryption_service.decrypt_aes(
                request.encrypted_data, request.iv, request.key
            )
            return DecryptionResponse(
                decrypted_data=decrypted_data,
                algorithm=request.algorithm
            )
        elif request.algorithm == "RSA-4096":
            decrypted_data = encryption_service.decrypt_rsa(request.encrypted_data)
            return DecryptionResponse(
                decrypted_data=decrypted_data,
                algorithm=request.algorithm
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported decryption algorithm"
            )
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption error: {str(e)}"
        )


@router.post("/encrypt-file")
async def encrypt_file(
    file: UploadFile = File(...),
    key: Optional[str] = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Encrypt uploaded file"""
    try:
        # Save uploaded file temporarily
        temp_path = f"temp_{file.filename}"
        with open(temp_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Encrypt file
        encryption_service = EncryptionService()
        encrypted_path = f"encrypted_{file.filename}"
        success = encryption_service.encrypt_file(temp_path, encrypted_path, key)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File encryption failed"
            )
        
        return {
            "message": "File encrypted successfully",
            "encrypted_file": encrypted_path
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File encryption error: {str(e)}"
        )


@router.post("/decrypt-file")
async def decrypt_file(
    file: UploadFile = File(...),
    key: Optional[str] = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Decrypt uploaded file"""
    try:
        # Save uploaded file temporarily
        temp_path = f"temp_{file.filename}"
        with open(temp_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Decrypt file
        encryption_service = EncryptionService()
        decrypted_path = f"decrypted_{file.filename}"
        success = encryption_service.decrypt_file(temp_path, decrypted_path, key)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File decryption failed"
            )
        
        return {
            "message": "File decrypted successfully",
            "decrypted_file": decrypted_path
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File decryption error: {str(e)}"
        )


@router.get("/public-key")
async def get_public_key(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get RSA public key"""
    try:
        encryption_service = EncryptionService()
        public_key = encryption_service.get_public_key_pem()
        
        return {
            "public_key": public_key,
            "algorithm": "RSA-4096"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting public key: {str(e)}"
        )


@router.post("/train-classifier")
async def train_classifier(
    training_data: List[Dict[str, str]],
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Train the data classification model"""
    try:
        classifier = DataClassificationEngine()
        
        # Convert training data to required format
        formatted_data = [(item["text"], item["label"]) for item in training_data]
        
        success = classifier.train_classifier(formatted_data)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Training failed"
            )
        
        return {
            "message": "Classifier trained successfully",
            "training_samples": len(formatted_data)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Training error: {str(e)}"
        )


@router.get("/classification-rules")
async def get_classification_rules(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get current classification rules"""
    try:
        classifier = DataClassificationEngine()
        rules = classifier.get_classification_rules()
        
        return {
            "classification_rules": rules,
            "total_categories": len(rules)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting classification rules: {str(e)}"
        )


@router.post("/add-classification-rule")
async def add_classification_rule(
    category: str,
    pattern: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Add new classification rule"""
    try:
        classifier = DataClassificationEngine()
        success = classifier.add_classification_rule(category, pattern)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add classification rule"
            )
        
        return {
            "message": "Classification rule added successfully",
            "category": category,
            "pattern": pattern
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error adding classification rule: {str(e)}"
        )
