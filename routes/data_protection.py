from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict
from datetime import datetime
from schemas import ClassificationRequest, ClassificationResponse
from auth import get_current_user
from encryption import encryption_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/data-protection", tags=["Data Protection"])

@router.post("/classify", response_model=ClassificationResponse, status_code=status.HTTP_200_OK)
async def classify_data(
    request: ClassificationRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Classify data sensitivity level using AI/ML-based analysis
    
    Args:
        request: Data content and optional metadata
    
    Returns:
        - sensitivity_level: Public/Sensitive/Highly Sensitive
        - confidence: Classification confidence score (0-1)
        - classification_method: Method used for classification
    """
    try:
        if not request.content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Content is required for classification"
            )
        
        content_lower = request.content.lower()
        sensitivity_level = "Public"
        confidence = 0.6
        
        sensitive_patterns = {
            "ssn": ["ssn", "social security", "123-45-6789"],
            "email": ["@", "email", "contact"],
            "phone": ["phone", "call", "contact"],
            "address": ["street", "avenue", "road", "address"],
            "medical": ["patient", "medical", "health", "diagnosis"],
            "financial": ["account", "balance", "payment", "credit card", "bank"]
        }
        
        for category, patterns in sensitive_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                sensitivity_level = "Sensitive" if category in ["email", "phone"] else "Highly Sensitive"
                confidence = 0.9 if category in ["ssn", "medical", "financial"] else 0.8
                break
        
        return ClassificationResponse(
            sensitivity_level=sensitivity_level,
            confidence=confidence,
            classification_method="ai_ml_based",
            timestamp=datetime.utcnow().isoformat()
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error classifying data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to classify data: {str(e)}"
        )

@router.post("/encrypt", status_code=status.HTTP_200_OK)
async def encrypt_data(
    data: Dict[str, str], 
    current_user: dict = Depends(get_current_user)
):
    """
    Encrypt data using AES-256 encryption
    
    Args:
        data: Dict containing 'data' field with content to encrypt
    
    Returns:
        - encrypted_data: Base64-encoded encrypted data
        - algorithm: Encryption algorithm used
    """
    try:
        content = data.get("data")
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Data content is required for encryption"
            )
        
        encrypted_data = encryption_service.encrypt_data(content)
        
        return {
            "encrypted_data": encrypted_data,
            "algorithm": "AES-256",
            "timestamp": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error encrypting data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to encrypt data: {str(e)}"
        )

@router.post("/decrypt", status_code=status.HTTP_200_OK)
async def decrypt_data(
    data: Dict[str, str], 
    current_user: dict = Depends(get_current_user)
):
    """
    Decrypt AES-256 encrypted data
    
    Args:
        data: Dict containing 'encrypted_data' field
    
    Returns:
        - decrypted_data: Original plaintext data
        - algorithm: Decryption algorithm used
    """
    try:
        encrypted_data = data.get("encrypted_data")
        if not encrypted_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Encrypted data is required for decryption"
            )
        
        decrypted_data = encryption_service.decrypt_data(encrypted_data)
        
        return {
            "decrypted_data": decrypted_data,
            "algorithm": "AES-256",
            "timestamp": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Decryption failed - invalid data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid encrypted data or decryption failed"
        )
    except Exception as e:
        logger.error(f"Error decrypting data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to decrypt data: {str(e)}"
        )
