from fastapi import APIRouter, Depends
from typing import Dict
from datetime import datetime
from schemas import ClassificationRequest, ClassificationResponse
from auth import get_current_user
from encryption import encryption_service

router = APIRouter(prefix="/api/v1/data-protection", tags=["Data Protection"])

@router.post("/classify", response_model=ClassificationResponse)
async def classify_data(request: ClassificationRequest, current_user: dict = Depends(get_current_user)):
    content_lower = request.content.lower()
    sensitivity_level = "Public"
    confidence = 0.6
    
    sensitive_patterns = {
        "ssn": ["ssn", "social security", "123-45-6789"],
        "email": ["@", "email", "contact"],
        "phone": ["phone", "call", "contact"],
        "address": ["street", "avenue", "road", "address"],
        "medical": ["patient", "medical", "health", "diagnosis"],
        "financial": ["account", "balance", "payment", "credit card"]
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

@router.post("/encrypt")
async def encrypt_data(data: Dict[str, str], current_user: dict = Depends(get_current_user)):
    content = data.get("data", "")
    encrypted_data = encryption_service.encrypt_data(content)
    
    return {
        "encrypted_data": encrypted_data,
        "algorithm": "AES-256",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.post("/decrypt")
async def decrypt_data(data: Dict[str, str], current_user: dict = Depends(get_current_user)):
    encrypted_data = data.get("encrypted_data", "")
    decrypted_data = encryption_service.decrypt_data(encrypted_data)
    
    return {
        "decrypted_data": decrypted_data,
        "algorithm": "AES-256",
        "timestamp": datetime.utcnow().isoformat()
    }

