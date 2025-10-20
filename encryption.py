#!/usr/bin/env python3
"""
Encryption and decryption services
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from config import settings

class EncryptionService:
    """Encryption service for data protection"""
    
    def __init__(self):
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key"""
        if settings.ENCRYPTION_KEY and settings.ENCRYPTION_KEY != "your-encryption-key-here":
            # Use provided key
            password = settings.ENCRYPTION_KEY.encode()
            salt = b'hybrid_cloud_security_salt'  # In production, use random salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            return key
        else:
            # Generate new key
            return Fernet.generate_key()
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt data using AES-256"""
        try:
            encrypted_data = self.cipher.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data using AES-256"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.cipher.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def hash_data(self, data: str) -> str:
        """Hash data using SHA-256"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def generate_key(self) -> str:
        """Generate new encryption key"""
        return Fernet.generate_key().decode()

# Create encryption service instance
encryption_service = EncryptionService()
