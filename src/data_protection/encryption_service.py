"""
Encryption Service for Hybrid Cloud Security Framework
"""

import os
import base64
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from src.core.logging import get_logger

logger = get_logger(__name__)


class EncryptionService:
    """Encryption service for data protection"""
    
    def __init__(self):
        self.aes_key = os.getenv('AES_KEY', 'default-aes-key-32-bytes-long!')
        self.rsa_private_key = None
        self.rsa_public_key = None
        self._load_rsa_keys()
    
    def _load_rsa_keys(self):
        """Load RSA keys from environment or generate new ones"""
        try:
            private_key_pem = os.getenv('RSA_PRIVATE_KEY')
            public_key_pem = os.getenv('RSA_PUBLIC_KEY')
            
            if private_key_pem and public_key_pem:
                self.rsa_private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None,
                    backend=default_backend()
                )
                self.rsa_public_key = serialization.load_pem_public_key(
                    public_key_pem.encode(),
                    backend=default_backend()
                )
            else:
                self._generate_rsa_keys()
                
        except Exception as e:
            logger.error(f"Error loading RSA keys: {str(e)}")
            self._generate_rsa_keys()
    
    def _generate_rsa_keys(self):
        """Generate new RSA key pair"""
        try:
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            self.rsa_public_key = self.rsa_private_key.public_key()
            logger.info("Generated new RSA key pair")
        except Exception as e:
            logger.error(f"Error generating RSA keys: {str(e)}")
            raise
    
    def encrypt_aes(self, data: str, key: Optional[str] = None) -> Dict[str, str]:
        """Encrypt data using AES-256"""
        try:
            encryption_key = key or self.aes_key
            key_bytes = encryption_key.encode()[:32].ljust(32, b'0')
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key_bytes),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            # Encrypt data
            encryptor = cipher.encryptor()
            data_bytes = data.encode('utf-8')
            
            # Pad data to multiple of 16 bytes
            padding_length = 16 - (len(data_bytes) % 16)
            padded_data = data_bytes + bytes([padding_length] * padding_length)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "iv": base64.b64encode(iv).decode(),
                "algorithm": "AES-256-CBC"
            }
            
        except Exception as e:
            logger.error(f"AES encryption error: {str(e)}")
            raise
    
    def decrypt_aes(self, encrypted_data: str, iv: str, key: Optional[str] = None) -> str:
        """Decrypt data using AES-256"""
        try:
            encryption_key = key or self.aes_key
            key_bytes = encryption_key.encode()[:32].ljust(32, b'0')
            
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv_bytes = base64.b64decode(iv)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key_bytes),
                modes.CBC(iv_bytes),
                backend=default_backend()
            )
            
            # Decrypt data
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
            
            # Remove padding
            padding_length = decrypted_data[-1]
            unpadded_data = decrypted_data[:-padding_length]
            
            return unpadded_data.decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES decryption error: {str(e)}")
            raise
    
    def encrypt_rsa(self, data: str) -> str:
        """Encrypt data using RSA-4096"""
        try:
            if not self.rsa_public_key:
                raise ValueError("RSA public key not available")
            
            # RSA can only encrypt small amounts of data
            # For larger data, use hybrid encryption
            data_bytes = data.encode('utf-8')
            
            if len(data_bytes) > 400:  # RSA-4096 can encrypt ~400 bytes
                return self._hybrid_encrypt(data)
            
            encrypted_data = self.rsa_public_key.encrypt(
                data_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"RSA encryption error: {str(e)}")
            raise
    
    def decrypt_rsa(self, encrypted_data: str) -> str:
        """Decrypt data using RSA-4096"""
        try:
            if not self.rsa_private_key:
                raise ValueError("RSA private key not available")
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            decrypted_data = self.rsa_private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            logger.error(f"RSA decryption error: {str(e)}")
            raise
    
    def _hybrid_encrypt(self, data: str) -> Dict[str, str]:
        """Hybrid encryption: AES for data, RSA for AES key"""
        try:
            # Generate random AES key
            aes_key = os.urandom(32)
            
            # Encrypt data with AES
            aes_result = self.encrypt_aes(data, aes_key.decode('latin-1'))
            
            # Encrypt AES key with RSA
            encrypted_aes_key = self.rsa_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return {
                "encrypted_data": aes_result["encrypted_data"],
                "iv": aes_result["iv"],
                "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
                "algorithm": "RSA-AES-Hybrid"
            }
            
        except Exception as e:
            logger.error(f"Hybrid encryption error: {str(e)}")
            raise
    
    def _hybrid_decrypt(self, encrypted_data: str, iv: str, encrypted_key: str) -> str:
        """Hybrid decryption: RSA for AES key, AES for data"""
        try:
            # Decrypt AES key with RSA
            encrypted_key_bytes = base64.b64decode(encrypted_key)
            aes_key = self.rsa_private_key.decrypt(
                encrypted_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt data with AES
            return self.decrypt_aes(encrypted_data, iv, aes_key.decode('latin-1'))
            
        except Exception as e:
            logger.error(f"Hybrid decryption error: {str(e)}")
            raise
    
    def generate_key_derivation(self, password: str, salt: bytes) -> bytes:
        """Generate key from password using PBKDF2"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            return kdf.derive(password.encode())
        except Exception as e:
            logger.error(f"Key derivation error: {str(e)}")
            raise
    
    def get_public_key_pem(self) -> str:
        """Get RSA public key in PEM format"""
        try:
            if not self.rsa_public_key:
                raise ValueError("RSA public key not available")
            
            pem = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode()
            
        except Exception as e:
            logger.error(f"Error getting public key: {str(e)}")
            raise
    
    def get_private_key_pem(self) -> str:
        """Get RSA private key in PEM format"""
        try:
            if not self.rsa_private_key:
                raise ValueError("RSA private key not available")
            
            pem = self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            return pem.decode()
            
        except Exception as e:
            logger.error(f"Error getting private key: {str(e)}")
            raise
    
    def encrypt_file(self, file_path: str, output_path: str, key: Optional[str] = None) -> bool:
        """Encrypt file using AES-256"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Convert to string for encryption
            data_str = base64.b64encode(data).decode()
            encrypted_result = self.encrypt_aes(data_str, key)
            
            # Save encrypted data
            with open(output_path, 'w') as f:
                f.write(encrypted_result["encrypted_data"])
                f.write('\n')
                f.write(encrypted_result["iv"])
            
            logger.info(f"File encrypted: {file_path} -> {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"File encryption error: {str(e)}")
            return False
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str, key: Optional[str] = None) -> bool:
        """Decrypt file using AES-256"""
        try:
            with open(encrypted_file_path, 'r') as f:
                lines = f.readlines()
            
            encrypted_data = lines[0].strip()
            iv = lines[1].strip()
            
            decrypted_str = self.decrypt_aes(encrypted_data, iv, key)
            decrypted_data = base64.b64decode(decrypted_str)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"File decrypted: {encrypted_file_path} -> {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"File decryption error: {str(e)}")
            return False

