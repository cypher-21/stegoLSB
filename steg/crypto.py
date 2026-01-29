"""
Encryption module using AES-256-GCM
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits
ITERATIONS = 100000


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive encryption key from password using PBKDF2.
    
    Args:
        password: user password
        salt: random salt
    
    Returns:
        32-byte key for AES-256
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt(data: bytes, password: str) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    
    Format: [16-byte salt][12-byte nonce][ciphertext+tag]
    
    Args:
        data: plaintext bytes
        password: encryption password
    
    Returns:
        Encrypted bytes with salt and nonce prepended
    """
    # Generate random salt and nonce
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    
    # Derive key
    key = derive_key(password, salt)
    
    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    # Return: salt + nonce + ciphertext (includes 16-byte auth tag)
    return salt + nonce + ciphertext


def decrypt(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypt data encrypted with AES-256-GCM.
    
    Args:
        encrypted_data: encrypted bytes with salt and nonce
        password: decryption password
    
    Returns:
        Decrypted plaintext bytes
    
    Raises:
        ValueError: if decryption fails (wrong password or corrupted data)
    """
    min_size = SALT_SIZE + NONCE_SIZE + 16  # 16 = auth tag
    if len(encrypted_data) < min_size:
        raise ValueError("Encrypted data too short")
    
    # Extract components
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:]
    
    # Derive key
    key = derive_key(password, salt)
    
    # Decrypt
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise ValueError("Decryption failed: wrong password or corrupted data") from e
