"""
Compatibility module for legacy format
Allows extracting data from images created by the legacy tool.
"""

import numpy as np
from pathlib import Path
from PIL import Image

from .crypto import decrypt as aes_decrypt

# Original stegpy magic number
MAGIC_NUMBER = b"stegv3"


def _load_image(image_path: str) -> np.ndarray:
    """Load image as numpy array."""
    img = Image.open(image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    return np.array(img)


def decode_legacy_format(host_data: np.ndarray) -> np.ndarray:
    """
    Decode using legacy algorithm.
    The number of bits used is encoded in bits 5-6 of the first byte.
    """
    host_data = host_data.flatten().astype(np.int32)  # Use int32 to avoid overflow
    
    # bits = 2 ^ ((5th and 6th bits) >> 4)
    bits = 2 ** ((int(host_data[0]) & 48) >> 4)
    divisor = 8 // bits
    
    # Pad if needed
    original_size = host_data.size
    if host_data.size % divisor != 0:
        pad_size = divisor - (host_data.size % divisor)
        host_data = np.concatenate([host_data, np.zeros(pad_size, dtype=np.int32)])
    
    # Decode message
    msg_size = len(host_data) // divisor
    msg = np.zeros(msg_size, dtype=np.uint8)
    
    for i in range(divisor):
        msg |= ((host_data[i::divisor] & (2**bits - 1)) << (bits * i)).astype(np.uint8)
    
    return msg


def extract_legacy_format(image_path: str, password: str = None, 
                            output_dir: str = ".") -> tuple:
    """
    Extract data hidden by the legacy tool.
    
    Args:
        image_path: path to stego image
        password: decryption password (if encrypted)
        output_dir: directory to save extracted files
    
    Returns:
        (data/path, is_file, filename)
    """
    # Load image
    pixels = _load_image(image_path)
    
    # Decode using original algorithm
    msg = decode_legacy_format(pixels)
    
    # Handle encryption (legacy format prepends 16-byte salt)
    if password:
        try:
            salt = bytes(msg[:16])
            # Legacy tool uses different encryption - try to import their crypt
            # For now, just extract the rest
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            
            # Derive key same way as legacy tool
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            
            # Original uses Fernet, but let's try basic decryption
            from cryptography.fernet import Fernet
            import base64
            fernet_key = base64.urlsafe_b64encode(key)
            f = Fernet(fernet_key)
            msg = np.frombuffer(f.decrypt(bytes(msg[16:])), dtype=np.uint8)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    # Check magic number
    if bytes(msg[0:6]) != MAGIC_NUMBER:
        raise ValueError(f"No legacy data found (magic number mismatch)")
    
    # Parse header
    msg_len = int.from_bytes(bytes(msg[6:10]), "big")
    filename_len = int.from_bytes(bytes(msg[10:11]), "big")
    
    start = filename_len + 11
    end = start + msg_len
    
    if filename_len > 0:
        # It's a file
        filename = "_" + bytes(msg[11:11 + filename_len]).decode("utf-8")
        file_data = bytes(msg[start:end])
        
        # Save file
        output_path = Path(output_dir) / filename
        with open(output_path, "wb") as f:
            f.write(file_data)
        
        print(f"File {filename} succesfully extracted from {image_path}")
        return str(output_path), True, filename
    else:
        # It's text
        text = bytes(msg[start:end]).decode("utf-8")
        print(text)
        return text.encode('utf-8'), False, None


def is_legacy_format(image_path: str) -> bool:
    """Check if image contains data in legacy format."""
    try:
        pixels = _load_image(image_path)
        msg = decode_legacy_format(pixels)
        return bytes(msg[0:6]) == MAGIC_NUMBER
    except:
        return False
