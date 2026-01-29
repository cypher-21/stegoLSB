"""
Utility functions for steganography operations
"""

import os
from pathlib import Path

# Data format flags
FLAG_ENCRYPTED = 0x01
FLAG_IS_FILE = 0x02


def bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list) -> bytes:
    """Convert a list of bits back to bytes."""
    # Pad to multiple of 8
    while len(bits) % 8 != 0:
        bits.append(0)
    
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def int_to_bytes(value: int, length: int = 4) -> bytes:
    """Convert integer to bytes (big-endian)."""
    return value.to_bytes(length, byteorder='big')


def bytes_to_int(data: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(data, byteorder='big')


def prepare_payload(data: bytes, is_file: bool = False, is_encrypted: bool = False, 
                    filename: str = None) -> bytes:
    """
    Prepare data payload with header.
    
    Format:
    - 4 bytes: payload length (excluding this header)
    - 1 byte: flags
    - 2 bytes: filename length (if is_file)
    - N bytes: filename (if is_file)
    - M bytes: data
    """
    flags = 0
    if is_encrypted:
        flags |= FLAG_ENCRYPTED
    if is_file:
        flags |= FLAG_IS_FILE
    
    payload = bytearray()
    
    if is_file and filename:
        filename_bytes = filename.encode('utf-8')
        filename_len = len(filename_bytes)
        # flags + filename_len (2 bytes) + filename + data
        total_len = 1 + 2 + filename_len + len(data)
        payload.extend(int_to_bytes(total_len, 4))
        payload.append(flags)
        payload.extend(int_to_bytes(filename_len, 2))
        payload.extend(filename_bytes)
        payload.extend(data)
    else:
        # flags + data
        total_len = 1 + len(data)
        payload.extend(int_to_bytes(total_len, 4))
        payload.append(flags)
        payload.extend(data)
    
    return bytes(payload)


def parse_payload(data: bytes) -> tuple:
    """
    Parse payload and extract data.
    
    Returns: (data, is_encrypted, is_file, filename)
    """
    if len(data) < 5:
        raise ValueError("Invalid payload: too short")
    
    length = bytes_to_int(data[:4])
    flags = data[4]
    
    is_encrypted = bool(flags & FLAG_ENCRYPTED)
    is_file = bool(flags & FLAG_IS_FILE)
    
    payload_data = data[5:5 + length - 1]  # -1 for flags byte already read
    
    filename = None
    if is_file and len(payload_data) >= 2:
        filename_len = bytes_to_int(payload_data[:2])
        filename = payload_data[2:2 + filename_len].decode('utf-8')
        payload_data = payload_data[2 + filename_len:]
    
    return payload_data, is_encrypted, is_file, filename


def get_file_data(path: str) -> tuple:
    """Read file and return (data, filename)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    with open(path, 'rb') as f:
        data = f.read()
    
    return data, path.name


def save_file(data: bytes, filename: str, output_dir: str = ".") -> str:
    """Save data to file."""
    output_path = Path(output_dir) / filename
    
    # Handle existing files
    if output_path.exists():
        base, ext = os.path.splitext(filename)
        counter = 1
        while output_path.exists():
            output_path = Path(output_dir) / f"{base}_{counter}{ext}"
            counter += 1
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return str(output_path)


def format_size(size_bytes: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"
