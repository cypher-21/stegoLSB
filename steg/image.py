"""
Image steganography module
Supports: PNG, BMP, GIF, WebP
"""

import os
from pathlib import Path
from PIL import Image
import numpy as np

from .core import encode_data, decode_data, calculate_capacity
from .utils import prepare_payload, parse_payload, get_file_data, save_file, format_size
from .crypto import encrypt, decrypt

# Supported formats
SUPPORTED_FORMATS = {'PNG', 'BMP', 'GIF', 'WEBP'}
DEFAULT_OUTPUT_FORMAT = 'PNG'


def _load_image(image_path: str) -> tuple:
    """
    Load image and return as numpy array.
    
    Returns: (pixel_array, image_mode, original_format)
    """
    img = Image.open(image_path)
    original_format = img.format or 'PNG'
    
    # Convert to RGB or RGBA if needed
    if img.mode not in ('RGB', 'RGBA'):
        img = img.convert('RGB')
    
    pixels = np.array(img)
    return pixels, img.mode, original_format


def _save_image(pixels: np.ndarray, output_path: str, mode: str):
    """Save numpy array as image."""
    img = Image.fromarray(pixels.astype(np.uint8), mode=mode)
    
    # Determine format from extension
    ext = Path(output_path).suffix.upper().lstrip('.')
    if ext == 'JPG':
        ext = 'JPEG'
    
    # Force PNG for JPEG (lossy compression destroys LSB data)
    if ext in ('JPEG', 'JPG'):
        output_path = str(Path(output_path).with_suffix('.png'))
        ext = 'PNG'
    
    if ext not in SUPPORTED_FORMATS:
        ext = DEFAULT_OUTPUT_FORMAT
        output_path = str(Path(output_path).with_suffix('.png'))
    
    img.save(output_path, format=ext)
    return output_path


def get_image_capacity(image_path: str, bits_per_sample: int = 1) -> int:
    """
    Get maximum data capacity of an image in bytes.
    
    Args:
        image_path: path to image file
        bits_per_sample: LSB bits to use (1-4)
    
    Returns:
        Maximum payload size in bytes
    """
    pixels, _, _ = _load_image(image_path)
    carrier_size = pixels.size
    return calculate_capacity(carrier_size, bits_per_sample)


def hide_in_image(image_path: str, data, output_path: str = None, 
                  password: str = None, bits_per_sample: int = 1) -> str:
    """
    Hide data in an image using LSB steganography.
    
    Args:
        image_path: path to host image
        data: string, bytes, or file path to hide
        output_path: output image path (default: _original.png)
        password: optional encryption password
        bits_per_sample: LSB bits to use (1-4)
    
    Returns:
        Path to output image
    """
    # Load image
    pixels, mode, original_format = _load_image(image_path)
    
    # Prepare data
    is_file = False
    filename = None
    
    if isinstance(data, str):
        # Check if it's a file path
        if os.path.isfile(data):
            file_data, filename = get_file_data(data)
            payload = file_data
            is_file = True
        else:
            # It's a text message
            payload = data.encode('utf-8')
    elif isinstance(data, bytes):
        payload = data
    else:
        raise TypeError("Data must be string, bytes, or file path")
    
    # Encrypt if password provided
    is_encrypted = False
    if password:
        payload = encrypt(payload, password)
        is_encrypted = True
    
    # Prepare payload with header
    full_payload = prepare_payload(payload, is_file=is_file, 
                                   is_encrypted=is_encrypted, filename=filename)
    
    # Check capacity
    capacity = calculate_capacity(pixels.size, bits_per_sample)
    if len(full_payload) > capacity:
        raise ValueError(
            f"Data too large for image. Data: {format_size(len(full_payload))}, "
            f"Capacity: {format_size(capacity)}"
        )
    
    # Encode data
    stego_pixels = encode_data(pixels, full_payload, bits_per_sample)
    
    # Determine output path
    if output_path is None:
        base = Path(image_path)
        output_path = str(base.parent / f"_{base.stem}.png")
    
    # Save image
    saved_path = _save_image(stego_pixels, output_path, mode)
    
    return saved_path


def extract_from_image(image_path: str, password: str = None, 
                       bits_per_sample: int = 1, output_dir: str = ".") -> tuple:
    """
    Extract hidden data from an image.
    
    Args:
        image_path: path to stego image
        password: decryption password (if encrypted)
        bits_per_sample: LSB bits used (1-4)
        output_dir: directory to save extracted files
    
    Returns:
        (data, is_file, filename) - data as bytes or saved file path if is_file
    """
    # Load image
    pixels, _, _ = _load_image(image_path)
    
    # Decode data
    try:
        raw_payload = decode_data(pixels, bits_per_sample)
    except ValueError as e:
        raise ValueError(f"Failed to extract data: {e}")
    
    # Parse payload
    data, is_encrypted, is_file, filename = parse_payload(
        bytes([0, 0, 0, len(raw_payload)]) + raw_payload  # Reconstruct with temp length
    )
    
    # Actually re-parse correctly
    from .utils import bytes_to_int, FLAG_ENCRYPTED, FLAG_IS_FILE
    
    flags = raw_payload[0]
    is_encrypted = bool(flags & FLAG_ENCRYPTED)
    is_file = bool(flags & FLAG_IS_FILE)
    
    payload_data = raw_payload[1:]
    
    filename = None
    if is_file and len(payload_data) >= 2:
        filename_len = bytes_to_int(payload_data[:2])
        if filename_len > 0 and len(payload_data) >= 2 + filename_len:
            filename = payload_data[2:2 + filename_len].decode('utf-8')
            payload_data = payload_data[2 + filename_len:]
    
    # Decrypt if needed
    if is_encrypted:
        if not password:
            raise ValueError("Data is encrypted. Please provide a password.")
        try:
            payload_data = decrypt(payload_data, password)
        except ValueError:
            raise ValueError("Decryption failed: wrong password or corrupted data")
    
    # Handle file output
    if is_file and filename:
        saved_path = save_file(payload_data, filename, output_dir)
        return saved_path, True, filename
    else:
        return payload_data, False, None
