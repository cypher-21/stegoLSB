"""
StegoLSB - A Python steganography library
Hide data in images and audio using LSB encoding
"""

from .core import encode_data, decode_data
from .image import hide_in_image, extract_from_image, get_image_capacity
from .audio import hide_in_audio, extract_from_audio, get_audio_capacity
from .crypto import encrypt, decrypt

__version__ = "1.0.0"
__all__ = [
    "encode_data",
    "decode_data", 
    "hide_in_image",
    "extract_from_image",
    "get_image_capacity",
    "hide_in_audio",
    "extract_from_audio",
    "get_audio_capacity",
    "encrypt",
    "decrypt",
]
