"""
Core LSB steganography encoding/decoding functions
"""

import numpy as np
from .utils import bytes_to_bits, bits_to_bytes, bytes_to_int


def encode_data(carrier: np.ndarray, data: bytes, bits_per_sample: int = 1) -> np.ndarray:
    """
    Encode data into carrier using LSB steganography.
    
    Args:
        carrier: numpy array of carrier data (image pixels or audio samples)
        data: bytes to hide
        bits_per_sample: number of LSB bits to use (1-4)
    
    Returns:
        Modified carrier array with hidden data
    """
    if bits_per_sample < 1 or bits_per_sample > 4:
        raise ValueError("bits_per_sample must be between 1 and 4")
    
    # Flatten carrier for easier processing
    original_shape = carrier.shape
    flat_carrier = carrier.flatten().astype(np.int32)
    
    # Convert data to bits
    data_bits = bytes_to_bits(data)
    
    # Check capacity
    max_bits = len(flat_carrier) * bits_per_sample
    if len(data_bits) > max_bits:
        raise ValueError(
            f"Data too large: {len(data_bits)} bits required, "
            f"but only {max_bits} bits available"
        )
    
    # Create mask for clearing LSBs
    clear_mask = ~((1 << bits_per_sample) - 1) & 0xFF
    
    # Encode data
    bit_index = 0
    for i in range(len(flat_carrier)):
        if bit_index >= len(data_bits):
            break
        
        # Clear the LSBs
        flat_carrier[i] = flat_carrier[i] & clear_mask
        
        # Set the new LSB value
        value = 0
        for b in range(bits_per_sample):
            if bit_index + b < len(data_bits):
                value |= data_bits[bit_index + b] << (bits_per_sample - 1 - b)
        
        flat_carrier[i] = flat_carrier[i] | value
        bit_index += bits_per_sample
    
    # Reshape back to original
    return flat_carrier.reshape(original_shape).astype(carrier.dtype)


def decode_data(carrier: np.ndarray, bits_per_sample: int = 1) -> bytes:
    """
    Decode hidden data from carrier using LSB steganography.
    
    Args:
        carrier: numpy array of carrier data with hidden message
        bits_per_sample: number of LSB bits used (1-4)
    
    Returns:
        Extracted bytes
    """
    if bits_per_sample < 1 or bits_per_sample > 4:
        raise ValueError("bits_per_sample must be between 1 and 4")
    
    # Flatten carrier
    flat_carrier = carrier.flatten()
    
    # Extract bits
    extracted_bits = []
    mask = (1 << bits_per_sample) - 1
    
    for sample in flat_carrier:
        value = int(sample) & mask
        for b in range(bits_per_sample):
            extracted_bits.append((value >> (bits_per_sample - 1 - b)) & 1)
    
    # First, extract the length (4 bytes = 32 bits)
    if len(extracted_bits) < 32:
        raise ValueError("Not enough data to extract length header")
    
    length_bits = extracted_bits[:32]
    length_bytes = bits_to_bytes(length_bits)
    payload_length = bytes_to_int(length_bytes)
    
    # Validate length
    total_bits_needed = 32 + (payload_length * 8)
    if payload_length <= 0 or total_bits_needed > len(extracted_bits):
        raise ValueError("Invalid or no hidden data found")
    
    # Extract payload
    payload_bits = extracted_bits[32:total_bits_needed]
    payload = bits_to_bytes(payload_bits)
    
    return payload


def calculate_capacity(carrier_size: int, bits_per_sample: int = 1) -> int:
    """
    Calculate maximum data capacity in bytes.
    
    Args:
        carrier_size: number of samples in carrier
        bits_per_sample: LSB bits used
    
    Returns:
        Maximum payload size in bytes
    """
    total_bits = carrier_size * bits_per_sample
    # Subtract header (4 bytes length + 1 byte flags = 5 bytes = 40 bits)
    available_bits = total_bits - 40
    return max(0, available_bits // 8)
