"""
Audio steganography module
Supports: WAV (16-bit PCM)
"""

import wave
import struct
from pathlib import Path
import numpy as np

from .core import encode_data, decode_data, calculate_capacity
from .utils import prepare_payload, get_file_data, save_file, format_size, bytes_to_int, FLAG_ENCRYPTED, FLAG_IS_FILE
from .crypto import encrypt, decrypt


def _load_wav(audio_path: str) -> tuple:
    """
    Load WAV file and return samples.
    
    Returns: (samples_array, params)
    """
    with wave.open(audio_path, 'rb') as wav:
        params = wav.getparams()
        n_frames = wav.getnframes()
        audio_data = wav.readframes(n_frames)
    
    # Convert to numpy array based on sample width
    if params.sampwidth == 1:
        samples = np.frombuffer(audio_data, dtype=np.uint8)
    elif params.sampwidth == 2:
        samples = np.frombuffer(audio_data, dtype=np.int16)
    elif params.sampwidth == 4:
        samples = np.frombuffer(audio_data, dtype=np.int32)
    else:
        raise ValueError(f"Unsupported sample width: {params.sampwidth}")
    
    return samples, params


def _save_wav(samples: np.ndarray, output_path: str, params):
    """Save samples as WAV file."""
    with wave.open(output_path, 'wb') as wav:
        wav.setparams(params)
        wav.writeframes(samples.tobytes())
    return output_path


def get_audio_capacity(audio_path: str, bits_per_sample: int = 1) -> int:
    """
    Get maximum data capacity of a WAV file in bytes.
    
    Args:
        audio_path: path to WAV file
        bits_per_sample: LSB bits to use (1-4)
    
    Returns:
        Maximum payload size in bytes
    """
    samples, _ = _load_wav(audio_path)
    return calculate_capacity(len(samples), bits_per_sample)


def hide_in_audio(audio_path: str, data, output_path: str = None,
                  password: str = None, bits_per_sample: int = 1) -> str:
    """
    Hide data in a WAV audio file using LSB steganography.
    
    Args:
        audio_path: path to host WAV file
        data: string, bytes, or file path to hide
        output_path: output WAV path (default: _original.wav)
        password: optional encryption password
        bits_per_sample: LSB bits to use (1-4)
    
    Returns:
        Path to output WAV file
    """
    # Load audio
    samples, params = _load_wav(audio_path)
    
    # Prepare data
    is_file = False
    filename = None
    
    if isinstance(data, str):
        # Check if it's a file path
        import os
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
    capacity = calculate_capacity(len(samples), bits_per_sample)
    if len(full_payload) > capacity:
        raise ValueError(
            f"Data too large for audio. Data: {format_size(len(full_payload))}, "
            f"Capacity: {format_size(capacity)}"
        )
    
    # We need to handle signed integers for audio
    # Convert to unsigned for LSB manipulation
    if samples.dtype == np.int16:
        # Shift to unsigned range for manipulation
        samples_unsigned = samples.astype(np.int32) + 32768
        stego_samples = encode_data(samples_unsigned.astype(np.uint16), 
                                    full_payload, bits_per_sample)
        # Shift back to signed
        stego_samples = (stego_samples.astype(np.int32) - 32768).astype(np.int16)
    else:
        stego_samples = encode_data(samples, full_payload, bits_per_sample)
    
    # Determine output path
    if output_path is None:
        base = Path(audio_path)
        output_path = str(base.parent / f"_{base.stem}.wav")
    
    # Save audio
    saved_path = _save_wav(stego_samples, output_path, params)
    
    return saved_path


def extract_from_audio(audio_path: str, password: str = None,
                       bits_per_sample: int = 1, output_dir: str = ".") -> tuple:
    """
    Extract hidden data from a WAV file.
    
    Args:
        audio_path: path to stego WAV file
        password: decryption password (if encrypted)
        bits_per_sample: LSB bits used (1-4)
        output_dir: directory to save extracted files
    
    Returns:
        (data, is_file, filename) - data as bytes or saved file path if is_file
    """
    # Load audio
    samples, params = _load_wav(audio_path)
    
    # Handle signed integers
    if samples.dtype == np.int16:
        samples_unsigned = (samples.astype(np.int32) + 32768).astype(np.uint16)
    else:
        samples_unsigned = samples
    
    # Decode data
    try:
        raw_payload = decode_data(samples_unsigned, bits_per_sample)
    except ValueError as e:
        raise ValueError(f"Failed to extract data: {e}")
    
    # Parse payload
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
