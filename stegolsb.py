#!/usr/bin/env python3
"""
StegoLSB - Command Line Interface
Hide data in images and audio using LSB steganography
"""

import argparse
import sys
import getpass
from pathlib import Path

from steg import (
    hide_in_image, extract_from_image, get_image_capacity,
    hide_in_audio, extract_from_audio, get_audio_capacity
)
from steg.utils import format_size


# Supported extensions
IMAGE_EXTENSIONS = {'.png', '.bmp', '.gif', '.webp', '.jpg', '.jpeg'}
AUDIO_EXTENSIONS = {'.wav'}


def get_file_type(path: str) -> str:
    """Determine if file is image or audio."""
    ext = Path(path).suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        return 'image'
    elif ext in AUDIO_EXTENSIONS:
        return 'audio'
    else:
        return 'unknown'


def cmd_hide(args):
    """Hide data in carrier file."""
    carrier_path = args.carrier
    data = args.data
    output_path = args.output
    bits = args.bits
    
    # Get password if encryption requested
    password = None
    if args.password:
        password = getpass.getpass("Enter password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Error: Passwords do not match", file=sys.stderr)
            return 1
    
    # Determine file type
    file_type = get_file_type(carrier_path)
    
    try:
        if file_type == 'image':
            result_path = hide_in_image(
                carrier_path, data, output_path,
                password=password, bits_per_sample=bits
            )
        elif file_type == 'audio':
            result_path = hide_in_audio(
                carrier_path, data, output_path,
                password=password, bits_per_sample=bits
            )
        else:
            print(f"Error: Unsupported file format: {carrier_path}", file=sys.stderr)
            return 1
        
        print(f"✓ Data hidden successfully!")
        print(f"  Output: {result_path}")
        
        if args.verbose:
            if Path(data).is_file():
                print(f"  Hidden: {data} ({format_size(Path(data).stat().st_size)})")
            else:
                print(f"  Hidden: {len(data)} characters")
            if password:
                print(f"  Encrypted: Yes (AES-256-GCM)")
            print(f"  LSB bits: {bits}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_extract(args):
    """Extract hidden data from carrier file."""
    carrier_path = args.carrier
    output_dir = args.output_dir
    bits = args.bits
    
    # Get password if decryption requested
    password = None
    if args.password:
        password = getpass.getpass("Enter password: ")
    
    # Determine file type
    file_type = get_file_type(carrier_path)
    
    # Try legacy format first (for compatibility)
    if file_type == 'image':
        try:
            from steg.compat import is_legacy_format, extract_legacy_format
            if is_legacy_format(carrier_path):
                result, is_file, filename = extract_legacy_format(
                    carrier_path, password=password, output_dir=output_dir
                )
                return 0
        except Exception:
            pass  # Fall through to our format
    
    try:
        if file_type == 'image':
            result, is_file, filename = extract_from_image(
                carrier_path, password=password,
                bits_per_sample=bits, output_dir=output_dir
            )
        elif file_type == 'audio':
            result, is_file, filename = extract_from_audio(
                carrier_path, password=password,
                bits_per_sample=bits, output_dir=output_dir
            )
        else:
            print(f"Error: Unsupported file format: {carrier_path}", file=sys.stderr)
            return 1
        
        print(f"✓ Data extracted successfully!")
        
        if is_file:
            print(f"  Saved to: {result}")
        else:
            # It's text/bytes
            try:
                text = result.decode('utf-8')
                print(f"  Message: {text}")
            except UnicodeDecodeError:
                print(f"  Binary data: {len(result)} bytes")
                # Optionally save as file
                save_path = Path(output_dir) / "extracted_data.bin"
                with open(save_path, 'wb') as f:
                    f.write(result)
                print(f"  Saved to: {save_path}")
        
        return 0
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_capacity(args):
    """Show carrier capacity."""
    carrier_path = args.carrier
    bits = args.bits
    
    file_type = get_file_type(carrier_path)
    
    try:
        if file_type == 'image':
            capacity = get_image_capacity(carrier_path, bits)
        elif file_type == 'audio':
            capacity = get_audio_capacity(carrier_path, bits)
        else:
            print(f"Error: Unsupported file format: {carrier_path}", file=sys.stderr)
            return 1
        
        print(f"Carrier: {carrier_path}")
        print(f"Type: {file_type}")
        print(f"LSB bits: {bits}")
        print(f"Capacity: {format_size(capacity)}")
        
        # Show capacity with different bit settings
        if args.verbose:
            print("\nCapacity by LSB bits:")
            for b in range(1, 5):
                if file_type == 'image':
                    cap = get_image_capacity(carrier_path, b)
                else:
                    cap = get_audio_capacity(carrier_path, b)
                print(f"  {b} bit(s): {format_size(cap)}")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(
        prog='stegolsb',
        description='Hide data in images and audio using LSB steganography',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hide a message in an image
  stegolsb hide "Secret message" image.png
  
  # Hide a file in an image with encryption
  stegolsb hide secret.txt image.png -o output.png -p
  
  # Extract hidden data
  stegolsb extract output.png
  
  # Extract encrypted data
  stegolsb extract output.png -p
  
  # Check carrier capacity
  stegolsb capacity image.png -v
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Hide command
    hide_parser = subparsers.add_parser('hide', help='Hide data in carrier file')
    hide_parser.add_argument('data', help='Text message or file path to hide')
    hide_parser.add_argument('carrier', help='Carrier image or audio file')
    hide_parser.add_argument('-o', '--output', help='Output file path')
    hide_parser.add_argument('-p', '--password', action='store_true',
                            help='Encrypt with password')
    hide_parser.add_argument('-b', '--bits', type=int, default=1, choices=[1, 2, 3, 4],
                            help='LSB bits per sample (default: 1)')
    hide_parser.add_argument('-v', '--verbose', action='store_true',
                            help='Verbose output')
    hide_parser.set_defaults(func=cmd_hide)
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract hidden data')
    extract_parser.add_argument('carrier', help='Carrier file with hidden data')
    extract_parser.add_argument('-o', '--output-dir', default='.',
                               help='Output directory for extracted files')
    extract_parser.add_argument('-p', '--password', action='store_true',
                               help='Decrypt with password')
    extract_parser.add_argument('-b', '--bits', type=int, default=1, choices=[1, 2, 3, 4],
                               help='LSB bits per sample (default: 1)')
    extract_parser.add_argument('-v', '--verbose', action='store_true',
                               help='Verbose output')
    extract_parser.set_defaults(func=cmd_extract)
    
    # Capacity command
    capacity_parser = subparsers.add_parser('capacity', help='Show carrier capacity')
    capacity_parser.add_argument('carrier', help='Carrier file to check')
    capacity_parser.add_argument('-b', '--bits', type=int, default=1, choices=[1, 2, 3, 4],
                                help='LSB bits per sample (default: 1)')
    capacity_parser.add_argument('-v', '--verbose', action='store_true',
                                help='Show capacity for all bit settings')
    capacity_parser.set_defaults(func=cmd_capacity)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
