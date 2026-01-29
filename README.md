# StegoLSB 🔐

A Python steganography tool for hiding data in images and audio files using LSB (Least Significant Bit) encoding.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/platform-linux%7Cmacos%7Cwindows-lightgrey)

## Features

- **LSB Steganography** - Hide data in the least significant bits of carrier files
- **Image Support** - PNG, BMP, GIF, WebP (JPEG auto-converts to PNG)
- **Audio Support** - WAV (16-bit PCM)
- **Encryption** - AES-256-GCM with password protection
- **File Hiding** - Hide any file type, not just text
- **Multi-bit LSB** - Use 1-4 bits per sample for higher capacity

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cypher-21/stegoLSB.git
   cd stegoLSB
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install the tool:**
   ```bash
   pip install .
   ```
   *This will install all required dependencies (from `requirements.txt`) and make the `stegolsb` command available system-wide (within the virtual environment).*

## Usage

### Hide a message in an image

```bash
stegolsb hide "Secret message" image.png
```

### Hide a file in an image

```bash
stegolsb hide secret.txt image.png -o output.png
```

### Hide with encryption

```bash
stegolsb hide "Secret message" image.png -p
```

### Extract hidden data

```bash
stegolsb extract output.png
```

### Extract encrypted data with password

```bash
stegolsb extract output.png -p
```

### Audio steganography

```bash
stegolsb hide "Secret" audio.wav -o output.wav
stegolsb extract output.wav
```

### Check carrier capacity

```bash
stegolsb capacity image.png -v
```

## Options

| Option | Description |
|--------|-------------|
| `-o, --output` | Output file path |
| `-p, --password` | Enable encryption (prompts for password) |
| `-b, --bits` | LSB bits to use (1-4, default: 1) |
| `-v, --verbose` | Verbose output |

## How It Works

### LSB Steganography

The tool modifies the Least Significant Bit(s) of each pixel/sample in the carrier file. Since changing the last bit(s) is imperceptible to human senses, data can be hidden without noticeable quality loss.

**Example**: To hide the letter 'A' (binary: 01000001), we modify 8 pixels, changing only their last bit:

```
Original pixels: [100, 150, 200, 125, 175, 225, 50, 75]
Hidden 'A':      [100, 151, 200, 124, 174, 224, 50, 75]
                    ^    ^    ^    ^    ^    ^   ^   ^
                    0    1    0    0    0    0   0   1
```

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2 with SHA-256 (100,000 iterations)

## API Usage

```python
from steg import hide_in_image, extract_from_image, hide_in_audio, extract_from_audio

# Hide message
hide_in_image("input.png", "Secret message", "output.png")

# Hide with encryption
hide_in_image("input.png", "Secret", "output.png", password="mypassword")

# Audio
hide_in_audio("input.wav", "Secret", "output.wav")
```

## License

MIT License
