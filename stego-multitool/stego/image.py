"""
Image LSB (Least Significant Bit) steganography.

How LSB encoding works:
  Each pixel in an RGB image has three channels: R, G, B.
  Each channel is an 8-bit integer (0–255).
  The least significant bit (bit 0) contributes only 1/255 of the value.
  Changing it is visually imperceptible.

  To hide one byte of secret data (8 bits), we need 8 channel values.
  We replace bit 0 of each channel with one bit of our secret data.

  Example: hiding 'A' (01000001) in three pixels (R,G,B each):
    Pixel 1 R=200 (11001000) → 11001000 (bit 0 = 0) → 200
    Pixel 1 G=150 (10010110) → 10010111 (bit 0 = 1) → 151
    ...

Capacity: width × height × 3 channels / 8 bits per byte − overhead.
A 1920×1080 PNG can hide (1920×1080×3)/8 = ~777 KB of data.

We prepend a 32-bit length header so extraction knows when to stop.
"""

from PIL import Image
import struct


# Sentinel: 32-bit big-endian integer prepended to the message
# so the decoder knows exactly how many bytes to extract.
HEADER_BYTES = 4


def _str_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a flat list of bits (MSB first per byte)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):   # bit 7 (MSB) → bit 0 (LSB)
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a flat list of bits back to bytes (MSB first)."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        byte = 0
        for bit in chunk:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def hide(image_path: str, secret: bytes, output_path: str) -> None:
    """
    Encode secret bytes into an image using LSB steganography.

    Parameters
    ----------
    image_path  : path to carrier image (any Pillow-supported format)
    secret      : raw bytes to hide
    output_path : path to write the stego image (use PNG to avoid lossy re-compression)

    Raises ValueError if the image is too small to hold the secret.
    """
    img    = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())   # list of (R, G, B) tuples

    # Build the full payload: 4-byte length header + secret data
    payload     = struct.pack(">I", len(secret)) + secret
    bits        = _str_to_bits(payload)
    capacity    = len(pixels) * 3   # one bit per channel

    if len(bits) > capacity:
        raise ValueError(
            f"Image too small: need {len(bits)} bits, have {capacity} bits. "
            f"Use a larger carrier image or shorter message."
        )

    # Walk through pixels and replace the LSB of each channel
    bit_idx    = 0
    new_pixels = []
    for r, g, b in pixels:
        channels = [r, g, b]
        for i in range(3):
            if bit_idx < len(bits):
                # Clear bit 0 with AND 0xFE, then set it to the secret bit
                # 0xFE = 11111110 — clears only bit 0
                channels[i] = (channels[i] & 0xFE) | bits[bit_idx]
                bit_idx += 1
        new_pixels.append(tuple(channels))

    # Rebuild the image from modified pixel data
    out = Image.new("RGB", img.size)
    out.putdata(new_pixels)
    # MUST save as PNG — JPEG re-compression destroys LSB data
    out.save(output_path, format="PNG")


def reveal(image_path: str) -> bytes:
    """
    Extract hidden bytes from an LSB-encoded image.

    Parameters
    ----------
    image_path : path to the stego image

    Returns the original secret bytes, or raises ValueError if
    the header indicates an invalid or absent message.
    """
    img    = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    # Extract all LSBs from all channels
    bits = []
    for r, g, b in pixels:
        for channel in (r, g, b):
            bits.append(channel & 1)   # bit 0

    # First 32 bits (4 bytes) are the length header
    header_bits = bits[:HEADER_BYTES * 8]
    length      = struct.unpack(">I", _bits_to_bytes(header_bits))[0]

    if length == 0 or length > len(pixels) * 3 // 8:
        raise ValueError("No valid hidden message found in this image.")

    # Extract exactly 'length' bytes after the header
    start      = HEADER_BYTES * 8
    end        = start + length * 8
    msg_bits   = bits[start:end]
    return _bits_to_bytes(msg_bits)
