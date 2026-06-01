"""
QR code steganography via error-correction exploitation.

QR error correction levels:
  L = 7%  recovery capacity
  M = 15% recovery capacity
  Q = 25% recovery capacity
  H = 30% recovery capacity   ← we use this

The Reed-Solomon code can correct errors in up to 30% of the data
codewords at level H. We encode our secondary message by deliberately
corrupting modules in the QR image — as long as we stay under the 30%
threshold, the QR scanner still reads the primary message correctly.

Secondary message encoding:
  We encode the hidden message as an LSB payload in the pixel data of
  the QR image, choosing only the "quiet zone" (white border) and
  timing pattern modules where flipping bits is least detectable and
  has the least impact on decoding.

For simplicity this implementation hides data in the pixels of the
quiet zone (white border) — these are not part of the QR data matrix
and are ignored by decoders.
"""

import qrcode
from PIL import Image
import struct


HEADER_BYTES = 4


def _to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _from_bits(bits: list[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        byte = sum(b << (7 - j) for j, b in enumerate(chunk))
        result.append(byte)
    return bytes(result)


def hide(primary_message: str, secret: bytes, output_path: str,
         module_size: int = 10) -> None:
    """
    Generate a QR code for primary_message and hide secret bytes in
    the quiet zone pixels using LSB encoding.

    Parameters
    ----------
    primary_message : the visible/scannable message
    secret          : bytes to hide in the QR image
    output_path     : path to write the output PNG
    module_size     : pixel size of each QR module (higher = more capacity)
    """
    # Generate the QR code image at level H (maximum error correction)
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=module_size,
        border=4,    # 4 modules of quiet zone (QR spec minimum)
    )
    qr.add_data(primary_message)
    qr.make(fit=True)

    # Get the QR image as a PIL Image (black and white)
    img = qr.make_image(fill_color="black", back_color="white")
    img = img.convert("RGB")

    pixels = list(img.getdata())
    width, height = img.size

    # The quiet zone is the white border — border=4 modules × module_size px
    # We hide data in these border pixels only
    quiet_zone_px = 4 * module_size

    # Collect indices of pixels in the quiet zone (top border rows)
    quiet_indices = []
    for y in range(quiet_zone_px):
        for x in range(width):
            quiet_indices.append(y * width + x)

    payload  = struct.pack(">I", len(secret)) + secret
    bits     = _to_bits(payload)
    capacity = len(quiet_indices) * 3   # 3 channels per pixel

    if len(bits) > capacity:
        raise ValueError(
            f"QR quiet zone too small for this secret. "
            f"Increase module_size or shorten the secret. "
            f"Capacity: {capacity // 8} bytes."
        )

    # Hide bits in LSBs of quiet zone pixels
    bit_idx    = 0
    new_pixels = list(pixels)
    for idx in quiet_indices:
        if bit_idx >= len(bits):
            break
        r, g, b = new_pixels[idx]
        channels = [r, g, b]
        for i in range(3):
            if bit_idx < len(bits):
                channels[i] = (channels[i] & 0xFE) | bits[bit_idx]
                bit_idx += 1
        new_pixels[idx] = tuple(channels)

    out = Image.new("RGB", img.size)
    out.putdata(new_pixels)
    out.save(output_path, format="PNG")


def reveal(image_path: str, module_size: int = 10) -> bytes:
    """Extract the hidden message from the QR code's quiet zone."""
    img    = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    width  = img.size[0]

    quiet_zone_px = 4 * module_size

    # Collect bits from quiet zone pixels
    bits = []
    for y in range(quiet_zone_px):
        for x in range(width):
            r, g, b = pixels[y * width + x]
            for channel in (r, g, b):
                bits.append(channel & 1)

    length = struct.unpack(">I", _from_bits(bits[:32]))[0]
    if length == 0 or length > len(bits) // 8:
        raise ValueError("No hidden message found in QR quiet zone.")

    return _from_bits(bits[32: 32 + length * 8])
