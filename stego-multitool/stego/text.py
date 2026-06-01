"""
Zero-width Unicode character steganography.

Zero-width characters are Unicode codepoints that render as nothing —
they take up no visual space and are invisible in virtually all text
renderers (browsers, terminals, text editors, email clients).

We use four zero-width characters to encode data in base-4:
  U+200B  ZERO WIDTH SPACE         → digit 0
  U+200C  ZERO WIDTH NON-JOINER    → digit 1
  U+200D  ZERO WIDTH JOINER        → digit 2
  U+FEFF  ZERO WIDTH NO-BREAK SPACE (BOM) → digit 3

Two base-4 digits = one byte (base-4 requires 4 digits per byte,
or we can use binary: 8 zero-width chars per byte using just two types).

We use the simpler binary approach: two zero-width chars (ZWS, ZWNJ),
8 chars per byte, inserted between words in the cover text.
The cover text reads and renders completely normally.

Detection:
  Zero-width characters ARE detectable by hex editors and tools like
  'cat -A' or 'hexdump'. This technique hides data from casual readers,
  not from forensic analysis. Real operational security would combine
  this with encryption.
"""

import struct
from typing import Iterator

# Binary encoding: just two zero-width characters
ZW_ZERO = "\u200b"   # Zero Width Space     = bit 0
ZW_ONE  = "\u200c"   # Zero Width Non-Joiner = bit 1

# Marker sequence inserted before the payload so extraction can find it
MARKER = "\u200d\u200d\u200d"   # Three Zero Width Joiners


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


def hide(cover_text: str, secret: bytes) -> str:
    """
    Inject secret bytes into cover_text using zero-width characters.

    The zero-width payload is inserted after the first space in the
    cover text, preceded by a MARKER sequence for reliable extraction.
    The returned string looks identical to cover_text when rendered.

    Parameters
    ----------
    cover_text : the visible plaintext to carry the hidden message
    secret     : bytes to encode

    Returns the stego text (visually identical to cover_text).
    """
    payload = struct.pack(">I", len(secret)) + secret
    bits    = _to_bits(payload)

    # Build the zero-width encoded string
    encoded = MARKER + "".join(ZW_ONE if b else ZW_ZERO for b in bits)

    # Insert after the first word/space for natural placement
    idx = cover_text.find(" ")
    if idx == -1:
        # No space found — append to end
        return cover_text + encoded

    # Insert the invisible payload right after the first space
    return cover_text[:idx+1] + encoded + cover_text[idx+1:]


def reveal(stego_text: str) -> bytes:
    """
    Extract hidden bytes from a zero-width encoded text.

    Searches for the MARKER sequence, then reads zero-width characters
    following it to reconstruct the original bytes.
    """
    # Find the marker
    marker_pos = stego_text.find(MARKER)
    if marker_pos == -1:
        raise ValueError("No hidden message found (no zero-width marker).")

    # Collect all zero-width bits after the marker
    payload_start = marker_pos + len(MARKER)
    bits = []
    for ch in stego_text[payload_start:]:
        if ch == ZW_ZERO:
            bits.append(0)
        elif ch == ZW_ONE:
            bits.append(1)
        # All other characters (visible text) are ignored

    if len(bits) < 32:
        raise ValueError("Payload too short — may be truncated or corrupted.")

    length = struct.unpack(">I", _from_bits(bits[:32]))[0]
    if length == 0 or length > len(bits) // 8:
        raise ValueError("Invalid payload length header.")

    return _from_bits(bits[32: 32 + length * 8])
