"""
PDF steganography using two techniques:

1. INVISIBLE TEXT LAYER
   PDF supports text with colour (1, 1, 1) — white on white.
   The text is in the PDF's content stream and is selectable/searchable,
   but invisible to the reader. We render the secret in white text at
   font size 0.001 points (invisible but present).

2. WHITESPACE ENCODING (binary in spaces)
   We encode data by choosing between regular spaces (U+0020) and
   non-breaking spaces (U+00A0) in the visible text body.
   One space encodes one bit: regular space = 0, non-breaking = 1.
   This technique survives copy-paste into a text editor.

Both techniques can be combined or used independently.
"""

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import struct
import io


# Space characters used for whitespace encoding
SPACE_0 = "\u0020"   # regular space = bit 0
SPACE_1 = "\u00a0"   # non-breaking space = bit 1


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


def hide(output_path: str,
         visible_text: str,
         secret: bytes,
         method: str = "invisible") -> None:
    """
    Create a PDF with the visible_text content and the secret hidden inside.

    Parameters
    ----------
    output_path  : path to write the stego PDF
    visible_text : the text humans see when opening the PDF
    secret       : bytes to hide
    method       : "invisible" (white text layer) or "whitespace" (space encoding)
    """
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4

    # Draw the visible text in normal black
    c.setFont("Helvetica", 12)
    c.setFillColorRGB(0, 0, 0)   # black
    # Wrap text manually for display
    y = height - 50
    for line in visible_text.split("\n"):
        c.drawString(50, y, line)
        y -= 20

    if method == "invisible":
        _hide_invisible_text(c, secret, width, height)
    elif method == "whitespace":
        _hide_whitespace(c, secret, width)

    c.save()


def _hide_invisible_text(c, secret: bytes, width: float, height: float) -> None:
    """
    Render secret as white text on white background.
    Font size 1 — renders but stays invisible at normal zoom.
    The text is present in the PDF content stream and can be extracted.
    """
    # Encode secret as hex so it's pure ASCII (safe for PDF text stream)
    hex_payload = secret.hex()

    c.setFont("Helvetica", 1)
    c.setFillColorRGB(1, 1, 1)   # WHITE — invisible on white background

    # Write the hex-encoded secret at the bottom of the page
    # Split into 200-char lines to stay within PDF line width limits
    y = 20
    for i in range(0, len(hex_payload), 200):
        c.drawString(0, y, hex_payload[i:i+200])
        y += 2   # 2pt line height at font size 1


def _hide_whitespace(c, secret: bytes, width: float) -> None:
    """
    Encode secret bits as spaces in a whitespace-only text block.
    Regular space = bit 0, non-breaking space = bit 1.
    The block is rendered in white text so it's invisible.
    """
    payload = struct.pack(">I", len(secret)) + secret
    bits    = _to_bits(payload)
    # Build a string of encoded spaces
    encoded = "".join(SPACE_1 if b else SPACE_0 for b in bits)

    c.setFont("Helvetica", 8)
    c.setFillColorRGB(1, 1, 1)   # invisible white
    # Render in chunks across the page
    chunk_size = int(width // 6)
    y = 50
    for i in range(0, len(encoded), chunk_size):
        c.drawString(0, y, encoded[i:i+chunk_size])
        y += 10


def reveal(pdf_path: str, method: str = "invisible") -> bytes:
    """
    Extract hidden bytes from a stego PDF.

    Uses pdfminer.six to extract raw text content including white text.
    """
    from pdfminer.high_level import extract_text

    # extract_text() reads ALL text including invisible white-coloured text
    raw = extract_text(pdf_path)

    if method == "invisible":
        # Find the hex payload — it appears as a long hex string
        # after the visible text content
        import re
        # Look for runs of hex characters (the encoded secret)
        matches = re.findall(r'[0-9a-f]{16,}', raw)
        if not matches:
            raise ValueError("No hidden message found (invisible text method).")
        hex_str = "".join(matches)
        return bytes.fromhex(hex_str)

    elif method == "whitespace":
        # Extract only space / non-breaking space characters
        bits = []
        for ch in raw:
            if ch == SPACE_0:
                bits.append(0)
            elif ch == SPACE_1:
                bits.append(1)

        if len(bits) < 32:
            raise ValueError("Not enough whitespace data found.")

        length = struct.unpack(">I", _from_bits(bits[:32]))[0]
        return _from_bits(bits[32: 32 + length * 8])

    raise ValueError(f"Unknown method: {method}")
