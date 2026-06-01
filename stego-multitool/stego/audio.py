"""
Audio LSB steganography for WAV and FLAC files.

Audio samples are integers (or floats). For 16-bit PCM (int16), each sample
is a value from -32768 to 32767. Changing the least significant bit shifts
the audio level by 1 out of 65536 — completely inaudible.

We flatten all audio channels into a 1D array of samples, then replace
the LSB of each sample with one bit of secret data, identical to image LSB.

FLAC is lossless, so LSBs survive the encode/decode cycle. WAV is also
lossless. DO NOT use MP3 or Ogg — lossy compression destroys LSBs.
"""

import struct
import numpy as np
import soundfile as sf
from pathlib import Path


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


def hide(audio_path: str, secret: bytes, output_path: str) -> None:
    """
    Hide secret bytes in an audio file by modifying sample LSBs.

    soundfile.read() returns samples as float64 by default.
    We use dtype='int16' to get raw integer samples where LSB manipulation
    is straightforward. For 32-bit files we use int32.

    The audio is written back with the same sample rate and channel count.
    """
    # Read as int16 to access raw PCM values
    data, sample_rate = sf.read(audio_path, dtype="int16")

    # Flatten to 1D: shape (n_samples, n_channels) → (n_samples * n_channels,)
    flat = data.flatten()

    payload  = struct.pack(">I", len(secret)) + secret
    bits     = _to_bits(payload)
    capacity = len(flat)

    if len(bits) > capacity:
        raise ValueError(
            f"Audio too short: need {len(bits)} bits, have {capacity}."
        )

    # Replace bit 0 of each sample
    # np.int16 can overflow when doing bitwise ops — cast to int32 temporarily
    flat_i32 = flat.astype(np.int32)
    for i, bit in enumerate(bits):
        flat_i32[i] = (flat_i32[i] & ~1) | bit   # clear bit 0, set to secret bit

    # Reshape back to original channel layout
    modified = flat_i32.astype(np.int16).reshape(data.shape)

    # Determine output format from extension
    fmt = "WAV" if output_path.lower().endswith(".wav") else "FLAC"
    sf.write(output_path, modified, sample_rate, subtype="PCM_16", format=fmt)


def reveal(audio_path: str) -> bytes:
    """Extract hidden bytes from an LSB-encoded audio file."""
    data, _ = sf.read(audio_path, dtype="int16")
    flat     = data.flatten().astype(np.int32)

    # Extract all LSBs
    bits = [int(s) & 1 for s in flat]

    # Read 4-byte length header
    length = struct.unpack(">I", _from_bits(bits[:32]))[0]

    if length == 0 or length > len(flat) // 8:
        raise ValueError("No valid hidden message found in this audio file.")

    start = 32
    end   = start + length * 8
    return _from_bits(bits[start:end])
