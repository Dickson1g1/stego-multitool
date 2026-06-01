"""
Git commit steganography via timestamp manipulation.

Git stores two timestamps per commit:
  - author date:    when the change was written
  - committer date: when the commit was created

In normal commits these are identical (or very close).
We exploit the seconds field of the author timestamp to encode data.

Encoding scheme:
  The Unix timestamp has 60 possible second values (0–59).
  We split each byte of the secret into two 4-bit nibbles.
  Each nibble (0–15) is added to the commit's second value, creating
  a timestamp offset that encodes data.

  A sequence of N commits can hide N/2 bytes of data.

  Alternative approach (implemented here):
  We encode data in commit MESSAGE WHITESPACE — trailing spaces on the
  commit summary line (invisible in most git UIs) using the same
  binary space encoding as the text module.

  This approach:
    - Works on any existing git repo
    - Doesn't require rewriting timestamps (which changes commit hashes)
    - Survives git push/pull/clone (trailing spaces in commit messages
      are preserved)
    - Is detectable by 'git log --format=%B | cat -A'
"""

import struct
from pathlib import Path

try:
    import git as gitpython
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

# Binary whitespace encoding (same as text module)
WS_ZERO = " "    # regular space = bit 0
WS_ONE  = "\t"   # tab = bit 1
MARKER  = "  \t  \t "   # distinctive pattern to mark start of payload


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


def encode_message(secret: bytes) -> str:
    """
    Encode secret bytes as a whitespace suffix for a git commit message.

    Returns a string of spaces and tabs that encodes the secret.
    Append this to any commit summary line — it's invisible in git log.

    Usage:
        git commit -m "Fix bug$(python -c 'from stego.git_stego import encode_message; print(encode_message(b\"secret\"))')"
    """
    payload = struct.pack(">I", len(secret)) + secret
    bits    = _to_bits(payload)
    return MARKER + "".join(WS_ONE if b else WS_ZERO for b in bits)


def decode_message(commit_message: str) -> bytes:
    """
    Decode a hidden message from a git commit message's whitespace tail.

    Parameters
    ----------
    commit_message : the raw commit message string (including trailing whitespace)
    """
    marker_pos = commit_message.find(MARKER)
    if marker_pos == -1:
        raise ValueError("No hidden message found in commit message.")

    payload_start = marker_pos + len(MARKER)
    bits = []
    for ch in commit_message[payload_start:]:
        if ch == WS_ZERO:
            bits.append(0)
        elif ch == WS_ONE:
            bits.append(1)

    if len(bits) < 32:
        raise ValueError("Payload too short.")

    length = struct.unpack(">I", _from_bits(bits[:32]))[0]
    return _from_bits(bits[32: 32 + length * 8])


def hide_in_repo(repo_path: str, commit_message: str, secret: bytes,
                 file_to_commit: str = None) -> str:
    """
    Make a real git commit in repo_path with the secret encoded in
    the commit message whitespace. Returns the commit hash.

    Requires GitPython: pip install GitPython
    """
    if not GIT_AVAILABLE:
        raise ImportError("GitPython not installed: pip install GitPython")

    repo    = gitpython.Repo(repo_path)
    payload = encode_message(secret)
    full_msg = commit_message + payload

    # Stage a file if provided, otherwise create an empty marker file
    if file_to_commit:
        repo.index.add([file_to_commit])
    else:
        marker = Path(repo_path) / ".stego_marker"
        marker.write_text("stego")
        repo.index.add([str(marker)])

    commit = repo.index.commit(full_msg)
    return commit.hexsha


def reveal_from_repo(repo_path: str, commit_sha: str) -> bytes:
    """
    Extract hidden message from a specific commit in a repository.
    """
    if not GIT_AVAILABLE:
        raise ImportError("GitPython not installed.")

    repo   = gitpython.Repo(repo_path)
    commit = repo.commit(commit_sha)
    return decode_message(commit.message)
