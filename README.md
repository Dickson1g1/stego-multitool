```
 ███████╗████████╗███████╗ ██████╗  ██████╗ 
 ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗
 ███████╗   ██║   █████╗  ██║  ███╗██║   ██║
 ╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║
 ███████║   ██║   ███████╗╚██████╔╝╚██████╔╝
 ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ 

 ███╗   ███╗██╗   ██╗██╗  ████████╗██╗████████╗ ██████╗  ██████╗ ██╗     
 ████╗ ████║██║   ██║██║  ╚══██╔══╝██║╚══██╔══╝██╔═══██╗██╔═══██╗██║     
 ██╔████╔██║██║   ██║██║     ██║   ██║   ██║   ██║   ██║██║   ██║██║     
 ██║╚██╔╝██║██║   ██║██║     ██║   ██║   ██║   ██║   ██║██║   ██║██║     
 ██║ ╚═╝ ██║╚██████╔╝███████╗██║   ██║   ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝

   images · audio · qr · pdf · zero-width unicode · git commits
```

# stego-multitool

> A multi-format steganography toolkit that hides secret data across
> six different carrier types — images, audio, QR codes, PDFs, plaintext,
> and git commits. Built to explore covert communication techniques and
> demonstrate that steganography extends far beyond hiding text in pictures.

---

## What it does

`stego-multitool` encodes and decodes hidden messages across six media
formats using different techniques for each. A single unified CLI
handles all carriers with `hide` and `reveal` subcommands.

```
$ python stego_cli.py hide image -i photo.png -s "Top secret" -o stego.png
✔ Hidden in image → stego.png

$ python stego_cli.py reveal image -i stego.png
╭─────────── Revealed message ───────────╮
│ Top secret                             │
╰────────────────────────────────────────╯
```

---

## Carriers & techniques

| Carrier | Technique | How it works |
|---------|-----------|--------------|
| **Image** (PNG/BMP) | LSB encoding | Replaces bit 0 of each R/G/B channel; change of 1/255 is invisible |
| **Audio** (WAV/FLAC) | LSB sample encoding | Replaces bit 0 of each 16-bit PCM sample; inaudible at 1/65536 level |
| **QR code** | Quiet zone LSB | Hides data in the white border pixels; QR decoder ignores them |
| **PDF** | Invisible text layer | White-on-white text at size 1pt; selectable but invisible |
| **PDF** | Whitespace encoding | Regular space = bit 0, non-breaking space = bit 1 in cover text |
| **Text** | Zero-width Unicode | U+200B / U+200C invisible characters injected between words |
| **Git** | Commit message whitespace | Spaces and tabs appended to commit summary line; invisible in git log |

---

## Features

- **Image LSB** — encode arbitrary bytes into PNG/BMP pixel data;
  32-bit length header enables clean extraction; must save as PNG
  (JPEG lossy compression destroys LSBs)
- **Audio LSB** — WAV and FLAC supported via soundfile + numpy;
  samples read as int16 for direct bit manipulation; lossless formats
  only — MP3/Ogg would destroy the payload
- **QR code steganography** — generates a scannable QR at error-correction
  level H (30% damage tolerance), hides secondary message in the quiet
  zone border pixels that decoders ignore
- **PDF invisible text** — uses ReportLab to render white text at 1pt
  font size; pdfminer.six extracts it during reveal; hex-encoded for
  PDF stream safety
- **PDF whitespace** — encodes bits as regular spaces vs non-breaking
  spaces in the visible text; survives copy-paste into text editors
- **Zero-width Unicode** — uses U+200B (bit 0) and U+200C (bit 1)
  injected after the first word; renders as nothing in every browser,
  terminal, and email client; detectable by hex editors
- **Git commit encoding** — appends space/tab whitespace to commit
  summary lines; invisible in `git log` output; survives push/pull/clone
- **Rich CLI** — unified `hide` / `reveal` interface for all six carriers
- **Pure Python** — no compiled extensions beyond pip packages

---

## Requirements

- Python 3.10+
- Pillow — image processing
- soundfile + numpy — audio processing
- qrcode — QR code generation
- reportlab — PDF writing
- pdfminer.six — PDF reading
- GitPython — git repository interaction
- rich — terminal output

```bash
pip install Pillow soundfile numpy qrcode reportlab \
            "pdfminer.six" GitPython rich
```

---

## Installation

```bash
git clone https://github.com/Dickson1g1/stego-multitool.git
cd stego-multitool
python3 -m venv .venv && source .venv/bin/activate
pip install Pillow soundfile numpy qrcode reportlab \
            "pdfminer.six" GitPython rich
chmod +x stego_cli.py
```

---

## Usage

```bash
# Image LSB
python stego_cli.py hide image -i photo.png -s "secret message" -o stego.png
python stego_cli.py reveal image -i stego.png

# Audio LSB (WAV or FLAC only — not MP3)
python stego_cli.py hide audio -i song.wav -s "hidden audio" -o stego.wav
python stego_cli.py reveal audio -i stego.wav

# QR code with hidden message in quiet zone
python stego_cli.py hide qr -i "https://example.com" -s "qr secret" -o qr.png
python stego_cli.py reveal qr -i qr.png

# PDF — invisible white text layer
python stego_cli.py hide pdf -i "This is visible text." -s "pdf secret" -o doc.pdf
python stego_cli.py reveal pdf -i doc.pdf

# PDF — whitespace encoding
python stego_cli.py hide pdf -i "Visible content." -s "ws secret" -o doc.pdf --method whitespace
python stego_cli.py reveal pdf -i doc.pdf --method whitespace

# Zero-width Unicode text
python stego_cli.py hide text -i "Cover text goes here" -s "hidden" -o stego.txt
python stego_cli.py reveal text -i stego.txt

# Git commit whitespace encoding
python stego_cli.py hide git -i /path/to/repo -s "git secret" --commit-msg "Fix typo"
python stego_cli.py reveal git -i /path/to/repo --commit-sha 
```

---

## Detection notes

| Technique | Detectable by |
|-----------|---------------|
| Image LSB | Steganalysis tools (StegSolve, zsteg, stegdetect) |
| Audio LSB | Audio spectrum analysis; LSB histogram anomalies |
| QR quiet zone | Visual inspection of QR border pixels |
| PDF invisible text | Select-all in PDF viewer; pdfminer extraction |
| Zero-width Unicode | `cat -A`, `hexdump`, Unicode-aware text editors |
| Git whitespace | `git log --format=%B \| cat -A` |

These techniques hide data from casual inspection, not forensic analysis.
Combine with encryption for operational security.

---

## Project structure

```
stego-multitool/
├── stego/
│   ├── __init__.py
│   ├── image.py         # LSB image encode/decode (Pillow)
│   ├── audio.py         # LSB audio encode/decode (soundfile + numpy)
│   ├── qr.py            # QR quiet zone encode/decode (qrcode)
│   ├── pdf.py           # Invisible text + whitespace (reportlab + pdfminer)
│   ├── text.py          # Zero-width Unicode encode/decode
│   └── git_stego.py     # Git commit whitespace encoding (GitPython)
├── stego_cli.py         # Rich CLI entry point
└── tests/
    └── test_stego.py
```

---

## Concepts covered

- Least Significant Bit (LSB) encoding in images and audio
- 32-bit length headers for reliable payload extraction
- mmap-style zero-copy image pixel manipulation with Pillow
- PCM audio sample manipulation with numpy int16 arrays
- QR error-correction structure and quiet zone layout
- PDF content streams — invisible text layers with ReportLab
- Unicode zero-width character encoding (U+200B, U+200C, U+200D)
- Git internals — commit message structure and whitespace persistence
- Binary-to-space encoding (space=0, tab=1 or NBSP=1)
- Rich `Panel`, `Console`, and `Table` for terminal output

---

## Legal notice

Use only on files and systems you own or have explicit permission to
modify. Steganography used to conceal illegal activity or bypass
security controls may violate laws in your jurisdiction. This tool
is provided for educational and authorised security research only.

---

## License

MIT — do whatever you want, attribution appreciated.
