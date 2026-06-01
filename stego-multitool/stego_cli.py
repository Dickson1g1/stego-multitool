#!/usr/bin/env python3
"""stego_cli.py — Steganography Multi-Tool CLI."""

import argparse
import sys
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich         import box

console = Console()

def cmd_hide(args) -> int:
    secret = args.secret.encode("utf-8") if isinstance(args.secret, str) \
             else args.secret

    if args.carrier == "image":
        from stego.image import hide
        hide(args.input, secret, args.output)
        console.print(f"[green]✔[/green] Hidden in image → [bold]{args.output}[/bold]")

    elif args.carrier == "audio":
        from stego.audio import hide
        hide(args.input, secret, args.output)
        console.print(f"[green]✔[/green] Hidden in audio → [bold]{args.output}[/bold]")

    elif args.carrier == "qr":
        from stego.qr import hide
        hide(args.input, secret, args.output)
        console.print(f"[green]✔[/green] QR code written → [bold]{args.output}[/bold]")

    elif args.carrier == "pdf":
        from stego.pdf import hide
        hide(args.output, args.input, secret, method=args.method or "invisible")
        console.print(f"[green]✔[/green] Hidden in PDF → [bold]{args.output}[/bold]")

    elif args.carrier == "text":
        from stego.text import hide
        result = hide(args.input, secret)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(result)
            console.print(f"[green]✔[/green] Stego text written → [bold]{args.output}[/bold]")
        else:
            console.print(result)

    elif args.carrier == "git":
        from stego.git_stego import hide_in_repo
        sha = hide_in_repo(args.input, args.commit_msg or "Update", secret)
        console.print(f"[green]✔[/green] Committed → [bold]{sha}[/bold]")

    return 0


def cmd_reveal(args) -> int:
    if args.carrier == "image":
        from stego.image import reveal
        secret = reveal(args.input)
    elif args.carrier == "audio":
        from stego.audio import reveal
        secret = reveal(args.input)
    elif args.carrier == "qr":
        from stego.qr import reveal
        secret = reveal(args.input)
    elif args.carrier == "pdf":
        from stego.pdf import reveal
        secret = reveal(args.input, method=args.method or "invisible")
    elif args.carrier == "text":
        from stego.text import reveal
        text = open(args.input, encoding="utf-8").read() if args.input != "-" \
               else sys.stdin.read()
        secret = reveal(text)
    elif args.carrier == "git":
        from stego.git_stego import reveal_from_repo
        secret = reveal_from_repo(args.input, args.commit_sha)
    else:
        console.print(f"[red]Unknown carrier: {args.carrier}[/red]")
        return 1

    try:
        console.print(Panel(secret.decode("utf-8"), title="[bold green]Revealed message[/bold green]"))
    except UnicodeDecodeError:
        console.print(f"[yellow]Binary payload ({len(secret)} bytes):[/yellow] {secret.hex()}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="stego", description="Steganography Multi-Tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    # hide subcommand
    h = sub.add_parser("hide", help="Hide a secret in a carrier")
    h.add_argument("carrier", choices=["image","audio","qr","pdf","text","git"])
    h.add_argument("-i", "--input",  required=True, help="Carrier file / cover text / repo path")
    h.add_argument("-s", "--secret", required=True, help="Secret message to hide")
    h.add_argument("-o", "--output", help="Output file path")
    h.add_argument("--method", help="pdf: 'invisible' or 'whitespace'")
    h.add_argument("--commit-msg", help="git: commit summary line")

    # reveal subcommand
    r = sub.add_parser("reveal", help="Extract hidden data from a carrier")
    r.add_argument("carrier", choices=["image","audio","qr","pdf","text","git"])
    r.add_argument("-i", "--input",      required=True, help="Stego file path / repo path")
    r.add_argument("--method",           help="pdf: 'invisible' or 'whitespace'")
    r.add_argument("--commit-sha",       help="git: commit SHA to read from")

    args = p.parse_args()
    try:
        if args.cmd == "hide":   return cmd_hide(args)
        if args.cmd == "reveal": return cmd_reveal(args)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
