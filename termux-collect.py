#!/usr/bin/env python3
"""
termux-collect.py — Termux-friendly front end for email-phish-takedown 2.2.

The release tool is pure Python stdlib, so it runs on Termux as-is. The only
piece that doesn't exist on Android is hatch_gws_cli (Gmail acquisition).
This wrapper replaces Phase A with a file: bring your own raw Gmail API
response bytes (e.g. saved from a desktop run, or exported JSON), and the
full Phase B pipeline + forensic case layout run unchanged.

Usage:
  python3 termux-collect.py --from-file raw_message.json --slug my-case \\
      -o ~/scam-intel-cases [--network] [--message-id ID] [--account ACCT]

Verify a case exactly like the main tool:
  python3 email-phish-takedown-2.2.py verify --case-dir <dir>
"""

import argparse
import importlib.util
import sys
from pathlib import Path

TOOL = Path(__file__).with_name("email-phish-takedown-2.2.py")


def load_tool():
    spec = importlib.util.spec_from_file_location("ept", str(TOOL))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description="Termux collect: file-fed phishing analysis.")
    parser.add_argument("--from-file", required=True, help="Raw Gmail API response bytes (JSON).")
    parser.add_argument("--slug", required=True, help="Case slug.")
    parser.add_argument("--message-id", default="unknown", help="Gmail message ID (for case ID).")
    parser.add_argument("--account", default="termux-import", help="Label recorded as acquiring account.")
    parser.add_argument("-o", "--output", default="~/scam-intel-cases", help="Case root.")
    parser.add_argument("--network", action="store_true", help="Opt-in network collection (off by default).")
    args = parser.parse_args()

    if not TOOL.exists():
        print(f"[!] tool not found next to this wrapper: {TOOL}", file=sys.stderr)
        return 1

    tool = load_tool()
    raw = Path(args.from_file).expanduser().read_bytes()
    try:
        out = tool.process_message(
            raw_message_bytes=raw,
            message_id=args.message_id,
            slug=args.slug,
            output_root=Path(args.output).expanduser(),
            account=args.account,
            network=args.network,
        )
    except Exception as exc:
        print(f"[!] PIPELINE FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"[+] case: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
