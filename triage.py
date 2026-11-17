#!/usr/bin/env python3
"""CLI Entrypoint for Scam & Phishing Infrastructure Triage Workbench."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage import __version__
from triage.engine import TriageEngine
from triage.network import SSRFProtectionError
from triage.reporter import print_cli_summary, to_json, to_markdown


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="triage.py",
        description="Scam & Phishing Infrastructure Triage Workbench (100% Passive OSINT)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 triage.py example.com
  python3 triage.py "hxxp://suspicious-login[.]xyz/verify" -f markdown -o report.md
  python3 triage.py 8.8.8.8 -f json -o report.json
  python3 triage.py evil-bank.com --format all -o investigation
        """,
    )

    parser.add_argument(
        "target",
        help="Suspicious URL, domain, or IP address to investigate (accepts defanged input)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output file path (e.g. report.md, report.json, or base filename)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "markdown", "json", "all"],
        default=None,
        help="Report format: text (terminal summary), markdown, json, or all. Inferred from --output if omitted.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress terminal UI output (useful when redirecting output to a file)",
    )
    parser.add_argument(
        "--dns-servers",
        type=str,
        default=None,
        help="Comma-separated custom DNS nameservers (e.g. '9.9.9.9,1.1.1.1')",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for public API calls and DNS (max 5.0s per SSRF guardrails)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Parse custom nameservers if provided
    nameservers = None
    if args.dns_servers:
        nameservers = [s.strip() for s in args.dns_servers.split(",") if s.strip()]

    # Determine desired format
    fmt = args.format
    if fmt is None:
        if args.output:
            lower_out = args.output.lower()
            if lower_out.endswith(".json"):
                fmt = "json"
            elif lower_out.endswith(".md") or lower_out.endswith(".markdown"):
                fmt = "markdown"
            else:
                fmt = "markdown"
        else:
            fmt = "text"

    try:
        engine = TriageEngine(nameservers=nameservers, timeout=args.timeout)
        report = engine.triage(args.target)
    except SSRFProtectionError as e:
        print(f"[!] SSRF Guardrail Violation: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during triage: {e}", file=sys.stderr)
        return 1

    # Render Terminal Output unless quiet is specified or writing pure json/md to stdout
    if not args.quiet and (fmt == "text" or args.output is not None):
        print_cli_summary(report)

    # Handle file outputs
    if args.output:
        out_path = Path(args.output)
        if fmt == "json":
            out_path.write_text(to_json(report), encoding="utf-8")
            if not args.quiet:
                print(f"JSON report saved to: {out_path.resolve()}")
        elif fmt == "markdown":
            out_path.write_text(to_markdown(report), encoding="utf-8")
            if not args.quiet:
                print(f"Markdown report saved to: {out_path.resolve()}")
        elif fmt == "all":
            stem = out_path.stem
            parent = out_path.parent
            md_path = parent / f"{stem}.md"
            json_path = parent / f"{stem}.json"
            md_path.write_text(to_markdown(report), encoding="utf-8")
            json_path.write_text(to_json(report), encoding="utf-8")
            if not args.quiet:
                print(f"Markdown report saved to: {md_path.resolve()}")
                print(f"JSON report saved to: {json_path.resolve()}")
    else:
        # Output directly to stdout if specific format requested without output file
        if fmt == "json":
            print(to_json(report))
        elif fmt == "markdown":
            print(to_markdown(report))

    return 0


if __name__ == "__main__":
    sys.exit(main())
