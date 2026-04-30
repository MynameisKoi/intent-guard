#!/usr/bin/env python3
"""CLI entrypoint."""

import argparse
import json
import sys

from engine.agent_runtime.tracing import configure_runtime_observability
from engine.orchestrator import run_scan


def main() -> None:
    p = argparse.ArgumentParser(description="IntentGuard scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="Run analysis on a GitHub URL or local path")
    s.add_argument("target", help="HTTPS GitHub repository URL or filesystem path")
    s.add_argument("--json", action="store_true", help="Print JSON nutrition label to stdout")
    args = p.parse_args()

    if args.cmd == "scan":
        configure_runtime_observability()
        record = run_scan(args.target)
        if record.status == "failed":
            print(record.error or "scan failed", file=sys.stderr)
            sys.exit(1)
        if args.json and record.report:
            print(json.dumps(record.report.model_dump(mode="json"), indent=2))
        else:
            print(f"Scan {record.scan_id} completed.")
            if record.report:
                print(f"Risk: {record.report.risk_score} ({record.report.risk_label})")
                print(record.report.intent_summary[:2000])


if __name__ == "__main__":
    main()
