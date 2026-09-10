"""Exercise the PowerShell-backed modules against the real operating system.

Run this on Windows to confirm that the scan, traffic and firewall-audit
integrations work on your machine (and in CI):

    python packaging\\verify_windows_modules.py

It performs read-only queries only and prints a short report. Exit code 1
means at least one module could not complete.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.firewall.logic import parse_windows_rules, read_firewall_rules  # noqa: E402
from modules.scanner.logic import (  # noqa: E402
    ScanError,
    assess_baseline,
    baseline_summary,
    build_report,
    run_local_scan,
)
from modules.traffic.logic import TrafficError, parse_snapshot, run_snapshot  # noqa: E402

failures = []


def check_scan():
    print("== Scan Reports ==")
    try:
        report = build_report(run_local_scan())
    except ScanError as error:
        failures.append("scan")
        print(f"  FAILED: {error}")
        return
    print(f"  listeners: {len(report.ports)}")
    print(f"  services:  {len(report.services)}")
    print(f"  hotfixes:  {len(report.patches)}")
    print(f"  firewall:  {'enabled' if report.firewall.enabled else 'disabled/unknown'}")
    print(f"  findings:  {len(report.findings)}")
    baseline = assess_baseline(report)
    summary = baseline_summary(baseline)
    print(f"  baseline:  {summary['hardening']}% hardening "
          f"({summary['counts']['pass']} pass / {summary['counts']['fail']} fail / "
          f"{summary['counts']['unknown']} unverifiable)")


def check_traffic():
    print("== Traffic Dashboard ==")
    try:
        snapshot = parse_snapshot(run_snapshot())
    except TrafficError as error:
        failures.append("traffic")
        print(f"  FAILED: {error}")
        return
    print(f"  adapters:    {len(snapshot.adapters)}")
    print(f"  connections: {len(snapshot.connections)}")


def check_firewall_audit():
    print("== Firewall rule audit ==")
    try:
        rules = parse_windows_rules(read_firewall_rules())
    except RuntimeError as error:
        failures.append("firewall-audit")
        print(f"  FAILED: {error}")
        return
    enabled = sum(1 for rule in rules if rule.enabled)
    inbound_allow = sum(
        1 for rule in rules if rule.direction == "Inbound" and rule.action == "Allow" and rule.enabled
    )
    print(f"  rules read:           {len(rules)}")
    print(f"  enabled:              {enabled}")
    print(f"  enabled inbound allow: {inbound_allow}  (review these first)")


def main() -> int:
    print("Bastion - Windows integration check (read-only)\n")
    check_scan()
    check_traffic()
    check_firewall_audit()
    print()
    if failures:
        print(f"FAILED modules: {', '.join(failures)}")
        return 1
    print("All PowerShell-backed modules responded successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
