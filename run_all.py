#!/usr/bin/env python3
"""
run_all.py -- runs every check module and prints one consolidated
report, sorted so HIGH-severity findings across all checks are easy
to scan. Run with sudo for a complete picture; most checks still
produce partial results without root.

Usage:
    sudo python3 run_all.py                 # run everything, print report
    sudo python3 run_all.py --only ssh,cron  # run a subset
    sudo python3 run_all.py --save report.json
    python3 run_all.py --list               # list available check names
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import utils
from checks import (
    users_groups, password_policy, suid_sgid, world_writable,
    prohibited_files, network_ports, firewall, cron_at, ssh_audit,
    services, auth_log, updates,
)

CHECKS = [
    ("users_groups", "Users & Groups", users_groups.check),
    ("password_policy", "Password Policy", password_policy.check),
    ("suid_sgid", "SUID / SGID Binaries", suid_sgid.check),
    ("world_writable", "World-Writable Files & Dirs", world_writable.check),
    ("prohibited_files", "Prohibited Files", prohibited_files.check),
    ("network_ports", "Listening Ports", network_ports.check),
    ("firewall", "Firewall", firewall.check),
    ("cron_at", "Cron & At Jobs", cron_at.check),
    ("ssh_audit", "SSH Configuration", ssh_audit.check),
    ("services", "Enabled Services", services.check),
    ("auth_log", "Auth Log Summary", auth_log.check),
    ("updates", "Package Updates", updates.check),
]


def main():
    parser = argparse.ArgumentParser(description="Run all CyberPatriot Linux checks")
    parser.add_argument("--only", help="Comma-separated check names to run (see --list)")
    parser.add_argument("--save", help="Also save the full report as JSON to this path")
    parser.add_argument("--list", action="store_true", help="List check names and exit")
    args = parser.parse_args()

    if args.list:
        for key, name, _ in CHECKS:
            print(f"  {key:<18} {name}")
        return

    selected = set(args.only.split(",")) if args.only else None
    to_run = [(k, n, fn) for k, n, fn in CHECKS if selected is None or k in selected]

    if not to_run:
        print("No matching checks. Use --list to see valid names.")
        sys.exit(1)

    if not utils.is_root():
        print("Note: not running as root. Several checks (shadow file, other users' "
              "crontabs, full filesystem scans) will be incomplete. Re-run with sudo "
              "for the full picture.\n")

    all_results = {}
    totals = {utils.HIGH: 0, utils.MED: 0, utils.LOW: 0, utils.INFO: 0}
    start = time.time()

    for key, name, fn in to_run:
        try:
            findings = fn()
        except Exception as e:  # noqa: BLE001 -- one bad check must not kill the run
            findings = [utils.finding(utils.MED, f"{name} check crashed", str(e))]
        utils.print_findings(name, findings)
        all_results[key] = findings
        for f in findings:
            totals[f["severity"]] = totals.get(f["severity"], 0) + 1

    elapsed = time.time() - start
    summary = f"Done in {elapsed:.1f}s -- HIGH: {totals[utils.HIGH]}  MEDIUM: {totals[utils.MED]}  LOW: {totals[utils.LOW]}  INFO: {totals[utils.INFO]}"
    print(summary)

    if args.save:
        with open(args.save, "w") as fh:
            json.dump({"timestamp": utils.timestamp(), "results": all_results, "totals": totals}, fh, indent=2)
        print(f"Full report saved to {args.save}")


if __name__ == "__main__":
    main()
