#!/usr/bin/env python3
"""
baseline.py -- snapshot the system's security-relevant state and diff
two snapshots against each other. Run this once right after the round
starts (before you change anything) and again periodically -- anything
that changed *without you doing it* is worth investigating immediately.

Usage:
    sudo python3 baseline.py snapshot [--out snapshots/round-start.json]
    sudo python3 baseline.py diff snapshots/round-start.json snapshots/now.json
    sudo python3 baseline.py snapshot --diff-against snapshots/round-start.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import utils
from checks import users_groups, network_ports, services, suid_sgid, cron_at

SNAPSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapshots")


def take_snapshot():
    users = users_groups._read_passwd()
    groups = users_groups._read_group()
    admins = set()
    for g in users_groups.ADMIN_GROUPS:
        if g in groups:
            admins.update(groups[g]["members"])

    listeners, _ = network_ports.list_listeners()
    listeners = sorted(set(listeners or []))

    enabled_services, _ = services._enabled_services()
    enabled_services = sorted(enabled_services or [])

    suid_paths, _ = suid_sgid._find_suid_sgid()
    suid_paths = sorted(suid_paths or [])

    crontab_entries, script_entries = cron_at._collect_system_cron()
    user_crontabs = cron_at._collect_user_crontabs()
    cron_lines = sorted(f"{src}: {line}" for src, line in crontab_entries + user_crontabs)
    cron_scripts = sorted(f"{path} ({'SUSPICIOUS: ' + hit if hit else 'ok'})" for path, hit in script_entries)

    return {
        "timestamp": utils.timestamp(),
        "users": sorted(users.keys()),
        "admins": sorted(admins),
        "listening_ports": [list(x) for x in listeners],
        "enabled_services": enabled_services,
        "suid_sgid_paths": suid_paths,
        "cron_entries": cron_lines,
        "cron_scripts": cron_scripts,
    }


def save_snapshot(snap, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(snap, fh, indent=2)


def load_snapshot(path):
    with open(path) as fh:
        return json.load(fh)


def _diff_list(old, new):
    old_s, new_s = set(map(str, old)), set(map(str, new))
    return sorted(new_s - old_s), sorted(old_s - new_s)  # added, removed


def diff_snapshots(old, new):
    findings = []
    fields = [
        ("users", "user account", utils.HIGH, utils.MED),
        ("admins", "admin/sudo member", utils.HIGH, utils.MED),
        ("enabled_services", "enabled service", utils.MED, utils.LOW),
        ("suid_sgid_paths", "SUID/SGID binary", utils.HIGH, utils.LOW),
        ("cron_entries", "cron entry", utils.HIGH, utils.LOW),
    ]
    for key, label, add_sev, rem_sev in fields:
        added, removed = _diff_list(old.get(key, []), new.get(key, []))
        for item in added:
            findings.append(utils.finding(add_sev, f"NEW {label}: {item}"))
        for item in removed:
            findings.append(utils.finding(rem_sev, f"REMOVED {label} (may be intentional): {item}"))

    old_ports = ["/".join(map(str, p)) for p in old.get("listening_ports", [])]
    new_ports = ["/".join(map(str, p)) for p in new.get("listening_ports", [])]
    added, removed = _diff_list(old_ports, new_ports)
    for item in added:
        findings.append(utils.finding(utils.HIGH, f"NEW listening port: {item}"))
    for item in removed:
        findings.append(utils.finding(utils.LOW, f"Port no longer listening: {item}"))

    return findings


def main():
    parser = argparse.ArgumentParser(description="Snapshot & diff system state for CyberPatriot rounds")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_snap = sub.add_parser("snapshot", help="Take a snapshot now")
    p_snap.add_argument("--out", default=os.path.join(SNAPSHOT_DIR, "snapshot.json"))
    p_snap.add_argument("--diff-against", help="Immediately diff the new snapshot against this older one")

    p_diff = sub.add_parser("diff", help="Diff two existing snapshot files")
    p_diff.add_argument("old")
    p_diff.add_argument("new")

    args = parser.parse_args()

    if not utils.is_root():
        print("Warning: not running as root -- snapshot will be incomplete "
              "(missing user crontabs, full SUID scan, etc). Re-run with sudo.\n")

    if args.cmd == "snapshot":
        snap = take_snapshot()
        save_snapshot(snap, args.out)
        print(f"Snapshot saved to {args.out} ({snap['timestamp']})")
        if args.diff_against:
            old = load_snapshot(args.diff_against)
            utils.print_findings(f"Diff: {args.diff_against} -> {args.out}", diff_snapshots(old, snap))

    elif args.cmd == "diff":
        old = load_snapshot(args.old)
        new = load_snapshot(args.new)
        utils.print_findings(f"Diff: {args.old} -> {args.new}", diff_snapshots(old, new))


if __name__ == "__main__":
    main()
