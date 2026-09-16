# CyberPatriot Linux Toolkit

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3](https://img.shields.io/badge/python-3.x-blue.svg)

A set of Python audit scripts for the Linux images: each one finds and
reports a category of vulnerability, none of them auto-fix anything.
That's deliberate — CyberPatriot scores you for *identifying and fixing*
vulnerabilities yourself, and auto-fixing risks silently breaking a
required service and costing you points you'd never see coming. Treat
every finding as a lead to investigate, not a verdict to trust blindly.

**Standard library only.** No `pip install` needed anywhere — these
scripts have to run on a competition image that typically has no
internet access.

## Before the round

1. Read the scenario README carefully and fill in the three config
   files in `config/`:
   - `authorized_users.json` — every account that should exist, and
     which of those should have admin/sudo rights.
   - `expected_services.json` — services required to stay on, ports
     that should be listening, and services that should never run.
   - `prohibited_files.json` — directories to scan and what counts as
     a prohibited file for this scenario.
   - `suid_whitelist.json` already has a reasonable Debian/Ubuntu
     default; skim it once against your actual image since this
     varies a bit by distro and version.
2. Copy the whole `cyberpatriot-toolkit/` folder onto your practice VM
   and run it there first. Get a feel for what a *clean* system
   reports so you recognize a real finding during the round instead of
   chasing your own tool's false positives.

## During the round

Run everything, ideally as root/sudo for complete results:

```bash
sudo python3 run_all.py
```

Run one check at a time (any file in `checks/` is runnable on its own):

```bash
sudo python3 checks/users_groups.py
```

Run a subset:

```bash
sudo python3 run_all.py --only users_groups,ssh_audit,cron_at
```

Save a full JSON report (handy for comparing runs later):

```bash
sudo python3 run_all.py --save snapshots/report1.json
```

### Catching changes mid-round (the important one)

Take a snapshot the moment the round starts, before you touch
anything:

```bash
sudo python3 baseline.py snapshot --out snapshots/round-start.json
```

Then periodically — say, every 20–30 minutes, or any time something
feels off:

```bash
sudo python3 baseline.py snapshot --out snapshots/now.json --diff-against snapshots/round-start.json
```

This tells you exactly what changed: new users, new admins, new
listening ports, newly enabled services, new SUID binaries, new cron
entries. A backdoor that re-creates itself is much easier to catch as
a diff than by re-reading a full report every time.

## What each check does

| Script | Flags |
|---|---|
| `users_groups.py` | Unauthorized accounts, stray UID 0 accounts, unauthorized sudo/admin members, empty passwords |
| `password_policy.py` | Weak password aging (`login.defs`) and missing complexity enforcement (`pwquality`/PAM) |
| `suid_sgid.py` | SUID/SGID binaries outside the expected whitelist |
| `world_writable.py` | World-writable files, and world-writable directories missing the sticky bit |
| `prohibited_files.py` | Banned file extensions and filenames matching known hacking-tool keywords |
| `network_ports.py` | Listening TCP/UDP ports outside the expected list; flags classic high-risk ports outright |
| `firewall.py` | Whether a firewall (ufw/firewalld/iptables) is installed, active, and default-deny |
| `cron_at.py` | Every cron/at entry, with suspicious ones (curl/wget/reverse-shell patterns) flagged first |
| `ssh_audit.py` | Risky `sshd_config` settings, plus every account with an authorized SSH key |
| `services.py` | Enabled services that shouldn't be (telnet, rsh, nfs...) and required services that aren't enabled |
| `auth_log.py` | Failed login bursts, new-account events, and sudo usage from the auth log |
| `updates.py` | How many package updates are available (best-effort — often blocked by no internet) |

## A rules note

Scripts are allowed during the online rounds, but **pre-written
scripts are prohibited at the National Finals Competition** — brought
in electronically, on a storage device, or on paper. If your team
makes it to Nationals, this toolkit stays behind; that round tests
doing it by hand. Confirm the current season's exact wording with your
coach, since CyberPatriot revises the rules book most years.

## Extending it

Every check in `checks/` follows the same shape: a `check()` function
that returns a list of `utils.finding(severity, title, detail)` dicts.
To add a new one, copy the shortest existing check (`firewall.py` is a
good template), write your logic, then add one line to the `CHECKS`
list in `run_all.py`.

## Disclaimer

Built for use on CyberPatriot competition images and personal practice
VMs you're authorized to audit. Point it only at systems you own or
have permission to test.

## License

[MIT](LICENSE) — see the LICENSE file.
