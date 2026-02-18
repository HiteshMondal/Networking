<div align="center">

# Networking & Cybersecurity Automation Toolkit

**A modular Bash-based suite for network diagnostics, security hardening, forensic collection, and real-time monitoring — with a live web dashboard.**

[![Bash](https://img.shields.io/badge/Shell-Bash_5.x-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Dashboard-Python_3.8+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)](https://kernel.org)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Features](#features)
- [Quick Start](#quick-start)
- [Scripts Reference](#scripts-reference)
- [Tools Reference](#tools-reference)
- [Dashboard](#dashboard)
- [Configuration](#configuration)
- [Output & Logs](#output--logs)
- [Requirements](#requirements)

---

## Overview

The **Networking & Cybersecurity Automation Toolkit** is a collection of Bash scripts and tools designed to automate common network analysis, security auditing, and forensic tasks on Linux systems. All executions are logged with timestamps, and results are surfaced through an interactive web dashboard with live tailing, search, social sharing, and real-time system resource monitoring.

```
┌─────────────────────────────────────────────────────────────┐
│                         run.sh                              │
│              (unified entry point / menu)                   │
└───────────┬────────────────────────┬────────────────────────┘
            │                        │
    ┌───────▼───────┐       ┌────────▼──────────┐
    │    scripts/   │       │      tools/        │
    │  (automation) │       │  (interactive CLI) │
    └───────┬───────┘       └────────┬───────────┘
            │                        │
    ┌───────▼────────────────────────▼───────────┐
    │          logs/  &  output/                  │
    │      (structured, timestamped output)       │
    └────────────────────┬────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │  dashboard/         │
              │  (live web UI)      │
              └─────────────────────┘
```

---

## Project Structure

```
networking_cybersecurity/
│
├── run.sh                        # Main entry point — interactive menu
├── README.md                     # This file
│
├── config/
│   └── settings.conf             # Global configuration (paths, flags, defaults)
│
├── lib/
│   ├── colors.sh                 # ANSI colour definitions for terminal output
│   └── functions.sh              # Shared helper functions used by all scripts/tools
│
├── scripts/                      # Automated security & network scripts
│   ├── run_script.sh             # Script runner with logging wrapper
│   ├── detect_suspicious_net_linux.sh   # Suspicious network connection detection
│   ├── forensic_collect.sh              # Forensic artifact collection
│   ├── revert_security.sh               # Revert hardening changes
│   ├── secure_system.sh                 # System hardening automation
│   ├── system_info.sh                   # System info & inventory report
│   └── web_recon.sh                     # Web reconnaissance & enumeration
│
├── tools/                        # Interactive educational/diagnostic tools
│   ├── tools.sh                  # Tool launcher / menu
│   ├── core_protocols.sh         # TCP/IP, DNS, HTTP protocol analysis
│   ├── ip_addressing.sh          # IP/CIDR/subnet calculator & analyser
│   ├── network_master.sh         # All-in-one network diagnostics suite
│   ├── network_tools.sh          # Ping, traceroute, port scan utilities
│   ├── networking_basics.sh      # Network fundamentals & diagnostics
│   ├── security_fundamentals.sh  # Encryption, hashing, key generation demos
│   └── switching_routing.sh      # Switching, VLAN, routing analysis
│
├── logs/                         # Auto-generated execution logs
│   └── <script>_<YYYYMMDD_HHMMSS>.log
│
├── output/                       # Script-generated output files
│   └── <category>_<timestamp>/   # Grouped by run (keys, reports, captures)
│
└── dashboard/                    # Real-time web dashboard
    ├── index.html                # Dashboard UI
    ├── app.js                    # Frontend logic
    ├── style.css                 # Styling & theming
    ├── server.py                 # Python HTTP API server
    └── start_dashboard.sh        # Dashboard launcher script
```

---

## Features

### Scripts (Automated Tasks)

| Feature | Description |
|---|---|
| 🔍 **Suspicious Network Detection** | Scans active connections for anomalous ports, foreign IPs, and unexpected listeners |
| 🔒 **System Hardening** | Applies firewall rules, disables unused services, locks down SSH, and enforces password policies |
| ↩️ **Revert Hardening** | Safely rolls back all changes applied by `secure_system.sh` |
| 💻 **System Inventory** | Collects OS version, hardware, users, running services, open ports, and disk info |
| 🕵️ **Forensic Collection** | Captures volatile data — processes, connections, ARP cache, login history, cron jobs |
| 🌐 **Web Recon** | Performs passive and active web reconnaissance including DNS, headers, and directory enumeration |

### Tools (Interactive CLI)

| Tool | Description |
|---|---|
| 🌐 **Network Tools** | Ping, traceroute, DNS lookup, Whois, port scanning |
| 📡 **Core Protocols** | Analyse TCP/IP, UDP, ICMP, DNS, HTTP in real-time |
| 🔢 **IP Addressing** | Subnet calculator, CIDR breakdown, IP class identifier |
| 🗺️ **Network Master** | Comprehensive suite: discovery, scanning, bandwidth, latency |
| 📖 **Networking Basics** | Guided diagnostics for connectivity, routing, and interfaces |
| 🔐 **Security Fundamentals** | RSA/ECC key generation, AES encryption, SHA hashing, digital signatures |
| 🔀 **Switching & Routing** | VLAN info, routing table analysis, ARP inspection |

### Dashboard

| Feature | Description |
|---|---|
| 📊 **Live Stats** | Total runs, success/warning/fail counts with animated counters |
| 📈 **Metrics** | Success rate ring, average duration, category breakdown chart |
| 🖥️ **System Resources** | Real-time CPU, Memory, Disk, Network usage — updates every 5 seconds |
| ⚠️ **Alerts** | Configurable warn/critical thresholds with optional email notifications |
| 📁 **Log Viewer** | In-browser log viewer with live tail (3-second polling) |
| 🔎 **Full-Text Search** | Search across all log files with match highlighting |
| ↗️ **Social Sharing** | Share reports to Twitter/X, LinkedIn, Reddit or via email |
| 📤 **Export** | Download a full plain-text report of all stats, history, and files |

---

## Quick Start

### 1. Run the interactive menu

```bash
./run.sh
```

### 2. Launch the dashboard

```bash
cd dashboard
./start_dashboard.sh
# Then open http://localhost:8000 in your browser
```
Or run the server directly:
```bash
python3 dashboard/server.py
```

> **Optional:** Install `psutil` for live system resource monitoring in the dashboard:
> ```bash
> pip install psutil --break-system-packages
> ```

---

## Scripts Reference

All scripts are invoked through `run.sh` or directly via `scripts/run_script.sh`. Each execution produces a timestamped log in `logs/`.

### `detect_suspicious_net_linux.sh`
Analyses active network connections using `ss`, `netstat`, and `/proc/net`. Flags:
- Connections to unusual ports (non-standard high ports, known malware ports)
- Processes with unexpected listening sockets
- Foreign IP connections not in a whitelist

### `secure_system.sh`
Applies a layered hardening checklist:
- Configures `ufw` / `iptables` firewall rules
- Hardens `/etc/ssh/sshd_config` (disables root login, enforces key auth)
- Disables unnecessary services via `systemctl`
- Sets password aging policies via `chage` / `pam`
- Saves a revert manifest for `revert_security.sh`

### `revert_security.sh`
Reads the revert manifest created by `secure_system.sh` and restores all previous settings — safe to run after testing a hardened environment.

### `system_info.sh`
Generates a structured system inventory including:
- OS, kernel, hostname, uptime
- CPU, memory, disk layout
- Running services and open ports
- Local user accounts and sudo privileges

### `forensic_collect.sh`
Captures volatile system state for incident response:
- Running processes (`ps`, `/proc`)
- Active network connections
- ARP cache and routing table
- Cron jobs (all users)
- Recent login history and auth log tail
- Loaded kernel modules

Output is saved as a structured report in `output/`.

### `web_recon.sh`
Performs web target reconnaissance:
- DNS record enumeration (A, MX, TXT, NS)
- HTTP header analysis
- Basic directory/path enumeration
- Robots.txt and sitemap discovery

---

## Tools Reference

Tools are interactive and menu-driven. Launch with `./run.sh` → Tools, or directly:

```bash
bash tools/network_tools.sh
bash tools/security_fundamentals.sh
# etc.
```

### `security_fundamentals.sh`
Hands-on cryptography demos — all operations run locally:

```
┌─────────────────────────────────────┐
│  Security Fundamentals Tool         │
├─────────────────────────────────────┤
│  1. RSA key generation & encrypt    │
│  2. ECC key pair generation         │
│  3. AES-256 encryption/decryption   │
│  4. SHA-256 / SHA-512 hashing       │
│  5. Digital signature (sign/verify) │
│  6. File integrity check            │
└─────────────────────────────────────┘
```

Output files (keys, encrypted blobs, signatures) are written to `output/security_<timestamp>/`.

### `network_tools.sh`
Wraps common network utilities in a guided interface:
- `ping` with configurable count and interval
- `traceroute` / `tracepath`
- `nmap` port scan (if installed)
- DNS lookup via `dig` / `nslookup`
- Interface and routing info

---

## Dashboard

The dashboard is a self-contained Python HTTP server + vanilla JS frontend requiring **no npm, no build step**.

### Starting

```bash
cd dashboard
python3 server.py
# Listening on http://localhost:8000
```

Custom port:

```bash
DASHBOARD_PORT=9090 python3 server.py
```

### Email Notifications (SMTP)

Configure via environment variables before starting the server:

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=you@gmail.com
export SMTP_PASS=your_app_password

python3 server.py
```

Then use the **⚠ Alerts** button in the dashboard header to set thresholds and enable automatic email alerts when CPU/Memory/Disk hit critical levels.

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/dashboard-data` | GET | Full dashboard payload (logs, outputs, history, stats) |
| `/api/metrics` | GET | Success rate, avg duration, category breakdown, disk usage |
| `/api/system-stats` | GET | Live CPU, Memory, Disk, Network (requires psutil) |
| `/api/file` | GET | Serve a log or output file (`?dir=logs&name=file.log`) |
| `/api/tail` | GET | Last N lines + mtime for live tailing |
| `/api/search` | GET | Full-text search across all log files |
| `/api/notify-email` | POST | Send an email notification (requires SMTP config) |
| `/api/alert-settings` | GET/POST | Read or update alert thresholds |

---

## Configuration

Edit `config/settings.conf` to adjust global defaults:

```bash
# Example settings.conf options
LOG_DIR="../logs"
OUTPUT_DIR="../output"
DASHBOARD_PORT=8000
MAX_LOG_LINES=10000
```

Shared library functions are in `lib/functions.sh` — source this in any custom script:

```bash
source "$(dirname "$0")/../lib/functions.sh"
source "$(dirname "$0")/../lib/colors.sh"
```

---

## Output & Logs

### Log Files

Every script run creates a log at `logs/<script>_<YYYYMMDD_HHMMSS>.log`:

```
logs/
├── network_tools_20260218_144030.log
├── security_fundamentals_20260218_144124.log
└── networking_basics_20260218_144142.log
```

Logs capture: start time, command output, exit code, and completion timestamp. The dashboard parses these to determine status (success / warning / error) and duration.

### Output Files

Scripts that produce artifacts write to `output/<category>_<timestamp>/`:

```
output/security_20260218_144125/
├── rsa_private.pem / rsa_public.pem    # RSA key pair
├── ecc_private.pem / ecc_public.pem    # ECC key pair
├── rsa_plain.txt / rsa_cipher.bin      # Encryption demo
├── rsa_decrypted.txt                   # Decryption result
├── aes_data.txt / aes_data.enc         # AES encrypt/decrypt
├── aes_data.dec
├── secret.txt / secret.enc / secret.dec
├── doc_to_sign.txt / doc.sig           # Digital signature demo
├── doc.sha256 / integrity_test.sha256  # Integrity checks
└── doc.txt / doc_tampered.txt          # Tamper detection
```

---

## Requirements

### System

| Requirement | Notes |
|---|---|
| Linux (Debian/Ubuntu/Arch) | Tested on Ubuntu 24.04 |
| Bash 5.x | `bash --version` |
| Python 3.8+ | For dashboard server |
| Standard tools | `ss`, `ip`, `dig`, `curl`, `openssl` |
| Optional: `nmap` | For port scanning features |
| Optional: `psutil` | `pip install psutil --break-system-packages` — for system stats in dashboard |

### Permissions

Some scripts require elevated privileges:

```bash
# System hardening and forensic collection may need sudo
sudo ./scripts/secure_system.sh
sudo ./scripts/forensic_collect.sh
```

Network scanning tools (`nmap`) may require `sudo` or raw socket capabilities.

---

## Security Notes

- All scripts operate **locally** — no data is sent to external services unless you explicitly configure SMTP or use the social share feature.
- The dashboard server binds to `localhost` by default. Do **not** expose it publicly without authentication.
- Forensic and hardening scripts should be reviewed before running in production environments.
- RSA/ECC keys and encrypted files generated by `security_fundamentals.sh` are for **demonstration purposes only**.

---

## 👨‍💻 Author

Hitesh Mondal 🔹 Developer & Cybersecurity Enthusiast 🔹 Focus areas: Networking • System Security • DevOps • Cloud Infrastructure

<div align="center">
  
</div>