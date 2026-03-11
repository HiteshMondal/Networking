<div align="center">

# Networking & Cybersecurity Automation Toolkit

**A modular Bash-based suite for network diagnostics, security hardening, forensic collection, threat detection, and real-time monitoring — with a live web dashboard.**

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
- [Security Modules Reference](#security-modules-reference)
- [Network Lab Reference](#network-lab-reference)
- [Dashboard](#dashboard)
- [Configuration](#configuration)
- [Output & Logs](#output--logs)
- [Requirements](#requirements)
- [Security Notes](#security-notes)

---

## Overview

The **Networking & Cybersecurity Automation Toolkit** is a collection of Bash scripts and tools designed to automate common network analysis, security auditing, threat detection, and forensic tasks on Linux systems. All executions are logged with timestamps, and results are surfaced through an interactive web dashboard with live tailing, full-text search, and real-time system resource monitoring.

```
┌───────────────────────────────────────────────────────┐
│                     run.sh                            │
│          (unified entry point / main menu)            │
└──────────┬──────────────────────────┬─────────────────┘
           │                          │
   ┌───────▼────────┐       ┌─────────▼───────────────┐
   │   modules/     │       │     network_lab/        │
   │ (security ops) │       │ (education & analysis)  │
   └───────┬────────┘       └─────────┬───────────────┘
           │                          │
   ┌───────▼──────────────────────────▼───────────┐
   │             logs/  &  output/                │
   │       (structured, timestamped output)       │
   └─────────────────────┬────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │     dashboard/      │
              │   (live web UI)     │
              └─────────────────────┘
```

---

## Project Structure

```
networking_cybersecurity/
├── run.sh                        # Main entry point
├── install.sh                    # Dependency installer (multi-distro)
├── config/
│   └── settings.conf             # Global configuration
├── lib/
│   ├── colors.sh                 # Terminal colour definitions
│   ├── functions.sh              # Shared utility functions
│   ├── init.sh                   # Library bootstrap
│   └── logging.sh                # Logging helpers
├── modules/
│   ├── run_modules.sh            # Module menu & execution handler
│   ├── analysis/
│   │   ├── cloud_exposure_audit.sh
│   │   ├── detect_suspicious_net_linux.sh
│   │   └── log_analysis.sh
│   ├── forensics/
│   │   ├── forensic_collect.sh
│   │   └── system_info.sh
│   ├── reconnaissance/
│   │   └── web_recon.sh
│   ├── system_security/
│   │   └── secure_system.sh
│   └── threat_detection/
│       ├── data_exfil_detect.sh
│       ├── lateral_movement_detect.sh
│       └── malware_analysis.sh
├── network_lab/
│   ├── network_lab.sh            # Network Lab controller
│   ├── diagnostics/
│   │   ├── ip_addressing.sh
│   │   └── packet_analysis.sh
│   ├── networking/
│   │   ├── core_protocols.sh
│   │   ├── network_hardening.sh
│   │   ├── networking_basics.sh
│   │   ├── network_master.sh
│   │   ├── network_tools.sh
│   │   └── switching_routing.sh
│   ├── security/
│   │   ├── firewall_ids.sh
│   │   ├── security_fundamentals.sh
│   │   ├── threat_intelligence.sh
│   │   └── wireless_security.sh
│   └── output/
├── dashboard/
│   ├── start_dashboard.sh
│   ├── server.py                 # Python HTTP API server
│   ├── index.html                # Dashboard frontend
│   ├── app.js                    # Dashboard JS logic
│   └── style.css                 # Dashboard styles
├── logs/                         # Auto-generated timestamped logs
└── output/                       # Script output artifacts
```

---

## Features

### Security Modules

| Module | Description |
|---|---|
| 🔍 **Suspicious Network Detection** | Scans active connections for anomalous ports, foreign IPs, and unexpected listeners |
| 🔒 **System Hardening** | Applies firewall rules, disables unused services, locks down SSH, enforces password policies |
| 💻 **System Inventory** | Collects OS version, hardware, users, running services, open ports, and disk info |
| 🕵️ **Forensic Collection** | Captures volatile data — processes, connections, ARP cache, login history, cron jobs |
| 🌐 **Web Recon** | Passive and active reconnaissance including DNS, headers, and directory enumeration |
| 🦠 **Malware Analysis** | Static and dynamic analysis of suspicious files and processes |
| 🔀 **Lateral Movement Detection** | Analyses authentication logs for lateral movement indicators |
| 📋 **Log Analysis** | Parses system logs for threat indicators and anomalies |
| ☁️ **Cloud Exposure Audit** | Probes cloud metadata services for misconfigurations and exposure |
| 📤 **Data Exfiltration Detection** | Scans for data exfiltration patterns in network traffic and logs |

### Network Lab

| Tool | Description |
|---|---|
| 🌐 **Network Tools** | Interfaces, ping, traceroute, DNS lookup, port scanning |
| 📡 **Core Protocols** | Analyse TCP/UDP, HTTP, DNS, ICMP in real-time |
| 🔢 **IP Addressing** | Subnetting, CIDR breakdown, NAT, ARP |
| 📦 **Packet Analysis** | Headers, Wireshark filters, PCAP |
| 🗺️ **Network Master** | Comprehensive suite — discovery, scanning, bandwidth, latency |
| 📖 **Networking Basics** | OSI model, TCP/IP, switching guided diagnostics |
| 🔀 **Switching & Routing** | VLANs, MAC tables, RIP/OSPF/BGP |
| 🔐 **Security Fundamentals** | RSA/ECC key gen, AES encryption, SHA hashing, digital signatures |
| 📶 **Wireless Security** | WiFi standards, WPA3, attack vectors |
| 🧱 **Firewall & IDS/IPS** | iptables, nftables, Snort configuration |
| 🛡️ **Network Hardening** | SSH hardening, VPN, Zero Trust |
| 🧠 **Threat Intelligence** | OSINT, CVE lookup, MITRE ATT&CK |

### Dashboard

| Feature | Description |
|---|---|
| 📊 **Live Stats** | Total runs, success/warning/fail counts with animated counters |
| 📈 **Metrics** | Success rate ring, average duration, category breakdown chart |
| 🖥️ **System Resources** | Real-time CPU, Memory, Disk, Network usage — updates every 5 seconds |
| ⚠️ **Alerts** | Configurable warn/critical thresholds with optional email notifications |
| 📁 **Log Viewer** | In-browser log viewer with live tail (3-second polling) |
| 🔎 **Full-Text Search** | Search across all log files with match highlighting |
| 📤 **Export** | Download a full plain-text report of all stats, history, and files |

---

## Quick Start

### 1. Install dependencies

```bash
sudo ./install.sh
```

### 2. Run the interactive menu

```bash
sudo ./run.sh
```

### 3. Launch the dashboard

```bash
cd dashboard
python3 server.py
# Open http://localhost:8000
```

> **Optional:** Install `psutil` for live system resource monitoring:
> ```bash
> pip install psutil --break-system-packages
> ```

---

## Security Modules Reference

All modules are invoked through `run.sh → Security Modules` or directly. Each execution produces a timestamped log in `logs/` and any output artifacts in `output/`.

### `detect_suspicious_net_linux.sh`
Analyses active network connections using `ss`, `netstat`, and `/proc/net`. Flags:
- Connections to unusual or known-malicious ports
- Processes with unexpected listening sockets
- Foreign IP connections outside a whitelist

**Timeout:** 800s

### `secure_system.sh`
Applies a layered hardening checklist:
- Configures `ufw` / `iptables` firewall rules
- Hardens `/etc/ssh/sshd_config` (disables root login, enforces key auth)
- Disables unnecessary services via `systemctl`
- Sets password aging policies via `chage` / `pam`

**Timeout:** 200s

### `system_info.sh`
Generates a structured system inventory including:
- OS, kernel, hostname, uptime
- CPU, memory, disk layout
- Running services and open ports
- Local user accounts and sudo privileges

**Timeout:** 200s

### `forensic_collect.sh`
Captures volatile system state for incident response:
- Running processes (`ps`, `/proc`)
- Active network connections
- ARP cache and routing table
- Cron jobs (all users)
- Recent login history and auth log tail
- Loaded kernel modules

Output is saved as a structured report in `output/`.

**Timeout:** 400s

### `web_recon.sh`
Performs web target reconnaissance (prompts for target domain/URL):
- DNS record enumeration (A, MX, TXT, NS)
- HTTP header analysis
- Basic directory/path enumeration
- Robots.txt and sitemap discovery

**Timeout:** 200s

### `malware_analysis.sh`
Performs static and dynamic analysis of suspicious files and running processes.

**Timeout:** 600s

### `lateral_movement_detect.sh`
Analyses authentication logs for signs of lateral movement — unusual login chains, privilege escalation patterns, and credential abuse.

**Timeout:** 300s

### `log_analysis.sh`
Parses system logs for threat indicators: failed auth attempts, sudo abuse, unusual cron activity, and more.

**Timeout:** 300s

### `cloud_exposure_audit.sh`
Probes cloud metadata services (AWS, GCP, Azure) for misconfigurations and unintended exposure.

**Timeout:** 200s

### `data_exfil_detect.sh`
Scans for data exfiltration patterns in active network connections and log history.

**Timeout:** 300s

---

## Network Lab Reference

Accessible via `run.sh → Network Lab`. All tools are interactive and run locally — no data leaves the machine.

### Diagnostics & Live Analysis

- **Network Tools** — Ping sweep, traceroute, DNS lookup, Whois, port scan via `nmap`
- **Core Protocols** — Live TCP/UDP, HTTP, DNS, ICMP analysis
- **IP Addressing** — Subnet calculator, CIDR breakdown, NAT/ARP inspection
- **Packet Analysis** — Header dissection, Wireshark filter builder, PCAP review

### Education & Reference

- **Network Master** — All networking topics in one comprehensive module
- **Networking Basics** — OSI model walkthroughs, TCP/IP stack, switching concepts
- **Switching & Routing** — VLAN info, routing table analysis, RIP/OSPF/BGP reference
- **Security Fundamentals** — Hands-on cryptography demos, all run locally:

```
┌─────────────────────────────────────┐
│  Security Fundamentals              │
├─────────────────────────────────────┤
│  1. RSA key generation & encrypt    │
│  2. ECC key pair generation         │
│  3. AES-256 encryption/decryption   │
│  4. SHA-256 / SHA-512 hashing       │
│  5. Digital signature (sign/verify) │
│  6. File integrity check            │
└─────────────────────────────────────┘
```

### Advanced Security

- **Wireless Security** — WiFi standards, WPA2/WPA3, common attack vectors
- **Firewall & IDS/IPS** — iptables/nftables rule building, Snort rule reference
- **Network Hardening** — SSH lockdown, VPN setup, Zero Trust principles
- **Threat Intelligence** — OSINT techniques, CVE lookup, MITRE ATT&CK framework

---

## Dashboard

The dashboard is a self-contained Python HTTP server + vanilla JS frontend. **No npm, no build step required.**

### Starting

```bash
# Via run.sh menu (option 3)
sudo ./run.sh

# Or directly
cd dashboard && python3 server.py

# Custom port
DASHBOARD_PORT=9090 python3 server.py
```

Then open **http://localhost:8000** in your browser.

### Email Notifications (SMTP)

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=you@gmail.com
export SMTP_PASS=your_app_password

python3 server.py
```

Use the **⚠ Alerts** button in the dashboard to set CPU/Memory/Disk thresholds and enable automatic email alerts.

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/dashboard-data` | GET | Full dashboard payload (logs, outputs, history, stats) |
| `/api/metrics` | GET | Success rate, avg duration, category breakdown, disk usage |
| `/api/system-stats` | GET | Live CPU, Memory, Disk, Network (requires `psutil`) |
| `/api/file` | GET | Serve a log or output file (`?dir=logs&name=file.log`) |
| `/api/tail` | GET | Last N lines + mtime for live tailing |
| `/api/search` | GET | Full-text search across all log files |
| `/api/notify-email` | POST | Send an email notification (requires SMTP config) |
| `/api/alert-settings` | GET/POST | Read or update alert thresholds |

---

## Configuration

Edit `config/settings.conf` to adjust global defaults:

```bash
LOG_DIR="../logs"
OUTPUT_DIR="../output"
DASHBOARD_PORT=8000
MAX_LOG_LINES=10000
```

Shared library functions are in `lib/functions.sh` — source in any custom script:

```bash
source "$(dirname "$0")/../lib/functions.sh"
source "$(dirname "$0")/../lib/colors.sh"
```

---

## Output & Logs

### Log Files

Every script run creates a timestamped log at `logs/<script>_<YYYYMMDD_HHMMSS>.log`. Logs capture: start time, full command output, exit code, and completion timestamp. The dashboard parses these to determine run status (success / warning / error) and duration.

### Output Files

Scripts that produce artifacts write to `output/<category>_<timestamp>/`. Example for `security_fundamentals.sh`:

```
output/security_20260310_144125/
├── rsa_private.pem / rsa_public.pem
├── ecc_private.pem / ecc_public.pem
├── rsa_plain.txt / rsa_cipher.bin / rsa_decrypted.txt
├── aes_data.txt / aes_data.enc / aes_data.dec
├── doc_to_sign.txt / doc.sig
└── doc.sha256 / integrity_test.sha256
```

---

## Requirements

### System

| Requirement | Notes |
|---|---|
| Linux | Debian/Ubuntu, Arch, RHEL/Fedora, openSUSE — all supported |
| Bash 5.x | `bash --version` |
| Python 3.8+ | For dashboard server |
| Core tools | `ss`, `ip`, `dig`, `curl`, `openssl` |
| `nmap` | Optional — for port scanning features |
| `psutil` | Optional — `pip install psutil --break-system-packages` — for dashboard system stats |

### Permissions

Some modules require elevated privileges:

```bash
sudo ./run.sh

# Or run individual scripts directly
sudo ./modules/system_security/secure_system.sh
sudo ./modules/forensics/forensic_collect.sh
```

---

## Security Notes

- All scripts operate **locally** — no data is sent to external services unless you explicitly configure SMTP.
- The dashboard server binds to `localhost` by default. **Do not expose it publicly without authentication.**
- Forensic and hardening scripts should be reviewed before running in production environments.
- RSA/ECC keys and encrypted files generated by `security_fundamentals.sh` are for **demonstration purposes only**.
- The `run_all_modules` option (option 11) executes every module sequentially — allow significant time and review timeouts in `run_modules.sh`.

---

## Author

**Hitesh Mondal** — Developer & Cybersecurity Enthusiast

Focus areas: Networking • System Security • DevOps • Cloud Infrastructure