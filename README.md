# 🛡️ Networking & Cybersecurity Automation Toolkit

A cross-platform collection of **Linux (`.sh`)** and **Windows (`.bat`)** scripts for **Networking, Cybersecurity, System Hardening, and Digital Forensics**.

This toolkit automates many repetitive tasks used in **penetration testing, security auditing, system diagnostics, and forensic evidence collection**, while ensuring outputs and sensitive data are never committed to version control.

---

## ⚠️ Caution: System Hardening Scripts

Read this carefully before running any script from this repository.

These shell scripts make system-level security and configuration changes. They are intended for testing, controlled environments, or system hardening under expert supervision — not for casual or blind execution.

Running these scripts may:

Modify kernel and network parameters (sysctl)

Change critical file permissions and ownership

Disable or remove system services (e.g., NFS, RPC, SMB, SNMP, CUPS)

Alter or reset firewall and iptables/ufw/firewalld rules

Lock user accounts (including root)

Remove or change SUID/SGID bits from binaries

Restrict ICMP (ping) responses and other network functions

Permanent loss of remote (SSH) access due to strict firewall rules

System instability or boot/login issues if critical binaries lose permissions

Service downtime if essential daemons are stopped or disabled

🛠️ Run this script to revert changes to normal ⚙️
```bash
cd scripts
revert_security.sh
```
✅
## 🚀 Features

| Category | Description | Platforms |
|-----------|--------------|------------|
| 🧠 **System Information** | Gather detailed system, hardware, and network metadata. | Linux / Windows |
| 🌐 **Web Reconnaissance** | Perform domain, DNS, and service discovery using built-in tools and external APIs. | Linux / Windows |
| 🕵️ **Suspicious Network Detection** | Detect abnormal connections, beaconing, or hidden listeners. | Linux / Windows |
| 🧰 **Forensic Collection** | Collect critical logs, running processes, and system artifacts for incident response. | Linux / Windows |
| 🔒 **System Hardening** | Apply security configurations and firewall rules to reduce exposure. | Linux / Windows |
| 🧩 **Specialized Search Engines** | Integrate or store references to OSINT tools (Shodan, Censys, VirusTotal, etc.). | Cross-platform |

---

---

## 🧰 Requirements

### 🔹 Linux
- Bash (v4 or later)
- Common networking utilities:
  - `curl`, `dig`, `whois`, `nmap`, `ss`, `netstat`, `lsof`, `tcpdump`
- Root privileges (for forensic and hardening scripts)

### 🔹 Windows
- PowerShell or Command Prompt
- Tools used:
  - `netstat`, `tasklist`, `wevtutil`, `systeminfo`, `wmic`
- Administrator privileges recommended

---

> Many commands require **sudo/root/admin privileges** and may modify system settings.

### 🧩 Run
For Linux
```bash
run.sh
```
For Windows
```bash
run.bat
```

## 🧹 Output Management

All generated outputs, logs, and forensic data are automatically ignored by Git via the .gitignore file.

Examples of ignored files:

nmap_*.txt, ping.txt, forensic_output/, malware_scan_*.txt, *.log, etc.

Private keys, certificates, dumps, and binary artifacts.

See the .gitignore
 file for the full list.

## ⚠️ Security & Legal Disclaimer

This project is intended solely for educational, research, and defensive cybersecurity purposes.

Do not run scans or recon commands against systems you don’t own or have explicit permission to test.

Always use a sandbox or isolated lab for testing hardening and forensic scripts.

The author is not responsible for misuse or damage caused by improper execution of these scripts.

## 🧱 Future Improvements

Add unified orchestration script in Python for cross-platform automation.

Add PowerShell versions of .bat scripts for enhanced Windows compatibility.

Add logging and summary reporting in both JSON and text formats.

Integrate optional cloud-based intelligence checks (VirusTotal, AbuseIPDB, etc.).

Provide pre-built Docker image for quick testing.

## 🧾 License

This project is released under the MIT License.
You are free to use, modify, and distribute it — provided you include proper attribution.

## 👨‍💻 Author

Hitesh Mondal
🔹 Developer & Cybersecurity Enthusiast
🔹 Focus areas: Networking • System Security • DevOps • Cloud Infrastructure