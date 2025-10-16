# 🛡️ Networking & Cybersecurity Automation Toolkit

A cross-platform collection of **Linux (`.sh`)** and **Windows (`.bat`)** scripts for **Networking, Cybersecurity, System Hardening, and Digital Forensics**.

This toolkit automates many repetitive tasks used in **penetration testing, security auditing, system diagnostics, and forensic evidence collection**, while ensuring outputs and sensitive data are never committed to version control.

---

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

## ⚙️ Usage Examples

> ⚠️ Run these scripts in **testing or controlled environments only.**
> Many commands require **root/admin privileges** and may modify system settings.

### 🧩 System Profiling
```bash
bash system_info.sh
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