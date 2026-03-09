#!/bin/bash

# /network_lab/security/threat_intelligence.sh
# Topic: Threat Intelligence, OSINT, CVE/CVSS, Kill Chain, MITRE ATT&CK
# Covers: OSINT, threat feeds/IOCs, CVE/CVSS, Kill Chain, ATT&CK, threat hunting,
#         dark web concepts, incident response

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# OSINT
check_osint() {
    header "OSINT — Open Source Intelligence"

    section "OSINT Definition & Scope"
    cat << 'INFO'
  OSINT (Open Source Intelligence) — intelligence gathered from publicly
  available sources without hacking or illegal access.

  Source categories:
    Passive OSINT  — no direct interaction with target systems
      • WHOIS, DNS records, SSL cert transparency logs
      • Shodan, Censys, Fofa (internet scan databases)
      • Google dorking, Bing, DuckDuckGo
      • LinkedIn, Twitter/X, company websites
      • Job postings (reveal tech stack, vendors, gaps)
      • GitHub, GitLab, Pastebin (accidental credential leaks)
      • Wayback Machine (old versions of target websites)

    Active OSINT   — some interaction; may be detectable
      • DNS zone transfers (AXFR)
      • Email harvesting tools (theHarvester, hunter.io)
      • Subdomain enumeration (Sublist3r, Amass)
      • Port scanning (Shodan passive vs Nmap active)

  Key OSINT Tools:
    Maltego         — link analysis and entity mapping
    theHarvester    — email, subdomain, host enumeration
    Recon-ng        — modular web reconnaissance framework
    SpiderFoot      — automated OSINT for IPs, domains, emails
    Amass           — comprehensive subdomain enumeration
    Shodan / Censys — search engine for internet-connected devices
    FOCA            — metadata extraction from documents
    ExifTool        — file metadata (location, author, software)
INFO

    section "Live OSINT Queries"
    read -rp "$(echo -e "  ${PROMPT}Enter domain for OSINT demo [default: example.com]:${NC} ")" target_domain
    target_domain="${target_domain:-example.com}"
    is_valid_host "$target_domain" || { log_warning "Invalid domain"; target_domain="example.com"; }

    echo

    if cmd_exists dig; then
        echo -e "  ${LABEL}DNS records (A, MX, NS, TXT):${NC}"
        for rtype in A MX NS TXT; do
            local result
            result=$(dig +short "$rtype" "$target_domain" 2>/dev/null | head -3)
            [[ -n "$result" ]] && printf "  ${CYAN}%-4s${NC}  %s\n" "$rtype" "$result"
        done
    fi

    echo
    if cmd_exists whois; then
        echo -e "  ${LABEL}WHOIS summary:${NC}"
        whois "$target_domain" 2>/dev/null | \
            grep -iE "^(registrar|creation|updated|expiry|name server)" | \
            head -8 | sed 's/^/  /'
    fi

    echo
    if cmd_exists curl; then
        echo -e "  ${LABEL}Certificate Transparency (crt.sh) — subdomains:${NC}"
        echo -e "  ${MUTED}https://crt.sh/?q=%25.${target_domain}&output=json${NC}"
        local ct_count
        ct_count=$(curl -s --max-time 6 \
            "https://crt.sh/?q=%25.${target_domain}&output=json" 2>/dev/null | \
            grep -o '"common_name"' | wc -l)
        [[ "$ct_count" -gt 0 ]] \
            && echo -e "  ${INFO}Found ~${ct_count} certificate entries${NC}" \
            || echo -e "  ${MUTED}No response or no results${NC}"
    fi

    section "Google Dorking Reference"
    cat << 'DORKS'
  site:example.com                     All indexed pages
  site:example.com filetype:pdf        PDFs on domain
  site:example.com inurl:admin         Admin pages
  site:example.com intitle:"index of"  Open directory listings
  site:github.com "example.com" password   Leaked credentials
  "example.com" ext:log                Log files
  "example.com" ext:sql                Database dumps
  intitle:"Login" site:example.com     Login pages
  intext:"Powered by" site:example.com Technology fingerprinting
  cache:example.com                    Cached version
DORKS
}

# THREAT FEEDS & IOCs
check_threat_feeds() {
    header "Threat Feeds & IOCs"

    section "Indicators of Compromise (IOCs)"
    cat << 'INFO'
  IOCs are artifacts that indicate a system has been compromised.

  Types:
    Hash-based   — MD5/SHA1/SHA256 hashes of known malware files
    IP-based     — known C2 servers, scanning IPs, TOR exit nodes
    Domain-based — malicious domains, DGA patterns, typosquatting
    URL-based    — specific malicious URLs / phishing pages
    Email-based  — malicious sender addresses, subject patterns
    Behavioural  — lateral movement patterns, persistence keys, registry changes

  IOC Formats:
    STIX 2.1  — Structured Threat Information eXpression (JSON-based)
    TAXII 2.1 — transport protocol for sharing STIX
    OpenIOC   — Mandiant's XML-based IOC format
    MISP      — Malware Information Sharing Platform (open source)
    YARA      — rule-based malware pattern matching

  Threat Intelligence Platforms (TIPs):
    Open source: MISP, OpenCTI, TheHive + Cortex
    Commercial:  Recorded Future, ThreatConnect, Anomali ThreatStream
INFO

    section "Open Threat Feeds"
    cat << 'FEEDS'
  IP Reputation:
    Spamhaus DROP/EDROP    — https://www.spamhaus.org/drop/
    EmergingThreats        — https://rules.emergingthreats.net/
    AbuseIPDB              — https://www.abuseipdb.com/
    Feodo Tracker (C2)     — https://feodotracker.abuse.ch/

  Domain / URL:
    URLhaus                — https://urlhaus.abuse.ch/
    PhishTank              — https://phishtank.org/
    Malware Domain List    — http://www.malwaredomainlist.com/

  File Hashes:
    VirusTotal             — https://www.virustotal.com/
    MalwareBazaar          — https://bazaar.abuse.ch/
    Hybrid Analysis        — https://hybrid-analysis.com/

  Aggregated:
    CIRCL MISP Feeds       — https://www.misp-project.org/feeds/
    AlienVault OTX         — https://otx.alienvault.com/
FEEDS

    section "Local IOC Check"
    if cmd_exists curl; then
        read -rp "$(echo -e "  ${PROMPT}Enter IP to check against AbuseIPDB concept [default: skip]:${NC} ")" check_ip
        if [[ -n "$check_ip" ]] && is_valid_ip "$check_ip"; then
            echo -e "  ${MUTED}Real check: https://api.abuseipdb.com/api/v2/check?ipAddress=${check_ip}${NC}"
            echo -e "  ${MUTED}(Requires free API key — register at abuseipdb.com)${NC}"
        fi
    fi
}

# CVE & CVSS
check_cve_cvss() {
    header "CVE & CVSS — Vulnerability Scoring"

    section "CVE (Common Vulnerabilities and Exposures)"
    cat << 'INFO'
  CVE provides a standardised identifier for publicly known vulnerabilities.
  Format: CVE-YYYY-NNNNN (e.g. CVE-2021-44228 = Log4Shell)
  Maintained by MITRE; entries published in NVD (National Vulnerability Database).

  Lifecycle:
    Discovered → CNA (CVE Numbering Authority) assigns ID
    → Reported to vendor → Vendor patches
    → CVE published in NVD with CVSS score
    → Patch / mitigation applied by organisations

  Key databases:
    NVD:     https://nvd.nist.gov/
    MITRE:   https://cve.mitre.org/
    Exploit-DB: https://www.exploit-db.com/
    Packet Storm: https://packetstormsecurity.com/
INFO

    section "CVSS v3.1 Scoring System"
    cat << 'INFO'
  CVSS (Common Vulnerability Scoring System) v3.1 — NIST standard.
  Score range: 0.0 – 10.0

  Severity ranges:
    None     0.0
    Low      0.1 – 3.9
    Medium   4.0 – 6.9
    High     7.0 – 8.9
    Critical 9.0 – 10.0

  Base Score Metrics:
    Attack Vector (AV):      Network(N) / Adjacent(A) / Local(L) / Physical(P)
    Attack Complexity (AC):  Low(L) / High(H)
    Privileges Required (PR): None(N) / Low(L) / High(H)
    User Interaction (UI):   None(N) / Required(R)
    Scope (S):               Unchanged(U) / Changed(C)
    Confidentiality (C):     None(N) / Low(L) / High(H)
    Integrity (I):           None(N) / Low(L) / High(H)
    Availability (A):        None(N) / Low(L) / High(H)

  Example — Log4Shell (CVE-2021-44228):
    AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H = 10.0 CRITICAL

  Temporal Metrics (modify base score):
    Exploit Code Maturity, Remediation Level, Report Confidence
INFO

    section "Recent Critical CVEs (Reference)"
    cat << 'TABLE'
  CVE ID              Score  Name / Description
  ──────────────────  ─────  ─────────────────────────────────────────────────
  CVE-2021-44228       10.0  Log4Shell — Log4j2 RCE via JNDI lookup
  CVE-2021-45046       9.0   Log4j2 RCE bypass of initial patch
  CVE-2022-26134       9.8   Atlassian Confluence OGNL injection RCE
  CVE-2023-0669        9.8   GoAnywhere MFT pre-auth RCE
  CVE-2023-34362       9.8   MOVEit Transfer SQL injection RCE
  CVE-2024-21762       9.6   Fortinet FortiOS SSL VPN RCE
  CVE-2021-34527       8.8   PrintNightmare — Windows Print Spooler RCE
  CVE-2022-30190       7.8   Follina — MSDT RCE via Office documents
TABLE

    section "Vulnerability Check — Installed Packages"
    if cmd_exists apt; then
        echo -e "${INFO}Packages with available security updates:${NC}"
        apt list --upgradable 2>/dev/null | grep -i "security\|Security" | head -10 | sed 's/^/  /' \
            || echo -e "  ${MUTED}Run: sudo apt update && apt list --upgradable 2>/dev/null | grep security${NC}"
    fi

    if cmd_exists rpm; then
        echo -e "${INFO}RPM security advisories:${NC}"
        yum updateinfo list security 2>/dev/null | head -10 | sed 's/^/  /' \
            || dnf updateinfo list security 2>/dev/null | head -10 | sed 's/^/  /'
    fi
}

# CYBER KILL CHAIN
check_kill_chain() {
    header "Cyber Kill Chain — Attack Lifecycle Model"

    section "Lockheed Martin Kill Chain (2011)"
    cat << 'INFO'
  The Kill Chain models the stages an attacker must complete for a successful intrusion.
  Breaking any link in the chain stops the attack.

  Phase 1 — RECONNAISSANCE
    Goal: gather information about the target.
    Passive: OSINT, WHOIS, Shodan, LinkedIn, job postings.
    Active: port scanning, service fingerprinting, phishing pretexts.
    Defence: limit public information, monitor for scanning (IDS), use deception.

  Phase 2 — WEAPONISATION
    Goal: create or acquire a weapon (payload + delivery mechanism).
    Examples: exploit kit, malicious Office doc, trojanised installer.
    Defence: threat intel (detect weaponisation infrastructure), sandbox analysis.

  Phase 3 — DELIVERY
    Goal: transmit the weapon to the target.
    Vectors: phishing email, watering hole, malicious USB, web exploit, supply chain.
    Defence: email gateway, web proxy/DLP, endpoint security, user training.

  Phase 4 — EXPLOITATION
    Goal: execute the payload to exploit a vulnerability.
    Examples: browser exploit, document macro, memory corruption.
    Defence: patch management, DEP/ASLR, sandboxing, exploit prevention (EDR).

  Phase 5 — INSTALLATION
    Goal: establish persistence (survive reboot).
    Techniques: scheduled tasks, registry run keys, service installation, rootkits.
    Defence: application whitelisting, file integrity monitoring (AIDE), EDR alerts.

  Phase 6 — COMMAND & CONTROL (C2)
    Goal: establish communication channel back to attacker.
    Channels: HTTPS to actor server, DNS tunnelling, social media, TOR.
    Defence: DNS sinkholes, proxy inspection, egress filtering, anomaly detection.

  Phase 7 — ACTIONS ON OBJECTIVES
    Goal: achieve the mission (exfil data, ransomware, destruction).
    Examples: data theft, lateral movement, ransomware deployment, sabotage.
    Defence: DLP, least privilege, network segmentation, backup verification.
INFO

    section "Kill Chain Detection Opportunities"
    echo
    printf "  ${BOLD}%-14s %-26s %-26s${NC}\n" "Phase" "Attacker Activity" "Detection Point"
    printf "  ${DARK_GRAY}%-14s %-26s %-26s${NC}\n" \
        "─────────────" "─────────────────────────" "─────────────────────────"
    while IFS='|' read -r phase activity detect; do
        printf "  ${CYAN}%-14s${NC} ${MUTED}%-26s${NC} ${GREEN}%-26s${NC}\n" \
            "$phase" "$activity" "$detect"
    done << 'TABLE'
Recon|Shodan/scanner hits|Honeypot + web logs
Weaponise|Payload creation|Threat intel feeds
Delivery|Phishing email|Email gateway + sandbox
Exploit|Shellcode/macro run|EDR + exploit guard
Install|Persistence creation|AIDE + auditd rules
C2|Outbound beacon|DNS/proxy anomaly alerts
Objectives|Data exfil|DLP + SIEM correlation
TABLE
}

# MITRE ATT&CK
check_mitre_attck() {
    header "MITRE ATT&CK Framework"

    section "Framework Overview"
    cat << 'INFO'
  ATT&CK = Adversarial Tactics, Techniques and Common Knowledge
  Published by MITRE; updated quarterly. URL: https://attack.mitre.org/

  Three matrices:
    Enterprise  — Windows, Linux, macOS, Cloud (AWS/Azure/GCP/M365/SaaS), Containers
    Mobile      — Android, iOS
    ICS         — Industrial Control Systems

  Structure:
    Tactic  — The "why" / adversarial goal (e.g., Persistence)
    Technique — The "how" (e.g., T1053 Scheduled Task/Job)
    Sub-technique — More specific variant (e.g., T1053.005 = Scheduled Task)
    Procedure — Real-world usage by a specific threat actor

  Enterprise Tactics (14 + PRE-ATT&CK):
    TA0043 Reconnaissance        TA0042 Resource Development
    TA0001 Initial Access        TA0002 Execution
    TA0003 Persistence           TA0004 Privilege Escalation
    TA0005 Defence Evasion       TA0006 Credential Access
    TA0007 Discovery             TA0008 Lateral Movement
    TA0009 Collection            TA0011 Command and Control
    TA0010 Exfiltration          TA0040 Impact
INFO

    section "High-Value Techniques to Detect"
    echo
    printf "  ${BOLD}%-14s %-40s %s${NC}\n" "ID" "Name" "Detection"
    printf "  ${DARK_GRAY}%-14s %-40s %s${NC}\n" \
        "─────────────" "──────────────────────────────────────" "──────────────────────────"
    while IFS='|' read -r tid name detect; do
        printf "  ${CYAN}%-14s${NC} ${MUTED}%-40s${NC} %s\n" "$tid" "$name" "$detect"
    done << 'TABLE'
T1078|Valid Accounts|Auth logs + MFA enforcement
T1053.005|Scheduled Task/Job|auditd + task log monitoring
T1059.004|Unix Shell|Shell history + process tree
T1021.004|SSH Lateral Movement|SSH auth logs + bastion host
T1003.008|/etc/passwd & /etc/shadow|File access auditing
T1070.006|Timestomping|AIDE integrity + inode timestamps
T1048|Exfil over Alt Protocol|DNS/ICMP anomaly detection
T1071.001|Web C2 Protocol|TLS inspection + proxy logs
T1136.001|Local Account Creation|PAM logs + /etc/passwd watch
T1486|Data Encrypted for Impact|Backup monitoring + entropy
TABLE

    section "ATT&CK Navigator Usage"
    cat << 'INFO'
  ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)
  allows you to:
    - Highlight techniques used by a specific threat group
    - Map your defensive coverage
    - Compare actor profiles
    - Generate heat-maps for red/blue team planning

  Example: APT29 (Cozy Bear) commonly uses:
    T1566.002 Spearphishing Link
    T1195.002 Compromise Software Supply Chain
    T1071.001 Web Protocols (C2)
    T1027     Obfuscated Files
    T1078     Valid Accounts
INFO
}

# THREAT HUNTING
check_threat_hunting() {
    header "Threat Hunting — Proactive Threat Detection"

    section "Threat Hunting Methodology"
    cat << 'INFO'
  Threat hunting is hypothesis-driven, proactive security analysis.
  Assumes breach has occurred; looks for attackers hiding in the noise.

  Process:
    1. Hypothesis   — "APT29 may have accessed our environment via supply chain"
    2. Data         — collect relevant logs, EDR telemetry, network flows
    3. Analysis     — query, correlate, visualise; look for anomalies
    4. Findings     — document confirmed / unconfirmed / false positive
    5. Inform       — update detection rules, patch gaps, report to leadership

  Data Sources:
    Endpoint  — process creation, network connections, file writes, registry
    Network   — DNS, proxy, NetFlow, full packet capture
    Identity  — auth events, Kerberos tickets, LDAP queries
    Cloud     — CloudTrail, Azure Monitor, GCP audit logs

  Hunting Hypotheses Examples:
    "Are any hosts beaconing at regular intervals to non-corporate IPs?"
    "Does any account log in from two continents within 1 hour?"
    "Is any service account running interactive shells?"
    "Are any processes writing to startup locations?"
INFO

    section "Linux Threat Hunting Checks"
    echo

    echo -e "  ${LABEL}Unusual SUID binaries:${NC}"
    find /tmp /var/tmp /dev/shm -type f -perm -4000 2>/dev/null | \
        while read -r f; do echo -e "  ${FAILURE}${f}${NC}"; done \
        || echo -e "  ${MUTED}None in suspicious locations${NC}"

    echo
    echo -e "  ${LABEL}Writable scripts in cron:${NC}"
    find /etc/cron* /var/spool/cron -type f -perm -002 2>/dev/null | \
        while read -r f; do echo -e "  ${FAILURE}${f}${NC}"; done \
        || echo -e "  ${MUTED}None found${NC}"

    echo
    echo -e "  ${LABEL}Listening services not in expected list:${NC}"
    local expected_ports=(22 80 443 53 68 123)
    ss -tlnp 2>/dev/null | tail -n +2 | while read -r _ _ _ local _; do
        local port="${local##*:}"
        local known=false
        for ep in "${expected_ports[@]}"; do
            [[ "$port" == "$ep" ]] && known=true && break
        done
        $known || echo -e "  ${WARNING}Unexpected listener: ${local}${NC}"
    done

    echo
    echo -e "  ${LABEL}Recently modified files in /etc (last 24h):${NC}"
    find /etc -maxdepth 2 -newer /etc/hosts -type f 2>/dev/null | head -10 | sed 's/^/  /'

    echo
    echo -e "  ${LABEL}Processes with deleted executables (potential in-memory malware):${NC}"
    ls -la /proc/*/exe 2>/dev/null | grep deleted | head -10 | sed 's/^/  /' \
        || echo -e "  ${MUTED}None detected${NC}"

    echo
    echo -e "  ${LABEL}Outbound connections to non-standard ports:${NC}"
    ss -tn state established 2>/dev/null | awk 'NR>1{print $5}' | \
        awk -F: '{print $NF}' | sort -n | uniq | \
        while read -r port; do
            case "$port" in
                80|443|22|53|25|587|993|995|123|67|68) ;;
                *) echo -e "  ${WARNING}Port ${port}${NC}" ;;
            esac
        done | head -10
}

# DARK WEB (conceptual)
check_dark_web() {
    header "Dark Web — Intelligence & Monitoring"

    section "Dark Web Overview"
    cat << 'INFO'
  The dark web is a part of the internet only accessible via overlay networks
  (TOR, I2P, Freenet) that provide anonymity via onion routing.

  Layers:
    Surface web  — indexed by search engines (~5% of content)
    Deep web     — not indexed (databases, paywalled, auth-required)
    Dark web     — intentionally hidden, requires special software

  TOR (The Onion Router):
    Traffic encrypted in 3 layers, routed through 3 volunteer relays.
    Each relay decrypts one layer and forwards to next.
    Exit node decrypts final layer and connects to destination.
    .onion addresses — SHA-256 derived from public key (v3 onion services).

  Security relevance:
    Threat intel — monitor paste sites, forums, marketplaces for:
      • Leaked credentials / PII from your organisation
      • Source code / internal data exfiltrated
      • Zero-day exploits / tools targeting your sector
      • Mentions of your brand, executives, infrastructure

  Monitoring services:
    Commercial:  Recorded Future, Flashpoint, DarkOwl, Kela
    Open tools:  OnionSearch, Ahmia.fi search engine
    Self-hosted: Hunchly, custom TOR crawler (legal & ethical use only)

  Legal note: accessing dark web is legal; purchasing illegal goods is not.
INFO
}

# INCIDENT RESPONSE
check_incident_response() {
    header "Incident Response — IR Lifecycle"

    section "IR Phases (NIST SP 800-61 Rev 2)"
    cat << 'INFO'
  Phase 1 — PREPARATION
    Build capabilities before incidents happen.
    • IR policy, procedures, playbooks
    • SIEM, EDR, logging infrastructure
    • IR team roles (Incident Commander, analyst, comms, legal)
    • Tabletop exercises, red team exercises
    • Evidence collection tools (memory dump, disk imaging)

  Phase 2 — DETECTION & ANALYSIS
    Identify that an incident is occurring.
    • SIEM alerts, EDR detections, threat intel matches
    • Triage: severity classification (P1/P2/P3/P4)
    • Timeline reconstruction from logs
    • Scope: what systems affected? lateral movement?

  Phase 3 — CONTAINMENT, ERADICATION, RECOVERY
    Containment:   isolate affected systems (network isolation, disable accounts)
    Eradication:   remove malware, close vulnerabilities, reset credentials
    Recovery:      restore from clean backups, validate integrity, re-enable

  Phase 4 — POST-INCIDENT ACTIVITY
    • Root cause analysis (RCA)
    • Lessons learned documentation
    • Update detection rules, playbooks, hardening baselines
    • Regulatory reporting (GDPR 72hr, HIPAA, SEC 4-day)
    • Threat intel sharing (ISACs)
INFO

    section "First Response Checklist"
    local steps=(
        "Declare incident — assign incident commander"
        "Preserve evidence — DO NOT reboot affected systems"
        "Capture memory (RAM) before shutdown: avml / LiME / winpmem"
        "Disk image: sudo dd if=/dev/sda | gzip > image.gz (SHA-256 hash before/after)"
        "Isolate from network (VLAN, firewall rule, unplug) — NOT shutdown"
        "Collect live artifacts: running processes, connections, logins, cron"
        "Preserve logs: /var/log/auth.log, syslog, audit.log, application logs"
        "Check persistence: cron, systemd units, /etc/rc.local, .bashrc, SUID"
        "Review network: ss -antup, iptables -L, DNS cache, ARP table"
        "Change all credentials: service accounts, admin, API keys"
        "Notify: management, legal, security team, external counsel as needed"
        "Regulatory review: GDPR/HIPAA/PCI-DSS notification requirements"
    )
    echo
    for i in "${!steps[@]}"; do
        printf "  ${CYAN}%2d.${NC} ${MUTED}%s${NC}\n" "$(( i + 1 ))" "${steps[$i]}"
    done

    section "Live System State Capture"
    echo -e "  ${INFO}Capturing live state for IR...${NC}"
    echo
    local ts
    ts=$(date '+%Y%m%d_%H%M%S')
    local ir_file="${OUTPUT_DIR}/ir_snapshot_${ts}.txt"

    {
        echo "=== IR SNAPSHOT: $(date) ==="
        echo "=== HOSTNAME: $(hostname) ==="
        echo
        echo "--- Running Processes ---"
        ps auxf 2>/dev/null | head -30
        echo
        echo "--- Network Connections ---"
        ss -antup 2>/dev/null
        echo
        echo "--- Listening Services ---"
        ss -tlnp 2>/dev/null
        echo
        echo "--- Recent Logins ---"
        last -20 2>/dev/null
        echo
        echo "--- Cron Jobs ---"
        crontab -l 2>/dev/null
        find /etc/cron* -type f 2>/dev/null | xargs cat 2>/dev/null
        echo
        echo "--- Systemd Units (enabled) ---"
        systemctl list-units --type=service --state=running 2>/dev/null | head -20
        echo
        echo "--- ARP Table ---"
        ip neigh show 2>/dev/null
    } > "$ir_file" 2>/dev/null

    if [[ -f "$ir_file" ]]; then
        local sz
        sz=$(du -sh "$ir_file" | cut -f1)
        status_line ok "IR snapshot saved: ${ir_file} (${sz})"
    fi
}

main() {
    check_osint
    check_threat_feeds
    check_cve_cvss
    check_kill_chain
    check_mitre_attck
    check_threat_hunting
    check_dark_web
    check_incident_response
}

main