#!/bin/bash

# /tools/threat_intelligence.sh
# Topic: Threat Intelligence, OSINT & Attack Frameworks
# Covers: OSINT techniques, threat feeds, CVE/CVSS, Cyber Kill Chain,
#         MITRE ATT&CK, IOCs, dark web concepts, threat hunting

# Bootstrap
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$_SELF_DIR")"}"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

: "${LOG_DIR:="${PROJECT_ROOT}/logs"}"
: "${OUTPUT_DIR:="${PROJECT_ROOT}/output"}"
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

#  OSINT
check_osint() {
    header "OSINT — Open Source Intelligence"

    section "What is OSINT?"
    cat << 'INFO'
  OSINT = collecting intelligence from publicly available sources.
  Used by: attackers (reconnaissance), defenders (threat intel),
           journalists, investigators, penetration testers.

  OSINT sources:
    Passive DNS:    Historical DNS records (SecurityTrails, PassiveDNS)
    WHOIS:          Domain/IP registration data (ARIN, RIPE, APNIC)
    Shodan:         Internet-connected device search engine
    Censys:         TLS certificate + banner scanning (IPv4/IPv6)
    Fofa:           Chinese OSINT scanner (IoT, industrial systems)
    Greynoise:      Differentiates internet noise from targeted attacks
    VirusTotal:     Multi-AV + URL/file reputation (hash lookup)
    Hunter.io:      Corporate email address discovery
    LinkedIn:       Employee enumeration → spear phishing targets
    Github:         Code repositories → leaked credentials, API keys
    Google Dorks:   Operator-based search for exposed files/pages
    Certificate CT: Certificate Transparency logs (crt.sh) → subdomains
    Wayback Machine:Historical website content (web.archive.org)
    Pastebin:       Leaked credentials, source code, config files
INFO

    section "Google Dorking Examples"
    cat << 'INFO'
  Google operators for OSINT reconnaissance:

  site:example.com filetype:pdf     — all PDFs on a domain
  site:example.com ext:sql          — exposed SQL files
  site:example.com inurl:admin      — admin panels
  intitle:"index of" "backup"       — directory listings with backups
  intext:"password" filetype:txt    — plaintext files with "password"
  site:pastebin.com "example.com"   — pastes mentioning your domain
  "Powered by phpMyAdmin"           — exposed database interfaces
  inurl:".git" intitle:"Index of"   — exposed .git repos
  filetype:env "DB_PASSWORD"        — exposed .env files
  intitle:"Kibana" inurl:5601       — exposed Kibana dashboards
  inurl:"/wp-content/uploads/" ext:php — WordPress shell uploads

  Tools: Google Dork Automation (dork-cli), Pagodo (bulk dorking)
INFO

    section "Shodan — The Hacker's Search Engine"
    cat << 'INFO'
  Shodan indexes internet-facing devices by banner/service response.
  Search for: webcams, routers, SCADA, databases, printers, IoT.

  Useful Shodan filters:
    hostname:example.com          — find all hosts for a domain
    ip:203.0.113.0/24             — scan entire subnet
    port:22 country:US            — SSH servers in the US
    product:nginx version:1.14    — specific vulnerable versions
    org:"Amazon"                  — AWS-hosted systems
    ssl:"example.com"             — by TLS certificate CN
    http.title:"Admin Panel"      — by page title
    has_screenshot:true           — indexed screenshots (webcams, VNC)
    vuln:CVE-2021-44228           — Log4Shell vulnerable hosts

  API access:
    curl "https://api.shodan.io/shodan/host/8.8.8.8?key=YOUR_KEY"

  Free tier: limited searches per month. Membership: $49/mo.
INFO

    section "Certificate Transparency Logs"
    cat << 'INFO'
  Certificate Transparency (CT) — RFC 6962 (2013).
  Every publicly-trusted TLS certificate MUST be logged to a CT log.
  Enables: subdomain discovery, certificate monitoring, phishing detection.

  Query:
    curl "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value'
    curl "https://api.certspotter.com/v1/issuances?domain=example.com"

  Tools: Amass, Subfinder, MassDNS, BBOT (automated subdomain enum)

  Defensive use:
    Monitor your domain in CT logs → detect unauthorized certificates (MITM)
    Set up CAA DNS record: example.com CAA 0 issue "letsencrypt.org"
    (prevents other CAs from issuing for your domain)
INFO

    section "Live OSINT Lookups"

    read -rp "$(echo -e "  ${PROMPT}Enter a domain for OSINT lookup [default: example.com]:${NC} ")" osint_domain
    osint_domain="${osint_domain:-example.com}"
    is_valid_host "$osint_domain" || { log_warning "Invalid domain"; osint_domain="example.com"; }

    echo
    echo -e "${INFO}WHOIS data for ${osint_domain}:${NC}"
    if cmd_exists whois; then
        whois "$osint_domain" 2>/dev/null \
            | grep -iE "^(domain|registrar|creation|updated|expiry|status|name.server|admin|org|country)" \
            | head -20 | sed 's/^/  /'
    fi

    echo
    echo -e "${INFO}DNS enumeration (subdomains via brute-force wordlist):${NC}"
    local subdomains=("www" "mail" "ftp" "vpn" "api" "dev" "staging" "test" "admin" "portal" "smtp" "pop" "imap")
    local found_subs=0
    for sub in "${subdomains[@]}"; do
        local fqdn="${sub}.${osint_domain}"
        local result
        result=$(dig +short A "$fqdn" 2>/dev/null | head -1)
        if [[ -n "$result" ]]; then
            printf "  ${SUCCESS}%-30s${NC} → ${CYAN}%s${NC}\n" "$fqdn" "$result"
            found_subs=1
        fi
    done
    [[ $found_subs -eq 0 ]] && echo -e "  ${MUTED}No subdomains resolved from wordlist${NC}"

    echo
    echo -e "${INFO}Certificate Transparency (via crt.sh):${NC}"
    if cmd_exists curl; then
        local ct_result
        ct_result=$(curl -s --max-time 8 \
            "https://crt.sh/?q=%25.${osint_domain}&output=json" 2>/dev/null \
            | python3 -c "import sys,json; data=json.load(sys.stdin); \
              names=set(n for e in data for n in e.get('name_value','').split('\n')); \
              [print(n) for n in sorted(names)]" 2>/dev/null | head -20)
        if [[ -n "$ct_result" ]]; then
            echo "$ct_result" | sed 's/^/  /'
        else
            echo -e "  ${MUTED}CT lookup failed or no results${NC}"
        fi
    fi

    echo
    echo -e "${INFO}Reverse DNS for NS records:${NC}"
    dig +short NS "$osint_domain" 2>/dev/null | while read -r ns; do
        local ns_ip
        ns_ip=$(dig +short A "$ns" 2>/dev/null | head -1)
        printf "  ${LABEL}%-30s${NC} → ${CYAN}%s${NC}\n" "$ns" "$ns_ip"
    done
}

#  THREAT FEEDS & IOCs
check_threat_feeds() {
    header "Threat Intelligence Feeds & IOCs"

    section "What are IOCs?"
    cat << 'INFO'
  IOC (Indicator of Compromise) — artefact that indicates a security incident.

  IOC types:
    Network:
      IP addresses      — known C2 servers, scanners, TOR exit nodes
      Domains / URLs    — malware delivery, C2 beaconing, phishing
      Email addresses   — sender addresses, reply-to addresses
      JA3/JA3S hashes  — TLS fingerprints of known malware clients

    Host:
      File hashes       — MD5/SHA1/SHA256 of malware samples
      File paths        — known malware drop locations (%TEMP%, /var/tmp)
      Registry keys     — Windows persistence mechanisms
      Mutex names       — malware instance checks
      Process names     — known malicious process names

    Behavioural:
      Network patterns  — beacon intervals, domain generation algorithms
      Memory signatures — YARA rules against process memory

  IOC quality (pyramid of pain — David Bianco, 2013):
    Hash values    — Trivial to change (recompile)
    IP addresses   — Easy to change (new C2)
    Domain names   — Simple to change (new registrar)
    Network/host artefacts — Annoying to change
    Tools          — Challenging to change
    TTPs           — Tough to change (requires rethinking attack)
INFO

    section "Threat Intelligence Sharing Formats"
    cat << 'INFO'
  STIX (Structured Threat Information eXpression) v2.1 — JSON-based:
    Objects: Indicator, Malware, Attack Pattern, Campaign, Threat Actor...
    Relationships: uses, attributed-to, targets, mitigates...

  TAXII (Trusted Automated eXchange of Intelligence Information):
    Transport protocol for STIX over HTTPS.
    Collections: groups of STIX objects (one per threat group, campaign, etc.)

  OpenIOC: Mandiant's XML format for host-based indicators.
  MISP format: JSON, widely supported by open-source tools.

  Sharing communities:
    ISACs (Information Sharing & Analysis Centers) — sector-specific
    FS-ISAC (Financial), H-ISAC (Health), E-ISAC (Energy), IT-ISAC
    AlienVault OTX (Open Threat Exchange) — public, free
    CISA AIS (Automated Indicator Sharing) — US government
INFO

    section "Major Threat Intelligence Platforms"
    cat << 'INFO'
  Free:
    VirusTotal       — File/URL/IP/domain reputation (72+ AV engines)
    MalwareBazaar    — Malware sample repository (abuse.ch)
    URLhaus          — Malware distribution URLs (abuse.ch)
    Feodo Tracker    — Botnet C2 tracker (Emotet, TrickBot, QakBot)
    AlienVault OTX  — Community threat sharing platform
    Shodan           — Internet-scanning device intelligence
    GreyNoise        — Background internet noise classification
    AbuseIPDB        — IP abuse reporting database

  Commercial:
    Recorded Future  — Predictive threat intelligence (dark web + OSINT)
    Mandiant (Google)— Nation-state threat actor intelligence
    CrowdStrike Intel— Adversary intelligence (attribution)
    Palo Alto Unit42 — Threat research + intelligence

  Query format (VirusTotal API):
    curl -H "x-apikey: API_KEY" \
      "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
INFO

    section "IOC Lookup Demo"
    read -rp "$(echo -e "  ${PROMPT}Enter an IP to check against local blocklists [default: 1.1.1.1]:${NC} ")" check_ip
    check_ip="${check_ip:-1.1.1.1}"
    is_valid_ip "$check_ip" || { log_warning "Invalid IP"; check_ip="1.1.1.1"; }

    echo
    echo -e "${INFO}Reverse DNS for ${check_ip}:${NC}"
    dig +short -x "$check_ip" 2>/dev/null | sed 's/^/  /' || echo -e "  ${MUTED}No PTR${NC}"

    echo
    echo -e "${INFO}ASN/Organisation lookup:${NC}"
    if cmd_exists whois; then
        whois "$check_ip" 2>/dev/null \
            | grep -iE "^(netname|org-name|descr|country|cidr|route|owner|inetnum|NetRange)" \
            | head -10 | sed 's/^/  /'
    fi

    echo
    echo -e "${INFO}Checking local threat lists:${NC}"
    local threat_files=(
        "/etc/hosts.deny"
        "/etc/hosts"
    )
    local in_blocklist=0
    for f in "${threat_files[@]}"; do
        if [[ -f "$f" ]] && grep -q "$check_ip" "$f" 2>/dev/null; then
            echo -e "  ${FAILURE}${check_ip} found in ${f}${NC}"
            in_blocklist=1
        fi
    done
    [[ $in_blocklist -eq 0 ]] && status_line neutral "${check_ip} not found in local blocklists"

    echo
    echo -e "${MUTED}  For full threat intelligence, query VirusTotal, AbuseIPDB, or Shodan with an API key.${NC}"
}

#  CVE / CVSS
check_cve_cvss() {
    header "CVE, CVSS & Vulnerability Management"

    section "CVE — Common Vulnerabilities and Exposures"
    cat << 'INFO'
  CVE is a standardised identifier for publicly known vulnerabilities.
  Format: CVE-YEAR-SEQUENCE (e.g., CVE-2021-44228 = Log4Shell)
  Maintained by MITRE Corporation; sponsored by US CISA.

  CVE Lifecycle:
    1. Discovery — researcher or vendor finds vulnerability
    2. CNA assignment — CVE Numbering Authority assigns ID
    3. Analysis — NIST NVD adds CVSS score, CWE, affected versions
    4. Publication — publicly disclosed
    5. Remediation — vendor releases patch; users apply it

  NVD (National Vulnerability Database):
    nvd.nist.gov — authoritative CVSS scores, CPE, references
    Searchable API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
INFO

    section "CVSS — Common Vulnerability Scoring System"
    cat << 'INFO'
  CVSS v3.1 (current standard) — scores 0.0–10.0

  Severity bands:
    0.0       — None
    0.1–3.9   — Low
    4.0–6.9   — Medium
    7.0–8.9   — High
    9.0–10.0  — Critical

  Base Score Metrics:
    Attack Vector (AV):
      N=Network, A=Adjacent, L=Local, P=Physical
    Attack Complexity (AC): L=Low, H=High
    Privileges Required (PR): N=None, L=Low, H=High
    User Interaction (UI): N=None, R=Required
    Scope (S): U=Unchanged, C=Changed
    Confidentiality (C): N=None, L=Low, H=High
    Integrity (I): N=None, L=Low, H=High
    Availability (A): N=None, L=Low, H=High

  CVSS Vector example:
    CVE-2021-44228 (Log4Shell):
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  → 10.0 CRITICAL
    Meaning: Network-exploitable, low complexity, no auth, no user interaction,
             full confidentiality/integrity/availability impact across scope.

  Temporal Score: adjusts for exploit maturity, patch availability.
  Environmental Score: adjusts for your specific environment (CIA importance).
INFO

    section "Notable CVEs — Historical Reference"
    echo
    printf "  ${BOLD}%-20s %-8s %-14s %s${NC}\n" "CVE" "CVSS" "Affected" "Vulnerability"
    printf "  ${DARK_GRAY}%-20s %-8s %-14s %s${NC}\n" \
        "───────────────────" "───────" "─────────────" "──────────────────────────────────"
    while IFS='|' read -r cve score affected vuln; do
        local sc
        (( $(echo "$score >= 9.0" | bc -l 2>/dev/null) )) \
            && sc="$FAILURE" || sc="$WARNING"
        printf "  ${CYAN}%-20s${NC} ${sc}%-8s${NC} ${MUTED}%-14s${NC} %s\n" \
            "$cve" "$score" "$affected" "$vuln"
    done << 'TABLE'
CVE-2021-44228|10.0|Log4j 2.x|Log4Shell — JNDI injection, RCE
CVE-2014-0160|7.5|OpenSSL 1.0.1|Heartbleed — TLS memory leak
CVE-2017-5638|10.0|Apache Struts|Equifax breach — OGNL injection
CVE-2019-0708|9.8|Windows RDP|BlueKeep — unauthenticated RCE
CVE-2020-1472|10.0|Windows Netlogon|Zerologon — privilege escalation
CVE-2021-26855|9.8|Exchange Server|ProxyLogon — SSRF + auth bypass
CVE-2022-30190|7.8|Windows MSDT|Follina — zero-click Word exploit
CVE-2023-23397|9.8|Outlook|UNC path credential theft (no click)
CVE-2024-3400|10.0|PAN-OS|GlobalProtect command injection
CVE-2021-34527|8.8|Windows Print|PrintNightmare — LPE + RCE
TABLE

    section "Vulnerability Management Process"
    cat << 'INFO'
  1. Asset discovery    — know what you have (Nmap, Nessus, OpenVAS)
  2. Vulnerability scan — identify known CVEs in your assets
  3. Risk prioritisation — CVSS + asset criticality + exploitability
  4. Patch management   — apply patches; track SLA (critical: 24-48h)
  5. Verification       — re-scan to confirm remediation
  6. Exception tracking — document accepted risks (with expiry)

  Vulnerability scanners:
    Open source: OpenVAS/GVM, Nessus Essentials (free tier), Nuclei
    Commercial:  Qualys, Tenable.io, Rapid7 InsightVM, Crowdstrike Spotlight

  Patch SLA targets (common):
    Critical (9.0-10.0): 24-48 hours
    High (7.0-8.9):      7 days
    Medium (4.0-6.9):    30 days
    Low (0.1-3.9):       90 days
INFO

    section "Local Vulnerability Check"
    echo -e "${INFO}Checking installed packages for known vulnerable versions:${NC}"
    echo
    if cmd_exists dpkg; then
        echo -e "  ${MUTED}Checking OpenSSL version:${NC}"
        dpkg -l openssl 2>/dev/null | grep "^ii" | awk '{printf "  OpenSSL: %s\n", $3}'
        openssl version 2>/dev/null | sed 's/^/  /'

        echo
        echo -e "  ${MUTED}Checking SSH version:${NC}"
        ssh -V 2>&1 | sed 's/^/  /'

        echo
        echo -e "  ${MUTED}Packages with recent updates:${NC}"
        dpkg -l 2>/dev/null | grep "^ii" | wc -l | \
            xargs printf "  Total installed packages: %s\n"
    fi

    if cmd_exists rpm; then
        echo -e "  ${MUTED}Checking RPM packages:${NC}"
        rpm -qa --last 2>/dev/null | head -10 | sed 's/^/  /'
    fi

    echo
    echo -e "${MUTED}  For full CVE scanning, use: nmap --script vuln, or OpenVAS/Nessus${NC}"
}

#  KILL CHAIN & ATTACK FRAMEWORKS
check_kill_chain() {
    header "Cyber Kill Chain & Attack Frameworks"

    section "Lockheed Martin Cyber Kill Chain (2011)"
    cat << 'INFO'
  7 phases of a targeted cyberattack:

  1. Reconnaissance
     Goal:    Gather information about the target
     Tools:   OSINT, Shodan, whois, LinkedIn, Maltego, social engineering
     Defence: Monitor for reconnaissance (Shodan alerts), limit public info

  2. Weaponisation
     Goal:    Create exploit + payload (malware delivery mechanism)
     Tools:   Metasploit, custom malware, Office macro, malicious PDF/ISO
     Defence: Threat intel sharing; no defence possible at target

  3. Delivery
     Goal:    Transmit weapon to target environment
     Methods: Spear-phishing email, watering hole, USB drop, web exploit
     Defence: Email security (SPF/DKIM/DMARC), web proxy, user training

  4. Exploitation
     Goal:    Trigger code execution using a vulnerability
     Methods: CVE exploit, zero-day, social engineering (run attachment)
     Defence: Patch management, application allowlisting, EDR

  5. Installation
     Goal:    Establish persistence on target system
     Methods: Rootkit, service install, registry autorun, cron, WMI
     Defence: Least privilege, EDR, file integrity monitoring

  6. Command & Control (C2)
     Goal:    Establish remote channel for attacker control
     Methods: HTTP/HTTPS beaconing, DNS tunnelling, ICMP C2, social media
     Defence: Egress filtering, DNS monitoring, anomaly detection

  7. Actions on Objectives
     Goal:    Achieve mission (exfil, ransomware, destruction, pivot)
     Methods: Data exfiltration, encryption, sabotage, persistence
     Defence: DLP, SIEM, network segmentation, honeyfiles
INFO

    section "MITRE ATT&CK Framework"
    cat << 'INFO'
  MITRE ATT&CK (Adversarial Tactics, Techniques & Common Knowledge)
  Knowledge base of real-world adversary TTPs observed in the wild.
  Version 14 (2023): 14 Tactics, 200+ Techniques, 400+ Sub-techniques.

  14 Tactics (Enterprise):
    TA0043 — Reconnaissance        Gather info before compromise
    TA0042 — Resource Development  Build infrastructure, acquire tools
    TA0001 — Initial Access        Gain foothold (phishing, exploit)
    TA0002 — Execution             Run malicious code
    TA0003 — Persistence           Maintain access across reboots
    TA0004 — Privilege Escalation  Gain higher permissions
    TA0005 — Defence Evasion       Avoid detection
    TA0006 — Credential Access     Steal credentials
    TA0007 — Discovery             Learn about environment
    TA0008 — Lateral Movement      Move through network
    TA0009 — Collection            Gather data of interest
    TA0011 — Command & Control     Communicate with compromised systems
    TA0010 — Exfiltration          Steal data
    TA0040 — Impact                Destroy, manipulate, disrupt

  Notable Technique Examples:
    T1566.001 — Spearphishing Attachment      (Initial Access)
    T1078     — Valid Accounts               (Persistence, Priv Esc)
    T1059.001 — PowerShell                   (Execution)
    T1003.001 — LSASS Memory (Mimikatz)      (Credential Access)
    T1021.001 — Remote Desktop Protocol      (Lateral Movement)
    T1486     — Data Encrypted for Impact    (Ransomware)
    T1048     — Exfiltration over Alt Protocol(Exfiltration)
    T1071.004 — DNS Application Protocol C2  (C&C)

  Use cases for defenders:
    Detection engineering: Map SIEM rules to ATT&CK techniques
    Gap analysis: ATT&CK Navigator — visualise detection coverage
    Red team planning: TTPs to emulate specific threat actors
    Threat intelligence: Attribution to known groups (APT29, Lazarus)
INFO

    section "MITRE ATT&CK Group Examples"
    echo
    printf "  ${BOLD}%-12s %-16s %-20s %s${NC}\n" "Group ID" "Name/Alias" "Origin" "Known For"
    printf "  ${DARK_GRAY}%-12s %-16s %-20s %s${NC}\n" \
        "───────────" "───────────────" "───────────────────" "──────────────────────────────"
    while IFS='|' read -r id name origin known; do
        printf "  ${CYAN}%-12s${NC} ${GOLD}%-16s${NC} ${MUTED}%-20s${NC} %s\n" \
            "$id" "$name" "$origin" "$known"
    done << 'TABLE'
G0016|APT29/Cozy Bear|Russia (SVR)|SolarWinds, DNC breach
G0007|APT28/Fancy Bear|Russia (GRU)|DNC, Bundestag, WADA
G0032|Lazarus Group|North Korea (RGB)|Sony, WannaCry, SWIFT
G0096|APT41|China (MSS)|Double espionage + cybercrime
G0034|Sandworm|Russia (GRU)|NotPetya, Ukraine power grid
G0080|Cobalt Group|FIN7/FIN|Financial sector, POS malware
G0085|FIN4|Unknown|Healthcare M&A insider trading
G0114|Chimera|China|Airline industry, IP theft
TABLE

    section "Diamond Model of Intrusion Analysis"
    cat << 'INFO'
  The Diamond Model (Caltagirone, 2013) structures intrusion events:

           ADVERSARY
          /         \
        /             \
  INFRASTRUCTURE — — VICTIM
        \             /
          \         /
           CAPABILITY

  Each axis:
    Adversary:      Who is attacking (attacker identity, motivation)
    Capability:     What tools/techniques they use (malware, exploits)
    Infrastructure: How they connect (C2 IPs, domains, hosting)
    Victim:         Who is targeted (org, person, system)

  Meta-features:
    Timestamp, Phase (Kill Chain step), Result, Direction, Methodology

  Use: link multiple incidents to same adversary by pivoting on shared indicators.
INFO
}

#  THREAT HUNTING
check_threat_hunting() {
    header "Threat Hunting"

    section "What is Threat Hunting?"
    cat << 'INFO'
  Threat hunting = proactive, hypothesis-driven search for hidden threats
  not yet detected by automated controls (SIEM rules, AV, EDR).

  Hunting Maturity Model (Sqrrl):
    Level 0 — Reactive    (rely on alerts only)
    Level 1 — Minimal     (threat intel enrichment of alerts)
    Level 2 — Procedural  (run hunts from others' procedures)
    Level 3 — Innovative  (create novel data-driven hypotheses)
    Level 4 — Leading     (automate hunts, contribute to community)

  Hunting loop:
    1. Form hypothesis   (informed by threat intel, ATT&CK, known TTPs)
    2. Investigate       (search logs, PCAP, endpoint data)
    3. Uncover patterns  (find anomalies or confirm absence of threat)
    4. Inform & enrich   (update detections, block IOCs, improve baseline)
INFO

    section "Hypothesis Examples"
    cat << 'INFO'
  Based on ATT&CK:
    H1: "An adversary may use T1071.004 (DNS C2) to beacon using long DNS names"
    H2: "An adversary may establish persistence via T1053.005 (Scheduled Tasks)"
    H3: "Lateral movement via T1021.001 (RDP) from unusual source hosts"

  Hypothesis-to-hunt:
    H1 → Query: DNS queries with name length > 50 chars, NXDOMAIN rate > 30%
    H2 → Query: schtasks.exe spawned by non-admin user, new task in 24h
    H3 → Query: RDP connections originating from workstations (not jump hosts)
INFO

    section "Local Threat Hunting Queries"
    echo -e "${INFO}Looking for suspicious network indicators...${NC}"
    echo

    echo -e "  ${AMBER}Unusual listening services (non-standard ports):${NC}"
    ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | cut -d: -f2 \
        | grep -vE '^(22|80|443|25|53|110|143|993|995|587|3306|5432|8080|8443|0)$' \
        | sort -un | while read -r port; do
            local proc
            proc=$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4~p{print $6}' | head -1)
            printf "  ${WARNING}Port %-6s${NC} %s\n" "$port" "$proc"
        done \
        || echo -e "  ${MUTED}  None detected${NC}"

    echo
    echo -e "  ${AMBER}Processes with outbound established connections (external IPs):${NC}"
    ss -tnp state established 2>/dev/null | awk 'NR>1{print $5, $6}' \
        | grep -v "127\.\|::1\|10\.\|172\.1[6-9]\.\|172\.2[0-9]\.\|172\.3[01]\.\|192\.168\." \
        | head -10 | while read -r remote proc; do
            printf "  ${CYAN}%-22s${NC} %s\n" "$remote" "$proc"
        done \
        || echo -e "  ${MUTED}  No unexpected external connections${NC}"

    echo
    echo -e "  ${AMBER}SUID binaries (privilege escalation candidates):${NC}"
    find /usr /bin /sbin -perm -4000 -type f 2>/dev/null | head -10 | while read -r f; do
        local size
        size=$(du -sh "$f" 2>/dev/null | cut -f1)
        printf "  ${WARNING}%s${NC} ${MUTED}(%s)${NC}\n" "$f" "$size"
    done

    echo
    echo -e "  ${AMBER}Recently modified system files (last 24h):${NC}"
    find /etc /bin /sbin /usr/bin /usr/sbin -newer /etc/passwd \
        -not -name "*.pyc" -not -path "*/\.*" 2>/dev/null \
        | head -10 | while read -r f; do
            local mtime
            mtime=$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)
            printf "  ${FAILURE}%s${NC} ${MUTED}[%s]${NC}\n" "$f" "$mtime"
        done \
        || echo -e "  ${MUTED}  No unexpected modifications found${NC}"

    echo
    echo -e "  ${AMBER}Cron jobs (persistence check):${NC}"
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron; do
        if [[ -d "$cron_dir" ]]; then
            local count
            count=$(find "$cron_dir" -type f 2>/dev/null | wc -l)
            printf "  ${MUTED}%-35s${NC} %s files\n" "$cron_dir" "$count"
        fi
    done
    echo
    crontab -l 2>/dev/null | grep -v "^#\|^$" | head -5 | sed 's/^/  /' \
        || echo -e "  ${MUTED}  No user crontab entries${NC}"
}

#  DARK WEB CONCEPTS
check_dark_web() {
    header "Dark Web & Underground Economy"

    section "The Web Layers"
    cat << 'INFO'
  Surface Web: Indexed by search engines (Google, Bing).
    ~5% of all web content. Normal websites, news, social media.

  Deep Web: Not indexed, requires authentication or direct URL.
    ~90%+ of web content. Online banking, email, corporate intranets,
    academic databases, cloud storage, medical records.
    NOT inherently illegal — just not public.

  Dark Web: Requires special software (Tor, I2P, Freenet).
    ~0.01% of web content. .onion domains on Tor network.
    Used by: privacy-conscious users, journalists, dissidents,
             activists in oppressive regimes — AND criminals.

  Note: "dark web" ≠ "dark net" ≠ "deep web" (commonly conflated).
INFO

    section "Tor Network Architecture"
    cat << 'INFO'
  Tor (The Onion Router) — originally a US Navy project (1990s).
  Operated by Tor Project (non-profit). Uses layered encryption.

  How Tor works:
    1. Client fetches consensus from directory servers (guard nodes)
    2. Builds 3-hop circuit: Guard Node → Middle Node → Exit Node
    3. Each hop knows only previous and next hop (onion routing)
    4. Exit node connects to destination; sees destination but not source

  Encryption layers (like an onion):
    Client encrypts payload 3 times (one per hop).
    Each node decrypts its layer and forwards to next.
    Exit node sees final plaintext (if HTTP; HTTPS remains encrypted).

  .onion (v3) addresses:
    56-char base32 string derived from Ed25519 public key.
    No DNS; address IS the public key. End-to-end with no exit node.
    Server identity anonymous (hidden service).

  Tor weaknesses:
    Timing correlation: monitor ingress + egress to deanonymize
    Malicious exit nodes: can MITM unencrypted connections
    Browser fingerprinting: Tor Browser mitigates but not eliminates
    Bad OPSEC: logging in to accounts defeats anonymity
INFO

    section "Dark Web Threat Intelligence"
    cat << 'INFO'
  Monitoring dark web for your organisation:

  What attackers sell/buy on dark web markets:
    Stolen credentials:   Corporate logins, customer databases, combo lists
    Initial access:       RDP/VPN/citrix sessions to specific corporates
    Ransomware-as-a-Service (RaaS): Affiliate programs (LockBit, ALPHV)
    Zero-day exploits:   Priced $10K–$2.5M (iOS, Windows, browser)
    DDoS-for-hire:       Booter/stresser services
    Fraud:               Carding, money mules, synthetic identity

  Monitoring services:
    Commercial: Recorded Future, Flashpoint, Digital Shadows, Kela
    Free/Research: OnionScan, DarkOwl, Ransomwatch

  Leaked credential monitoring:
    Have I Been Pwned (HIBP) — haveibeenpwned.com API
    Dehashed — paid search of leaked databases
    IntelX (intelligence.io) — dark web, paste site indexing

  Ransomware leak sites (monitored by threat intel teams):
    Groups publish stolen data to pressure victims into paying.
    Sites: LockBit (down 2024), ALPHV/BlackCat (down 2024), Cl0p, etc.
INFO

    section "HIBP — Have I Been Pwned Check"
    read -rp "$(echo -e "  ${PROMPT}Enter email to check against HIBP API [or skip]:${NC} ")" hibp_email
    if [[ -n "$hibp_email" ]] && cmd_exists curl; then
        local email_hash hibp_prefix hibp_suffix
        email_hash=$(echo -n "${hibp_email,,}" | sha1sum | awk '{print toupper($1)}')
        hibp_prefix="${email_hash:0:5}"
        hibp_suffix="${email_hash:5}"
        echo
        echo -e "  ${MUTED}Using k-Anonymity: sending prefix '${hibp_prefix}' only${NC}"
        local result
        result=$(curl -s --max-time 5 \
            -H "Add-Padding: true" \
            "https://api.pwnedpasswords.com/range/${hibp_prefix}" 2>/dev/null)
        if echo "$result" | grep -qi "^${hibp_suffix}:"; then
            local count
            count=$(echo "$result" | grep -i "^${hibp_suffix}:" | cut -d: -f2 | tr -d '[:space:]')
            echo -e "  ${FAILURE}Password/hash found in ${count} breaches!${NC}"
        elif [[ -n "$result" ]]; then
            status_line ok "Password hash not found in HIBP breach database"
        else
            echo -e "  ${MUTED}Could not reach HIBP API${NC}"
        fi
    fi

    section "Ransomware Kill Switch & Detection"
    cat << 'INFO'
  WannaCry (2017) kill switch:
    Hardcoded DNS lookup to a specific domain (registered by Marcus Hutchins).
    If domain resolved → malware would exit (sandbox detection check).
    Registering the domain accidentally stopped the outbreak.

  Common ransomware detection signals:
    File system: mass file renames (.locked, .encrypted extensions)
    Volume Shadow Copy deletion: vssadmin delete shadows /all /quiet
    Process: powershell.exe with encoded command (-enc)
    Network: rapid internal SMB scanning (EternalBlue propagation)
    Registry: RunOnce / HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Mutex: malware checks for own mutex to prevent double-infection

  Defence:
    Immutable backups (3-2-1 rule: 3 copies, 2 media, 1 offsite)
    Disable macros in Office via Group Policy
    Network segmentation (prevent rapid spread)
    EDR with behavioural detection (Crowdstrike, SentinelOne, Microsoft Defender)
    Application allowlisting (AppLocker, WDAC)
INFO
}

#  INCIDENT RESPONSE
check_incident_response() {
    header "Incident Response Fundamentals"

    section "NIST Incident Response Lifecycle"
    cat << 'INFO'
  NIST SP 800-61r2 — four-phase model:

  1. Preparation
     Policies, tools, team training, runbooks, communication plan,
     legal counsel contacts, forensic workstations, evidence bags.

  2. Detection & Analysis
     Alert triage, log analysis, correlation, severity classification.
     Questions: What happened? When? How? What systems affected?
     Severity levels: P1 Critical (24h), P2 High (48h), P3 Medium (7d)

  3. Containment, Eradication & Recovery
     Short-term: isolate affected systems (network segment, VLAN change)
     Long-term:  remove malware, patch vulnerability, restore from backup
     Recovery:   monitor for re-infection, restore to production

  4. Post-Incident Activity
     Root cause analysis (5 Whys)
     Lessons learned document
     Update runbooks, detections, controls
     Legal/regulatory notification (GDPR: 72 hours)

  SANS PICERL adds: Identification, Lessons Learned (slightly different grouping).
INFO

    section "Digital Forensics — Evidence Collection"
    cat << 'INFO'
  Order of Volatility (collect most volatile first):
    1. CPU registers, cache, running processes (RAM)
    2. Network connections, ARP cache, routing table
    3. RAM contents (memory dump)
    4. Running processes (proc list, open files, sockets)
    5. File system metadata (timestamps — access changes them!)
    6. Swap/pagefile
    7. Log files
    8. Archived media, backups

  Chain of Custody:
    Document every person who handles evidence.
    Hash all collected artefacts (SHA-256) immediately.
    Store in write-protected evidence containers.

  Memory acquisition:
    Linux: avml, lime (LKM), /proc/kcore
    Windows: WinPmem, Magnet RAM Capture, FTK Imager

  Disk imaging:
    dd if=/dev/sda of=image.dd bs=512 status=progress
    dcfldd (add hash on-the-fly)
    Forensic tools: Autopsy, FTK, Sleuth Kit
INFO

    section "Live Incident Triage Commands"
    echo -e "${INFO}Running a rapid triage snapshot...${NC}"
    echo

    local triage_file="${OUTPUT_DIR}/triage_$(date '+%Y%m%d_%H%M%S').txt"

    {
        echo "=== TRIAGE REPORT ==="
        echo "Timestamp: $(date)"
        echo "Hostname:  $(hostname)"
        echo "Uptime:    $(uptime)"
        echo
        echo "--- Running Processes ---"
        ps auxf 2>/dev/null | head -30
        echo
        echo "--- Network Connections ---"
        ss -tnp 2>/dev/null | head -20
        echo
        echo "--- Listening Ports ---"
        ss -tlnp 2>/dev/null
        echo
        echo "--- ARP Table ---"
        ip neigh show 2>/dev/null
        echo
        echo "--- Last 20 Logins ---"
        last -n 20 2>/dev/null
        echo
        echo "--- Failed Logins ---"
        lastb -n 20 2>/dev/null || journalctl -u ssh --since "24 hours ago" 2>/dev/null \
            | grep -i "failed" | tail -10
        echo
        echo "--- Crontab ---"
        crontab -l 2>/dev/null
        echo
        echo "--- /etc/passwd changes (last 24h) ---"
        find /etc -name "passwd" -newer /tmp -newer /etc/hosts 2>/dev/null | head -5
        echo
    } > "$triage_file" 2>/dev/null

    log_success "Triage report saved: $triage_file"
    echo
    echo -e "${INFO}Quick triage summary:${NC}"
    echo
    kv "Running processes" "$(ps aux 2>/dev/null | wc -l)"
    kv "Established connections" "$(ss -tn state established 2>/dev/null | wc -l)"
    kv "Listening ports" "$(ss -tlnp 2>/dev/null | tail -n +2 | wc -l)"
    kv "Logged-in users" "$(who 2>/dev/null | wc -l)"
    kv "Failed SSH logins (journal)" "$(journalctl -u ssh -u sshd --since today 2>/dev/null \
        | grep -c "Failed" || echo "N/A")"

    pause
}

main() {
    check_osint
    check_threat_feeds
    check_cve_cvss
    check_kill_chain
    check_threat_hunting
    check_dark_web
    check_incident_response
}

main