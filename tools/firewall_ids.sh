#!/bin/bash

# /tools/firewall_ids.sh
# Topic: Firewalls, IDS/IPS & WAF — Interactive Lab
# Covers: Firewall types, iptables/nftables, IDS/IPS, Snort/Suricata, WAF, fail2ban

# Bootstrap
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$_SELF_DIR")"}"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

: "${LOG_DIR:="${PROJECT_ROOT}/logs"}"
: "${OUTPUT_DIR:="${PROJECT_ROOT}/output"}"
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

#  FIREWALL FUNDAMENTALS
check_firewall_types() {
    header "Firewall Types & Architecture"

    section "Firewall Generations"
    cat << 'INFO'
  Generation 1 — Packet Filter (Stateless)
    Inspects each packet independently: src/dst IP, port, protocol.
    No session awareness — cannot track TCP state.
    Fast but easily evaded (fragmentation, spoofed ACK floods).
    Example: early BSD ipfw, router ACLs

  Generation 2 — Stateful Inspection
    Tracks TCP/UDP connection state in a session table.
    Legitimate replies allowed; unsolicited packets dropped.
    Most common: iptables, nftables, Windows Firewall, pf (BSD)

  Generation 3 — Application Layer Gateway (ALG) / Deep Packet Inspection
    Inspects payload up to Layer 7.
    Protocol-aware: understands FTP PORT command, SIP, DNS.
    Can detect protocol misuse (HTTP over port 443 ≠ HTTPS).

  Generation 4 — Next-Generation Firewall (NGFW)
    DPI + Application identification (regardless of port).
    User identity awareness (integrates with AD/LDAP).
    SSL/TLS inspection (MITM on encrypted traffic).
    Integrated IPS, sandboxing, threat intelligence feeds.
    Examples: Palo Alto PA series, Fortinet FortiGate, Cisco FTD
INFO

    section "Firewall Deployment Models"
    cat << 'INFO'
  Perimeter Firewall:
    Internet ─── [FW] ─── Internal LAN
    Simplest model; no protection from insider threats

  DMZ (Demilitarized Zone):
    Internet ─── [Ext FW] ─── [DMZ: Web/Mail/DNS] ─── [Int FW] ─── LAN
    Public servers exposed; internal LAN double-protected

  East-West Inspection (Micro-segmentation):
    Firewall between internal segments (VLANs, pods)
    Prevents lateral movement after initial compromise
    Zero Trust model: "never trust, always verify"

  Firewall Clustering / HA:
    Active-Passive: standby takes over on failure (session loss)
    Active-Active: load sharing with session sync (complex)
INFO

    section "Packet Filter Decision Logic"
    echo
    echo -e "  ${MUTED}Incoming packet arrives on interface${NC}"
    echo -e "  ${MUTED}         │${NC}"
    echo -e "  ${MUTED}         ▼${NC}"
    echo -e "  ${MUTED}  ┌─────────────┐${NC}"
    echo -e "  ${MUTED}  │ Match rules  │ ← Rules evaluated top-to-bottom${NC}"
    echo -e "  ${MUTED}  │ (in order)   │   First match wins${NC}"
    echo -e "  ${MUTED}  └──────┬──────┘${NC}"
    echo -e "  ${MUTED}     ┌───┴───┐${NC}"
    echo -e "  ${SUCCESS}  ACCEPT ${NC}  ${FAILURE}DROP/REJECT${NC}"
    echo -e "  ${MUTED}  (forward)  (discard)${NC}"
}

#  IPTABLES DEEP DIVE
check_iptables() {
    header "iptables — Linux Packet Filtering"

    section "Tables, Chains & Hooks"
    cat << 'INFO'
  iptables operates on TABLES, each containing CHAINS of RULES.

  Tables:
    filter  — default; controls packet accept/drop/reject
    nat     — Network Address Translation (PREROUTING, OUTPUT, POSTROUTING)
    mangle  — packet modification (TTL, TOS, MARK)
    raw     — bypass connection tracking (PREROUTING, OUTPUT)
    security— SELinux/mandatory access control

  Built-in Chains (hook points in the network stack):
    PREROUTING  — before routing decision (raw, nat, mangle)
    INPUT       — for packets destined to this host
    FORWARD     — for packets routed through this host
    OUTPUT      — from local processes
    POSTROUTING — after routing decision, before sending

  Packet traversal (incoming to local process):
    NIC → PREROUTING → INPUT → Local Process

  Packet traversal (forwarded):
    NIC → PREROUTING → FORWARD → POSTROUTING → NIC

  Default Policies: ACCEPT or DROP (applied if no rule matches)
INFO

    section "Rule Anatomy"
    echo
    echo -e "  ${CYAN}iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT${NC}"
    echo
    kv "  -A INPUT"        "Append to INPUT chain (filter table)"
    kv "  -p tcp"          "Protocol match: TCP"
    kv "  --dport 22"      "Destination port 22 (SSH)"
    kv "  -s 10.0.0.0/8"   "Source IP range (RFC1918 Class A)"
    kv "  -j ACCEPT"       "Jump target: ACCEPT the packet"
    echo
    echo -e "  ${MUTED}Common targets: ACCEPT, DROP, REJECT, LOG, MASQUERADE, DNAT, SNAT, MARK${NC}"

    section "Common Rule Patterns"
    cat << 'CMDS'
  # Allow established/related (stateful — put this near top)
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Allow loopback
  iptables -A INPUT -i lo -j ACCEPT

  # Allow SSH from specific subnet
  iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

  # Rate-limit SSH (prevent brute force)
  iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min --limit-burst 5 -j ACCEPT

  # Allow HTTP/HTTPS
  iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

  # Drop invalid packets
  iptables -A INPUT -m state --state INVALID -j DROP

  # Log and drop all else (default deny)
  iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4
  iptables -A INPUT -j DROP

  # NAT masquerade (outbound)
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

  # Port forwarding (DNAT)
  iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80
CMDS

    section "Live iptables State"
    echo -e "${INFO}Current filter table rules:${NC}"
    if sudo iptables -L -n -v --line-numbers 2>/dev/null | head -50 | grep -v "^$"; then
        :
    else
        echo -e "  ${MUTED}Cannot read iptables (requires sudo or not available)${NC}"
    fi

    echo
    echo -e "${INFO}iptables default policies:${NC}"
    sudo iptables -L 2>/dev/null | grep "^Chain" | while read -r _ chain _ policy _; do
        local color
        [[ "$policy" == "(policy DROP)" ]] && color="$SUCCESS" || color="$WARNING"
        printf "  ${CYAN}%-14s${NC} ${color}%s${NC}\n" "$chain" "$policy"
    done

    echo
    echo -e "${INFO}Connection tracking table (first 10):${NC}"
    if [[ -f /proc/net/nf_conntrack ]]; then
        head -10 /proc/net/nf_conntrack | sed 's/^/  /'
        echo -e "  ${MUTED}Total entries: $(wc -l < /proc/net/nf_conntrack)${NC}"
    else
        echo -e "  ${MUTED}nf_conntrack not available${NC}"
    fi
}

#  NFTABLES
check_nftables() {
    header "nftables — Modern Linux Packet Filtering"

    cat << 'INFO'
  nftables is the successor to iptables (Linux 3.13+, 2014).
  Unified framework replacing iptables/ip6tables/arptables/ebtables.

  Key improvements over iptables:
    - Single tool (nft) for all L2/L3/L4 filtering
    - Sets and maps for efficient multi-value matching (no rule duplication)
    - Atomic rule replacement (no partial-apply window)
    - Better performance at scale (JIT compilation)
    - Cleaner syntax; easier to read rulesets

  Concepts:
    Tables    — namespace; family (ip, ip6, inet, arp, bridge, netdev)
    Chains    — collection of rules with a hook, priority, policy
    Rules     — match + statement (accept, drop, log, counter, nat...)
    Sets      — named groups of addresses/ports for match efficiency
    Maps      — key→value lookup for dynamic rule decisions
INFO

    section "nftables vs iptables Syntax Comparison"
    echo
    printf "  ${BOLD}%-42s %-42s${NC}\n" "iptables" "nftables"
    printf "  ${DARK_GRAY}%-42s %-42s${NC}\n" "$(printf '─%.0s' {1..40})" "$(printf '─%.0s' {1..40})"
    while IFS='|' read -r old new; do
        printf "  ${YELLOW}%-42s${NC} ${CYAN}%-42s${NC}\n" "$old" "$new"
    done << 'TABLE'
iptables -A INPUT -p tcp -j DROP|nft add rule ip filter input tcp dport drop
iptables -N MYCHAIN|nft add chain ip filter MYCHAIN
iptables -m multiport --dports 80,443|nft add rule ... tcp dport { 80, 443 }
iptables -s 10.0.0.0/8 -j ACCEPT|nft add rule ... ip saddr 10.0.0.0/8 accept
ip6tables -A INPUT -j DROP|nft add rule ip6 filter input drop
TABLE

    section "nftables Configuration Example"
    cat << 'CONF'
  # /etc/nftables.conf
  table inet filter {
      set trusted_hosts {
          type ipv4_addr
          elements = { 192.168.1.0/24, 10.0.0.1 }
      }

      chain input {
          type filter hook input priority 0; policy drop;
          ct state established,related accept
          iif lo accept
          ip saddr @trusted_hosts tcp dport 22 accept
          tcp dport { 80, 443 } accept
          icmp type echo-request limit rate 5/second accept
          counter log prefix "nft-drop: " drop
      }

      chain forward {
          type filter hook forward priority 0; policy drop;
      }

      chain output {
          type filter hook output priority 0; policy accept;
      }
  }
CONF

    section "Live nftables State"
    if cmd_exists nft; then
        echo -e "${INFO}Current nftables ruleset:${NC}"
        sudo nft list ruleset 2>/dev/null | head -40 | sed 's/^/  /' \
            || echo -e "  ${MUTED}Empty or cannot read (requires sudo)${NC}"
    else
        status_line neutral "nft not installed (iptables in use or no firewall configured)"
    fi
}

#  UFW (Uncomplicated Firewall)
check_ufw() {
    header "UFW — Uncomplicated Firewall"

    cat << 'INFO'
  UFW is a frontend for iptables designed for simplicity.
  Default on Ubuntu. Stores rules in /etc/ufw/ directory.

  Common commands:
    ufw enable / disable / status verbose
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow from 192.168.1.0/24 to any port 3306
    ufw deny 23
    ufw limit ssh                  (rate-limits to 6 conn/30s)
    ufw delete allow 80/tcp
    ufw logging on
INFO

    section "Live UFW Status"
    if cmd_exists ufw; then
        echo -e "${INFO}UFW status:${NC}"
        sudo ufw status verbose 2>/dev/null | sed 's/^/  /' \
            || echo -e "  ${MUTED}Cannot read UFW status (requires sudo)${NC}"
    else
        status_line neutral "UFW not installed"
    fi
}

#  IDS / IPS
check_ids_ips() {
    header "IDS & IPS — Intrusion Detection & Prevention"

    section "IDS vs IPS"
    cat << 'INFO'
  IDS (Intrusion Detection System) — passive monitoring
    Copies traffic (SPAN/TAP), analyses, generates ALERTS.
    Does not block — zero impact on traffic flow.
    Alert lag: detection → analyst → response (minutes to hours).

  IPS (Intrusion Prevention System) — active, inline
    Sits inline in the traffic path; can DROP/RESET connections.
    Immediate automated response.
    Risk: false positives cause legitimate traffic to be blocked.
    Bypass: failopen (pass on failure) vs failclosed (drop on failure).

  HIDS (Host-Based IDS) — runs on the host
    Monitors: file integrity, process execution, syscalls, logs, registry.
    Tools: OSSEC, Wazuh, AIDE, Tripwire, Auditd, osquery.

  NIDS (Network-Based IDS) — monitors network traffic
    Captures packets from mirror port / network TAP.
    Tools: Snort, Suricata, Zeek (Bro).
INFO

    section "Detection Methods"
    cat << 'INFO'
  Signature-Based (Misuse Detection):
    Rules match known attack patterns (CVE signatures, shellcode bytes).
    + Low false positives for known attacks
    − Cannot detect zero-days or obfuscated variants

  Anomaly-Based (Behaviour Detection):
    Baseline normal traffic → alert on deviation.
    + Can detect novel attacks
    − High false positive rate; training period required
    Examples: ML models, statistical thresholds

  Reputation-Based:
    Block traffic to/from known-bad IPs, domains, hashes (threat feeds).
    + Easy to implement, low overhead
    − Only effective for known-bad indicators

  Protocol Analysis / Specification-Based:
    Verify protocol compliance (e.g., HTTP must have valid verb).
    + Effective against protocol-level evasion
    − Limited to well-understood protocols
INFO

    section "Snort Rule Anatomy"
    cat << 'INFO'
  Snort 3 / Suricata rule format:
  action proto src_ip src_port direction dst_ip dst_port (options)

  alert tcp any any -> $HOME_NET 22 (
      msg:"SSH brute force attempt";
      flow:to_server;
      threshold:type both, track by_src, count 5, seconds 60;
      classtype:attempted-admin;
      sid:1000001;
      rev:1;
  )

  alert http any any -> any any (
      msg:"SQL Injection attempt";
      http.uri;
      content:"UNION SELECT";
      nocase;
      classtype:web-application-attack;
      sid:1000002;
      rev:1;
  )

  Actions: alert, log, pass, drop (IPS), reject, rewrite
  Flow keywords: established, to_server, to_client
  Content modifiers: nocase, rawbytes, offset, depth, distance, within
INFO

    section "Suricata — Key Advantages over Snort"
    cat << 'INFO'
  Multi-threaded: uses all CPU cores (Snort is single-threaded per interface).
  Protocol detection independent of port (HTTP on port 4444 still detected).
  File extraction: saves files transferred over HTTP/FTP/SMTP for analysis.
  TLS fingerprinting: JA3/JA3S for encrypted traffic profiling.
  PCAP replay: can process offline captures.
  EVE JSON output: structured logs for SIEM ingestion.
  Lua scripting: custom detection logic.
INFO

    section "Zeek (Bro) — Network Analysis Framework"
    cat << 'INFO'
  Zeek focuses on protocol analysis and behavioural logging — not signatures.
  Produces structured logs (conn.log, dns.log, http.log, ssl.log, files.log, etc.)
  Scriptable in Zeek scripting language for custom analysis.

  Use case: threat hunting, compliance, forensics, anomaly detection.
  Integrates with Elastic Stack (ELK) for SIEM dashboards.
INFO

    section "IDS/IPS Status on This System"
    local found_ids=0
    for service in snort suricata zeek ossec wazuh-agent auditd; do
        if systemctl is-active "$service" &>/dev/null; then
            status_line ok "${service} is running"
            found_ids=1
        elif pgrep -x "$service" &>/dev/null; then
            status_line ok "${service} running (non-systemd)"
            found_ids=1
        fi
    done
    [[ $found_ids -eq 0 ]] && status_line neutral "No IDS/IPS services detected"

    section "auditd — Linux Audit System"
    if cmd_exists auditctl; then
        echo -e "${INFO}Audit rules:${NC}"
        sudo auditctl -l 2>/dev/null | head -20 | sed 's/^/  /' \
            || echo -e "  ${MUTED}Cannot read (requires sudo)${NC}"
    else
        status_line neutral "auditd not installed (install: apt install auditd)"
    fi

    if cmd_exists ausearch; then
        echo
        echo -e "${INFO}Recent authentication events:${NC}"
        sudo ausearch -m USER_AUTH,USER_LOGIN -ts today 2>/dev/null | tail -20 | sed 's/^/  /' \
            || echo -e "  ${MUTED}No events or insufficient privilege${NC}"
    fi
}

#  WAF — WEB APPLICATION FIREWALL
check_waf() {
    header "WAF — Web Application Firewall"

    cat << 'INFO'
  A WAF operates at Layer 7 (HTTP/HTTPS) to protect web applications.
  Positioned between the Internet and the web application server.

  WAF vs Network Firewall:
    Network FW: "Is this TCP session allowed?"
    WAF:        "Is this HTTP request semantically valid and non-malicious?"

  WAF Detection Modes:
    Blacklist (negative security): block known bad patterns (SQLi, XSS, etc.)
    Whitelist (positive security): only allow known-good request shapes
    Hybrid: whitelist structure + blacklist content

  Common WAF Products:
    Cloud:   AWS WAF, Cloudflare WAF, Akamai Kona, Azure Front Door
    Software: ModSecurity + OWASP CRS, Nginx ModSec, IronBee
    Appliance: F5 BIG-IP ASM, Imperva SecureSphere, Barracuda

  OWASP Core Rule Set (CRS):
    The most widely deployed open-source WAF ruleset.
    Protects against OWASP Top 10: SQLi, XSS, CSRF, LFI/RFI, RCE, etc.
    Paranoia levels 1–4: higher = more rules = more false positives.
INFO

    section "WAF Detection Methods for Common Attacks"
    echo
    printf "  ${BOLD}%-22s %-50s${NC}\n" "Attack" "WAF Detection Technique"
    printf "  ${DARK_GRAY}%-22s %-50s${NC}\n" "─────────────────────" "─────────────────────────────────────────────────"
    while IFS='|' read -r attack detection; do
        printf "  ${YELLOW}%-22s${NC} ${MUTED}%s${NC}\n" "$attack" "$detection"
    done << 'TABLE'
SQL Injection|Pattern match: UNION, SELECT, --, ;, 0x, hex encoding
XSS|Tag detection: <script>, onerror=, javascript:, event attrs
Path Traversal|Pattern: ../  %2e%2e%2f  ..%5c decoded normalization
Command Injection|Metacharacter detect: ;|&$`() in params
XXE|XML DOCTYPE external entity detection
File Upload|MIME vs extension mismatch, magic bytes check
CSRF|Token validation, Referer/Origin header check
Request Smuggling|HTTP version inconsistency, duplicate Content-Length
TABLE

    section "WAF Evasion Techniques (for Testing)"
    cat << 'INFO'
  1. Encoding: URL encode, double-encode, Unicode, HTML entity, Base64
  2. Case variation: SeLeCt, uNiOn (for case-insensitive regex rules)
  3. Comment injection: SELECT/**/1 (MySQL), SE/**/LECT (bypass split match)
  4. Whitespace alternatives: tabs, newlines, form-feed instead of spaces
  5. HTTP parameter pollution: id=1&id=SELECT (use depends on backend framework)
  6. Chunked encoding: bypass content-length inspection
  7. Slow requests: slowloris-style to evade timeout-based inspection
  8. Protocol-level: HTTP/2 vs HTTP/1.1 inconsistencies in proxy layers

  Note: Testing WAF bypass on systems you do not own is illegal.
        Use controlled lab environments only.
INFO

    section "ModSecurity Status"
    if cmd_exists apachectl; then
        echo -e "${INFO}Apache ModSecurity:${NC}"
        apachectl -M 2>/dev/null | grep -i "security" | sed 's/^/  /' \
            || echo -e "  ${MUTED}ModSecurity module not loaded in Apache${NC}"
    fi

    if cmd_exists nginx; then
        echo -e "${INFO}Nginx ModSecurity:${NC}"
        nginx -V 2>&1 | grep -i "modsec\|security" | sed 's/^/  /' \
            || echo -e "  ${MUTED}ModSecurity not compiled into Nginx${NC}"
    fi

    [[ ! $(command -v apachectl) && ! $(command -v nginx) ]] && \
        status_line neutral "No web server detected (Apache/Nginx not found)"
}

#  FAIL2BAN & RATE LIMITING
check_fail2ban() {
    header "fail2ban & Automated Blocking"

    cat << 'INFO'
  fail2ban monitors log files and bans IPs that show malicious behaviour.
  Creates iptables/nftables REJECT rules for configured ban period.

  Components:
    Filter   — regex pattern to match in log files
    Action   — what to do on match (ban/unban commands)
    Jail     — filter + action + parameters (maxretry, findtime, bantime)

  Default jails include:
    sshd     — /var/log/auth.log: SSH failures
    apache   — /var/log/apache2/error.log: 401/403 floods
    nginx    — Nginx auth failures
    postfix  — SMTP SASL failures
    recidive — bans repeat offenders for 1 week
INFO

    section "fail2ban Status"
    if cmd_exists fail2ban-client; then
        echo -e "${INFO}fail2ban service status:${NC}"
        if systemctl is-active fail2ban &>/dev/null; then
            status_line ok "fail2ban is running"
            echo
            echo -e "${INFO}Active jails:${NC}"
            sudo fail2ban-client status 2>/dev/null | sed 's/^/  /'
            echo
            echo -e "${INFO}SSH jail details:${NC}"
            sudo fail2ban-client status sshd 2>/dev/null | sed 's/^/  /' \
                || sudo fail2ban-client status ssh 2>/dev/null | sed 's/^/  /' \
                || echo -e "  ${MUTED}SSH jail not configured${NC}"
        else
            status_line neutral "fail2ban is not running"
            echo -e "  ${MUTED}Install/start: sudo apt install fail2ban && sudo systemctl enable --now fail2ban${NC}"
        fi
    else
        status_line neutral "fail2ban not installed"
    fi

    section "Manual Rate Limiting with iptables"
    cat << 'INFO'
  # Limit SSH to 3 new connections per minute (hashlimit module)
  iptables -A INPUT -p tcp --dport 22 -m hashlimit \
    --hashlimit-above 3/min --hashlimit-burst 5 \
    --hashlimit-mode srcip --hashlimit-name ssh_limit -j DROP

  # SYN flood protection (SYN cookies + rate limit)
  iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
  iptables -A INPUT -p tcp --syn -j DROP
  sysctl -w net.ipv4.tcp_syncookies=1

  # Port scan detection (block hosts that probe closed ports)
  iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
  iptables -A INPUT -m recent --name portscan --remove
  iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
INFO

    section "Current Banned IPs"
    echo -e "${INFO}Checking for recent authentication failures in logs:${NC}"
    if [[ -r /var/log/auth.log ]]; then
        echo -e "  ${MUTED}Top offending IPs (SSH failures, last 500 lines):${NC}"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -500 \
            | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -10 \
            | while read -r count ip; do
                printf "  ${FAILURE}%-6s${NC} ${WHITE}%s${NC}\n" "${count}x" "$ip"
            done
        [[ $? -ne 0 ]] && echo -e "  ${MUTED}No failures found${NC}"
    elif [[ -r /var/log/secure ]]; then
        grep "Failed password" /var/log/secure 2>/dev/null | tail -500 \
            | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -10 \
            | while read -r count ip; do
                printf "  ${FAILURE}%-6s${NC} ${WHITE}%s${NC}\n" "${count}x" "$ip"
            done
    else
        echo -e "  ${MUTED}Auth log not readable (requires sudo or journald in use)${NC}"
        echo -e "  ${MUTED}Try: sudo journalctl -u ssh --since today | grep Failed${NC}"
    fi
}

#  FIREWALL HARDENING BEST PRACTICES
check_firewall_hardening() {
    header "Firewall Hardening & Audit"

    section "sysctl Network Hardening Parameters"
    echo
    declare -A sysctl_expected=(
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv4.tcp_timestamps"]="0"
    )

    printf "  ${BOLD}%-44s %-10s %-10s %s${NC}\n" "Parameter" "Current" "Expected" "Status"
    printf "  ${DARK_GRAY}%-44s %-10s %-10s %s${NC}\n" \
        "$(printf '─%.0s' {1..43})" "─────────" "─────────" "──────"

    for param in "${!sysctl_expected[@]}"; do
        local current expected="${sysctl_expected[$param]}"
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        local status_sym status_col
        if [[ "$current" == "$expected" ]]; then
            status_sym="✔" status_col="$SUCCESS"
        else
            status_sym="✘" status_col="$FAILURE"
        fi
        printf "  ${LABEL}%-44s${NC} ${MUTED}%-10s${NC} %-10s ${status_col}%s${NC}\n" \
            "$param" "$current" "$expected" "$status_sym"
    done

    section "Firewall Rule Audit"
    echo -e "${INFO}Checking for overly permissive rules:${NC}"
    echo
    if sudo iptables -L -n 2>/dev/null | grep -q "0.0.0.0/0"; then
        echo -e "  ${WARNING}[~]${NC} Rules with unrestricted source (0.0.0.0/0) detected"
        echo -e "  ${MUTED}     Review: sudo iptables -L -n -v | grep 0.0.0.0${NC}"
    else
        status_line ok "No obvious unrestricted source rules in iptables"
    fi

    echo
    echo -e "${INFO}Open ports vs firewall coverage:${NC}"
    ss -tlnp 2>/dev/null | tail -n +2 | while read -r _ _ _ local _; do
        local port="${local##*:}"
        local allowed
        allowed=$(sudo iptables -L INPUT -n 2>/dev/null | grep -E "dpt:${port}|dpts.*${port}" | head -1)
        if [[ -n "$allowed" ]]; then
            printf "  ${SUCCESS}Port %-6s${NC} firewall rule: ${MUTED}%s${NC}\n" "$port" "$allowed"
        else
            printf "  ${WARNING}Port %-6s${NC} ${WARNING}no explicit INPUT rule found — rely on default policy${NC}\n" "$port"
        fi
    done

    section "Recommended Hardened Baseline Script"
    cat << 'CMDS'
  #!/bin/bash
  # Minimal hardened iptables baseline

  IPT=iptables

  # Flush existing rules
  $IPT -F; $IPT -X; $IPT -Z
  $IPT -t nat -F; $IPT -t mangle -F

  # Default deny
  $IPT -P INPUT   DROP
  $IPT -P FORWARD DROP
  $IPT -P OUTPUT  ACCEPT

  # Allow established sessions and loopback
  $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  $IPT -A INPUT -i lo -j ACCEPT

  # Drop invalid
  $IPT -A INPUT -m state --state INVALID -j DROP

  # Allow ICMP (rate limited)
  $IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT

  # Allow SSH (rate limited)
  $IPT -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
  $IPT -A INPUT -p tcp --dport 22 -m state --state NEW -m recent \
       --update --seconds 60 --hitcount 4 -j DROP
  $IPT -A INPUT -p tcp --dport 22 -j ACCEPT

  # Save rules
  iptables-save > /etc/iptables/rules.v4
CMDS

    pause
}

main() {
    check_firewall_types
    check_iptables
    check_nftables
    check_ufw
    check_ids_ips
    check_waf
    check_fail2ban
    check_firewall_hardening
}

main