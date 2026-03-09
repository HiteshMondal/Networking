#!/bin/bash

# /network_lab/security/firewall_ids.sh
# Topic: Firewalls, IDS/IPS, WAF, fail2ban & Hardening
# Covers: Firewall types, iptables, nftables, UFW, Snort/Suricata/Zeek, WAF, fail2ban

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# FIREWALL TYPES
check_firewall_types() {
    header "Firewall Types — Architecture Overview"

    cat << 'INFO'
  Generation 1 — Packet Filtering (Layer 3/4)
    Inspects IP headers and TCP/UDP ports.
    Stateless — each packet evaluated independently.
    Fast; no TCP state tracking.
    Example: iptables with basic INPUT/OUTPUT rules.

  Generation 2 — Stateful Inspection (Layer 3/4)
    Tracks TCP/UDP/ICMP connection state tables.
    Allows return traffic for established connections automatically.
    Blocks unsolicited inbound packets.
    Example: iptables conntrack, pfSense, Cisco ASA.

  Generation 3 — Application Layer Gateway (Layer 7)
    Inspects payload content; understands protocols (HTTP, FTP, DNS).
    Can block specific URL paths, file types, commands.
    Performs deep packet inspection (DPI).
    Example: Squid proxy, Web Application Firewall (WAF).

  Next-Generation Firewall (NGFW):
    Combines stateful + DPI + application ID + user identity + IPS + TLS inspection.
    Examples: Palo Alto NGFW, Fortinet FortiGate, pfSense + Snort, OPNsense + Suricata.

  Firewall Deployment Positions:
    Perimeter  — between internet and DMZ (north-south traffic)
    Internal   — between network segments (east-west traffic)
    Host-based — on each server/workstation (iptables, UFW, Windows Firewall)
    Cloud      — Security Groups (AWS), NSG (Azure), Firewall Policies (GCP)
INFO

    section "Firewall Software on This System"
    echo
    for fw in iptables ip6tables nftables ufw firewalld pf ipfw; do
        if cmd_exists "$fw"; then
            local ver
            ver=$("$fw" --version 2>/dev/null | head -1 \
                  || "$fw" -V 2>/dev/null | head -1 \
                  || echo "present")
            status_line ok "${fw}  —  ${ver}"
        fi
    done

    echo
    echo -e "${INFO}Active firewall services:${NC}"
    for svc in ufw firewalld iptables nftables; do
        systemctl is-active "$svc" &>/dev/null && \
            echo -e "  ${SUCCESS}${svc} is running${NC}"
    done
}

# IPTABLES
check_iptables() {
    header "iptables — Netfilter Firewall (IPv4)"

    section "iptables Concepts"
    cat << 'INFO'
  Tables (by priority):
    raw    — connection tracking bypass (PREROUTING, OUTPUT)
    mangle — packet modification (all chains)
    nat    — address/port translation (PREROUTING, INPUT, OUTPUT, POSTROUTING)
    filter — packet filtering (INPUT, FORWARD, OUTPUT) — DEFAULT table

  Built-in Chains:
    INPUT      — packets destined for this host
    OUTPUT     — packets originating from this host
    FORWARD    — packets routed through this host
    PREROUTING — before routing decision (nat/mangle)
    POSTROUTING— after routing decision (nat/mangle)

  Targets (what to do with a packet):
    ACCEPT     — allow the packet
    DROP       — silently discard (no response to sender)
    REJECT     — discard + send ICMP/RST error to sender
    LOG        — log to syslog and continue
    RETURN     — return to calling chain
    REDIRECT   — redirect to a local port (NAT table)
    MASQUERADE — dynamic SNAT for outbound traffic (NAT table)
    DNAT       — change destination address (PREROUTING)
    SNAT       — change source address (POSTROUTING)

  Packet flow (simplified):
    Network → PREROUTING → [routing decision] → INPUT (local) / FORWARD (route)
    Local process → OUTPUT → POSTROUTING → Network
INFO

    section "Live iptables Rules"
    echo -e "${INFO}Filter table — INPUT chain:${NC}"
    sudo iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -25 | sed 's/^/  /' \
        || echo -e "  ${MUTED}Cannot read (requires sudo or not installed)${NC}"

    echo
    echo -e "${INFO}Filter table — FORWARD chain:${NC}"
    sudo iptables -L FORWARD -n -v --line-numbers 2>/dev/null | head -15 | sed 's/^/  /'

    echo
    echo -e "${INFO}NAT table:${NC}"
    sudo iptables -t nat -L -n -v 2>/dev/null | head -15 | sed 's/^/  /'

    section "Recommended Hardened Baseline"
    cat << 'CMDS'
  # Flush and set secure defaults
  iptables -F && iptables -X && iptables -Z
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  # Allow loopback
  iptables -A INPUT -i lo -j ACCEPT

  # Allow established/related traffic (stateful)
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Drop invalid packets
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

  # Allow ICMP (ping) — rate-limited
  iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT

  # SSH — restrict to known source if possible
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

  # HTTP / HTTPS
  iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT

  # Log drops before final rule
  iptables -A INPUT -m limit --limit 5/m -j LOG --log-prefix "[iptables DROP] "

  # Persist (Debian/Ubuntu)
  apt install iptables-persistent
  netfilter-persistent save
CMDS

    section "iptables Statistics"
    echo -e "${INFO}Packet counts per chain:${NC}"
    sudo iptables -L -n -v 2>/dev/null | grep "Chain " | sed 's/^/  /'
}

# NFTABLES
check_nftables() {
    header "nftables — Modern Netfilter Replacement"

    section "nftables vs iptables"
    cat << 'INFO'
  nftables replaces iptables/ip6tables/arptables/ebtables with a single tool.
  Available since kernel 3.13 (2014). Default in Debian 10+, Fedora 18+.

  Key differences:
    ✓ Single tool for all protocols (IPv4, IPv6, ARP, bridge)
    ✓ Sets for efficient multi-value matching (no repeated rules)
    ✓ Better performance (rules compiled to bytecode)
    ✓ Maps for direct lookups (verdict map, NAT map)
    ✓ Atomic rule updates (no race conditions during reload)
    ✓ Cleaner syntax; easier to read rulesets

  Concepts:
    Tables    — top-level namespace (family: ip, ip6, inet, arp, bridge, netdev)
    Chains    — sequence of rules (type: filter/nat/route, hook, priority)
    Rules     — match + verdict
    Sets      — named collections of values (IP, port, MAC)
    Maps      — match → action lookup tables
INFO

    section "Live nftables Ruleset"
    if cmd_exists nft; then
        echo -e "${INFO}Current nftables ruleset:${NC}"
        sudo nft list ruleset 2>/dev/null | head -40 | sed 's/^/  /' \
            || echo -e "  ${MUTED}Cannot read (requires sudo)${NC}"

        echo
        echo -e "${INFO}Tables:${NC}"
        sudo nft list tables 2>/dev/null | sed 's/^/  /'
    else
        status_line neutral "nft not installed (apt install nftables)"
    fi

    section "nftables Hardened Baseline"
    cat << 'CONF'
  # /etc/nftables.conf — hardened baseline
  #!/usr/sbin/nft -f

  flush ruleset

  table inet filter {
      set allowed_tcp_dports {
          type inet_service
          elements = { 22, 80, 443 }
      }

      chain input {
          type filter hook input priority 0; policy drop;

          iif "lo" accept
          ct state invalid drop
          ct state { established, related } accept
          ip protocol icmp  limit rate 10/second accept
          ip6 nexthdr icmpv6 limit rate 10/second accept

          tcp dport @allowed_tcp_dports ct state new accept

          limit rate 5/minute log prefix "[nft DROP] "
      }

      chain forward {
          type filter hook forward priority 0; policy drop;
      }

      chain output {
          type filter hook output priority 0; policy accept;
      }
  }
CONF
}

# UFW
check_ufw() {
    header "UFW — Uncomplicated Firewall"

    section "UFW Overview"
    cat << 'INFO'
  UFW is an iptables/nftables frontend aimed at simplicity.
  Primarily for Ubuntu/Debian desktops and servers.
  GUI available: gufw

  Profiles: stored in /etc/ufw/applications.d/
  Default policies: defined in /etc/default/ufw
  Rules:  stored in /etc/ufw/user.rules (IPv4) and user6.rules (IPv6)
INFO

    if ! cmd_exists ufw; then
        status_line neutral "ufw not installed (apt install ufw)"
        return
    fi

    section "UFW Status"
    echo -e "${INFO}UFW status:${NC}"
    sudo ufw status verbose 2>/dev/null | sed 's/^/  /' \
        || echo -e "  ${MUTED}Cannot read (requires sudo)${NC}"

    section "UFW Command Reference"
    cat << 'CMDS'
  sudo ufw enable                        # Enable firewall
  sudo ufw disable                       # Disable (all traffic allowed)
  sudo ufw reset                         # Reset to defaults

  sudo ufw default deny incoming         # Block all inbound by default
  sudo ufw default allow outgoing        # Allow all outbound

  sudo ufw allow 22/tcp                  # Allow SSH
  sudo ufw allow 'Nginx Full'            # Allow HTTP + HTTPS (profile)
  sudo ufw allow from 10.0.0.0/8        # Allow entire subnet
  sudo ufw allow from 192.168.1.0/24 to any port 5432  # PostgreSQL from LAN

  sudo ufw deny 23/tcp                   # Block Telnet
  sudo ufw limit 22/tcp                  # Rate-limit SSH (brute-force protection)

  sudo ufw delete allow 22/tcp           # Remove a rule
  sudo ufw show added                    # Show pending rules

  sudo ufw logging on                    # Enable logging
  sudo ufw logging high                  # Verbose logging level
CMDS

    section "UFW Application Profiles"
    sudo ufw app list 2>/dev/null | sed 's/^/  /'
}

# IDS/IPS
check_ids_ips() {
    header "IDS / IPS — Intrusion Detection & Prevention"

    section "IDS vs IPS"
    cat << 'INFO'
  IDS (Intrusion Detection System):
    Monitors and ALERTS on suspicious activity.
    Passive — does not block traffic.
    Can be network-based (NIDS) or host-based (HIDS).
    False positives → alert fatigue; tune signatures carefully.

  IPS (Intrusion Prevention System):
    Monitors and BLOCKS suspicious activity inline.
    Active — sits in traffic path; can drop packets.
    Higher risk: false positive = blocked legitimate traffic.

  Deployment modes:
    Inline (IPS)   — traffic flows through the sensor
    Tap/span (IDS) — copy of traffic sent to sensor (passive)
    Host-based     — agent on each endpoint (auditd, OSSEC, Wazuh)

  Detection methods:
    Signature-based — match against known attack patterns (low FP, misses 0-day)
    Anomaly-based   — deviate from baseline (catches unknown, higher FP)
    Hybrid          — combines both
INFO

    section "Snort"
    if cmd_exists snort; then
        status_line ok "Snort is installed"
        echo -e "  ${MUTED}Version: $(snort -V 2>&1 | head -3 | tail -1)${NC}"
    else
        status_line neutral "Snort not installed (apt install snort)"
    fi

    section "Suricata"
    if cmd_exists suricata; then
        status_line ok "Suricata is installed"
        local ver
        ver=$(suricata --build-info 2>/dev/null | grep "^Version" | head -1)
        echo -e "  ${MUTED}${ver}${NC}"
        echo
        echo -e "${INFO}Suricata service status:${NC}"
        systemctl status suricata 2>/dev/null | head -6 | sed 's/^/  /'
    else
        status_line neutral "Suricata not installed (apt install suricata)"
    fi

    section "Zeek (formerly Bro)"
    if cmd_exists zeek || cmd_exists bro; then
        local z="${cmd:-zeek}"
        cmd_exists zeek && z=zeek || z=bro
        status_line ok "${z} is installed"
        $z --version 2>/dev/null | head -1 | sed 's/^/  /'
    else
        status_line neutral "Zeek not installed (apt install zeek)"
    fi

    section "OSSEC / Wazuh (HIDS)"
    for agent in wazuh-agent ossec; do
        if pgrep -x "$agent" &>/dev/null || systemctl is-active "$agent" &>/dev/null; then
            status_line ok "${agent} is running"
        fi
    done

    section "auditd — Kernel-level Auditing"
    if systemctl is-active auditd &>/dev/null; then
        status_line ok "auditd is active"
        echo
        echo -e "${INFO}Recent audit events (last 5):${NC}"
        sudo ausearch -m AVC,USER_AUTH,USER_LOGIN 2>/dev/null | tail -15 | sed 's/^/  /' \
            || sudo tail -5 /var/log/audit/audit.log 2>/dev/null | sed 's/^/  /'
        echo
        echo -e "${INFO}Audit rules loaded:${NC}"
        sudo auditctl -l 2>/dev/null | head -10 | sed 's/^/  /'
    else
        status_line neutral "auditd not running (apt install auditd audispd-plugins)"
    fi

    section "Suricata Rule Example"
    cat << 'RULES'
  # Alert on HTTP requests with 'cmd.exe' in URI
  alert http any any -> any any (
      msg:"Possible Windows command injection";
      http.uri; content:"cmd.exe"; nocase;
      classtype:web-application-attack;
      sid:1000001; rev:1;
  )

  # Alert on SSH brute-force (>5 attempts/60s)
  alert tcp any any -> $HOME_NET 22 (
      msg:"SSH brute-force attempt";
      flow:to_server;
      threshold: type threshold, track by_src, count 5, seconds 60;
      classtype:attempted-admin;
      sid:1000002; rev:1;
  )
RULES
}

# WAF
check_waf() {
    header "WAF — Web Application Firewall"

    section "WAF Overview"
    cat << 'INFO'
  A WAF protects web applications by inspecting HTTP/HTTPS traffic.
  Operates at Layer 7 — understands web protocol semantics.

  OWASP Top 10 attacks WAFs protect against:
    A01 Broken Access Control   — path traversal attempts
    A03 Injection               — SQLi, XSS, command injection
    A05 Security Misconfiguration— default files, debug endpoints
    A07 Auth & Session Failures — credential stuffing detection
    A10 SSRF                    — internal resource access blocking

  Deployment modes:
    Reverse proxy  — WAF sits in front (recommended; can decrypt TLS)
    Transparent    — layer 2 bridge (no IP change)
    Out-of-band    — traffic mirrored; alerts only (no blocking)
    Agent-based    — module in web server (mod_security/NGINX module)

  Popular WAFs:
    Open source: ModSecurity + OWASP CRS, Coraza, OpenResty+resty-waf
    Cloud:       Cloudflare WAF, AWS WAF, Google Cloud Armor, Akamai Kona
    Commercial:  F5 Advanced WAF, Imperva App Protect, Fortiweb
INFO

    section "ModSecurity Status"
    if cmd_exists modsec_sdbm_util 2>/dev/null || \
       apachectl -M 2>/dev/null | grep -q "security2" || \
       nginx -T 2>/dev/null | grep -q "modsecurity"; then
        status_line ok "ModSecurity is loaded"
    else
        status_line neutral "ModSecurity not detected"
    fi

    echo
    echo -e "${INFO}mod_security config:${NC}"
    for f in /etc/modsecurity/modsecurity.conf \
              /etc/apache2/mods-enabled/security2.conf; do
        [[ -f "$f" ]] && head -5 "$f" 2>/dev/null | sed 's/^/  /'
    done

    section "OWASP CRS Detection Rules (Concepts)"
    cat << 'INFO'
  OWASP Core Rule Set (CRS) — paranoia levels 1–4:

  Request Anomaly Score system:
    Each rule match adds to anomaly score.
    Total score exceeds threshold → block/log.
    Paranoia 1: common attacks (low FP), Paranoia 4: very strict (high FP).

  Sample rule categories:
    REQUEST-920: Protocol Enforcement
    REQUEST-930: Local File Inclusion (LFI)
    REQUEST-931: Remote File Inclusion (RFI)
    REQUEST-932: Remote Code Execution
    REQUEST-933: PHP injection
    REQUEST-941: Cross-Site Scripting (XSS)
    REQUEST-942: SQL Injection
    REQUEST-944: Java Application Attacks
INFO

    section "Common SQL Injection Patterns WAFs Block"
    cat << 'INFO'
  ' OR '1'='1                    -- Classic tautology bypass
  ' UNION SELECT NULL--           -- UNION-based extraction
  1; DROP TABLE users--           -- Stacked queries
  '; WAITFOR DELAY '0:0:5'--     -- Time-based blind
  admin'--                        -- Comment-out password check
  ' OR SLEEP(5)#                  -- MySQL time-based blind
INFO
}

# FAIL2BAN
check_fail2ban() {
    header "fail2ban — Brute-Force Protection"

    section "How fail2ban Works"
    cat << 'INFO'
  fail2ban monitors log files for patterns (failed auth attempts).
  On threshold breach: runs an action (usually iptables/nftables ban).
  After bantime expires: unbans automatically (or permanent with bantime=-1).

  Architecture:
    fail2ban-server   — daemon; reads config, watches logs via pyinotify
    fail2ban-client   — CLI to query/control the server

  Config hierarchy (each overrides the previous):
    /etc/fail2ban/fail2ban.conf    — base config
    /etc/fail2ban/jail.conf        — default jail definitions
    /etc/fail2ban/jail.local       — YOUR overrides (create this!)
    /etc/fail2ban/jail.d/*.conf    — per-jail overrides

  Key settings per jail:
    enabled   = true
    port      = ssh
    logpath   = /var/log/auth.log
    maxretry  = 5                # failures before ban
    findtime  = 600              # window (seconds)
    bantime   = 3600             # ban duration (seconds), -1 = permanent
    ignoreip  = 127.0.0.1/8 ::1 # never ban these
INFO

    if ! cmd_exists fail2ban-client; then
        status_line neutral "fail2ban not installed (apt install fail2ban)"
        return
    fi

    section "fail2ban Status"
    echo -e "${INFO}Service status:${NC}"
    systemctl status fail2ban 2>/dev/null | head -6 | sed 's/^/  /' \
        || pgrep -a fail2ban 2>/dev/null | sed 's/^/  /'

    echo
    echo -e "${INFO}All jails:${NC}"
    sudo fail2ban-client status 2>/dev/null | sed 's/^/  /'

    echo
    echo -e "${INFO}SSH jail detail:${NC}"
    sudo fail2ban-client status sshd 2>/dev/null | sed 's/^/  /' \
        || sudo fail2ban-client status ssh 2>/dev/null | sed 's/^/  /'

    section "Recommended jail.local"
    cat << 'CONF'
  # /etc/fail2ban/jail.local
  [DEFAULT]
  bantime  = 3600
  findtime = 600
  maxretry = 5
  ignoreip = 127.0.0.1/8 ::1

  banaction = iptables-multiport
  action    = %(action_mwl)s      # ban + log + send email (if configured)

  [sshd]
  enabled  = true
  port     = ssh
  logpath  = %(sshd_log)s
  maxretry = 3
  bantime  = 86400

  [nginx-http-auth]
  enabled  = true
  logpath  = /var/log/nginx/error.log

  [apache-auth]
  enabled  = true
  logpath  = /var/log/apache2/error.log
CONF
}

# FIREWALL HARDENING
check_firewall_hardening() {
    header "Comprehensive Firewall Hardening Audit"

    section "Kernel Network Security Parameters"
    echo
    declare -A kernel_checks=(
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["kernel.randomize_va_space"]="2"
    )

    printf "  ${BOLD}%-45s %-10s %-10s %s${NC}\n" \
        "Parameter" "Current" "Expected" "Status"
    printf "  ${DARK_GRAY}%-45s %-10s %-10s %s${NC}\n" \
        "$(printf '─%.0s' {1..44})" "─────────" "─────────" "──────"

    local pass=0 fail=0
    for param in "${!kernel_checks[@]}"; do
        local current expected="${kernel_checks[$param]}"
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        local color sym
        if [[ "$current" == "$expected" ]]; then
            color="$SUCCESS" sym="✔" ; (( pass++ ))
        else
            color="$FAILURE" sym="✘" ; (( fail++ ))
        fi
        printf "  ${LABEL}%-45s${NC} ${MUTED}%-10s${NC} %-10s ${color}%s${NC}\n" \
            "$param" "$current" "$expected" "$sym"
    done

    echo
    printf "  ${SUCCESS}Passed: %-3s${NC}  ${FAILURE}Failed: %-3s${NC}  Total: %s\n" \
        "$pass" "$fail" "$(( pass + fail ))"

    section "Open Listening Ports"
    echo -e "${INFO}All listening TCP/UDP ports:${NC}"
    ss -tlunp 2>/dev/null | tail -n +2 | while read -r proto _ _ local _ process; do
        local port="${local##*:}"
        local color="$MUTED"
        case "$port" in
            22|80|443) color="$SUCCESS" ;;
            23|21|25)  color="$WARNING" ;;
            3389|5900) color="$FAILURE" ;;
        esac
        printf "  ${color}%-8s${NC} ${CYAN}%-30s${NC} %s\n" "$proto" "$local" "${process:-}"
    done

    section "Connection State Summary"
    ss -tan 2>/dev/null | awk 'NR>1{print $1}' | sort | uniq -c | sort -rn | \
        while read -r count state; do
            printf "  ${CYAN}%-6s${NC} ${LABEL}%s${NC}\n" "$count" "$state"
        done
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