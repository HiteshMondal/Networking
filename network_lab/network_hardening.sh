#!/bin/bash

# /tools/network_hardening.sh
# Topic: Network Hardening & Defence in Depth
# Covers: SSH hardening, port knocking, DMZ design, zero trust,
#         network segmentation, VPNs, honeypots, SIEM concepts

# Bootstrap
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$_SELF_DIR")"}"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

: "${LOG_DIR:="${PROJECT_ROOT}/logs"}"
: "${OUTPUT_DIR:="${PROJECT_ROOT}/output"}"
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

#  SSH HARDENING
check_ssh_hardening() {
    header "SSH Hardening — Comprehensive Audit"

    section "SSH Protocol Overview"
    cat << 'INFO'
  SSH (Secure Shell) — RFC 4251-4256. Default port 22 (TCP).

  Protocol layers:
    1. Transport Layer  — key exchange, encryption, MAC, compression
    2. User Auth Layer  — authenticates the client to the server
    3. Connection Layer — multiplexes the encrypted channel into sessions

  Key Exchange Algorithms (ordered preference):
    curve25519-sha256 — ECDH, modern (recommended)
    ecdh-sha2-nistp521/384/256 — NIST curves
    diffie-hellman-group16-sha512 — safe DH (4096-bit group)
    diffie-hellman-group14-sha256 — acceptable minimum

  Host Key Types (server identity):
    ed25519 — best: small, fast, resistant to timing attacks
    ecdsa   — acceptable
    rsa-sha2-512/256 — acceptable (4096-bit key recommended)
    dsa     — DEPRECATED (DSS, 1024-bit max)

  Cipher Recommendations (NIST/Mozilla Modern):
    chacha20-poly1305@openssh.com
    aes256-gcm@openssh.com
    aes128-gcm@openssh.com
INFO

    section "sshd_config Security Audit"
    local sshd_conf="/etc/ssh/sshd_config"
    if [[ ! -r "$sshd_conf" ]]; then
        echo -e "  ${MUTED}/etc/ssh/sshd_config not readable (requires sudo or not installed)${NC}"
    else
        echo
        declare -A expected_settings=(
            ["PermitRootLogin"]="no"
            ["PasswordAuthentication"]="no"
            ["PubkeyAuthentication"]="yes"
            ["PermitEmptyPasswords"]="no"
            ["ChallengeResponseAuthentication"]="no"
            ["X11Forwarding"]="no"
            ["MaxAuthTries"]="3"
            ["LoginGraceTime"]="30"
            ["AllowAgentForwarding"]="no"
            ["AllowTcpForwarding"]="no"
            ["Protocol"]="2"
        )

        printf "  ${BOLD}%-32s %-20s %-20s %s${NC}\n" \
            "Directive" "Current" "Recommended" "Status"
        printf "  ${DARK_GRAY}%-32s %-20s %-20s %s${NC}\n" \
            "$(printf '─%.0s' {1..31})" "$(printf '─%.0s' {1..19})" \
            "$(printf '─%.0s' {1..19})" "──────"

        for directive in "${!expected_settings[@]}"; do
            local current recommended="${expected_settings[$directive]}"
            current=$(grep -iE "^${directive}\s" "$sshd_conf" 2>/dev/null \
                | awk '{print $2}' | head -1)
            current="${current:-[not set]}"
            local status_sym status_col
            if [[ "${current,,}" == "${recommended,,}" ]]; then
                status_sym="✔" status_col="$SUCCESS"
            else
                status_sym="✘" status_col="$FAILURE"
            fi
            printf "  ${LABEL}%-32s${NC} ${MUTED}%-20s${NC} %-20s ${status_col}%s${NC}\n" \
                "$directive" "$current" "$recommended" "$status_sym"
        done
    fi

    section "SSH Key Management Audit"
    echo -e "${INFO}Authorized keys files on this system:${NC}"
    find /home /root -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
        local owner keycount
        owner=$(stat -c '%U' "$keyfile" 2>/dev/null || echo "unknown")
        keycount=$(grep -c "^ssh-" "$keyfile" 2>/dev/null || echo 0)
        local perms
        perms=$(stat -c '%a' "$keyfile" 2>/dev/null)
        local perm_col
        [[ "$perms" == "600" || "$perms" == "644" ]] && perm_col="$SUCCESS" || perm_col="$WARNING"
        printf "  ${CYAN}%-45s${NC} owner: ${LABEL}%-12s${NC} keys: ${GOLD}%-3s${NC} perms: ${perm_col}%s${NC}\n" \
            "$keyfile" "$owner" "$keycount" "$perms"
    done

    echo
    echo -e "${INFO}SSH host key fingerprints:${NC}"
    for keyfile in /etc/ssh/ssh_host_*_key.pub; do
        [[ -f "$keyfile" ]] && ssh-keygen -lf "$keyfile" 2>/dev/null | sed 's/^/  /'
    done

    echo
    echo -e "${INFO}Current SSH server processes:${NC}"
    pgrep -a sshd 2>/dev/null | head -5 | sed 's/^/  /' \
        || echo -e "  ${MUTED}sshd not running${NC}"

    section "Recommended sshd_config Hardened Baseline"
    cat << 'CONF'
  # /etc/ssh/sshd_config — Hardened baseline
  Protocol 2
  Port 22                          # Consider changing to non-standard
  ListenAddress 0.0.0.0

  # Authentication
  PermitRootLogin no
  PasswordAuthentication no
  PubkeyAuthentication yes
  PermitEmptyPasswords no
  ChallengeResponseAuthentication no
  AuthenticationMethods publickey
  MaxAuthTries 3
  LoginGraceTime 30s
  MaxSessions 3

  # Cryptography (Mozilla Modern profile)
  KexAlgorithms curve25519-sha256,ecdh-sha2-nistp521
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512

  # Forwarding (disable unless needed)
  AllowTcpForwarding no
  AllowAgentForwarding no
  X11Forwarding no
  PermitTunnel no

  # Access control
  AllowUsers deploy admin          # Whitelist only
  # AllowGroups ssh-users

  # Logging
  LogLevel VERBOSE
  SyslogFacility AUTH

  # Disconnect idle sessions
  ClientAliveInterval 300
  ClientAliveCountMax 2
CONF
}

#  PORT KNOCKING
check_port_knocking() {
    header "Port Knocking & Single Packet Authorization"

    section "Port Knocking"
    cat << 'INFO'
  Port knocking hides services (e.g., SSH) behind a "secret knock" sequence.
  The port is CLOSED (stealth/filtered) until the correct sequence is received.
  The server monitors all connection attempts and opens the port on match.

  Example sequence:  TCP:7000 → TCP:8000 → TCP:9000 → port 22 opens (30s TTL)

  How it works (iptables + knockd):
    1. knockd daemon listens for port probes (via libpcap, no socket open)
    2. Client sends SYN packets to ports 7000, 8000, 9000 (in order)
    3. knockd detects the sequence → runs: iptables -A INPUT -s $IP -p tcp --dport 22 -j ACCEPT
    4. After timeout: iptables -D INPUT (reverts the rule)

  Client tools:
    knock -v host 7000 8000 9000          (knockd client)
    for port in 7000 8000 9000; do
        nmap -Pn --host-timeout 100ms -p $port host; done

  Weakness: replay attacks (if traffic captured); requires timing precision.

  SPA (Single Packet Authorization) — stronger alternative:
    One encrypted UDP packet (via fwknop) contains: timestamp, source IP, HMAC.
    Server decrypts + validates HMAC + checks timestamp (replay window).
    Used in production by many high-security environments.
INFO

    section "knockd Status"
    if cmd_exists knockd || pgrep -x knockd &>/dev/null; then
        status_line ok "knockd is available/running"
        if [[ -r /etc/knockd.conf ]]; then
            echo -e "${INFO}/etc/knockd.conf:${NC}"
            cat /etc/knockd.conf | sed 's/^/  /'
        fi
    else
        status_line neutral "knockd not installed (apt install knockd)"
    fi

    if cmd_exists fwknop || cmd_exists fwknopd; then
        status_line ok "fwknop (SPA) is available"
    fi
}

#  NETWORK SEGMENTATION & DMZ
check_segmentation() {
    header "Network Segmentation & DMZ Architecture"

    section "Segmentation Principles"
    cat << 'INFO'
  Network segmentation divides a network into isolated zones.
  Goal: limit blast radius of a breach (contain lateral movement).

  Defence in Depth — layered controls:
    ┌────────────────────────────────────────────────────┐
    │                 Internet                           │
    └──────────────────┬─────────────────────────────────┘
                       │
              [Edge Firewall / NGFW]
                       │
    ┌──────────────────┴─────────────────────────────────┐
    │                   DMZ                              │
    │   Web Servers │ Mail Relay │ DNS Auth │ VPN GW     │
    └──────────────────┬─────────────────────────────────┘
                       │
              [Internal Firewall]
                       │
    ┌──────────────────┴─────────────────────────────────┐
    │              Internal Network                      │
    │  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐│
    │  │  Corp LAN│ │  Dev VLAN│ │  Database VLAN       ││
    │  │ VLAN 10  │ │ VLAN 20  │ │  VLAN 30             ││
    │  └──────────┘ └──────────┘ └──────────────────────┘│
    └────────────────────────────────────────────────────┘

  DMZ Rules (strict):
    Internet → DMZ:     Only on specific ports (80, 443, 25...)
    DMZ → Internet:     Only response traffic (stateful)
    DMZ → Internal:     Only to specific backend servers + ports
    Internal → DMZ:     Management only (SSH from jump host)
    Internal → Internet: Via proxy; never direct (policy-dependent)
    DMZ ↔ DMZ:          Never (each service isolated)
INFO

    section "VLAN Segmentation Zones"
    echo
    printf "  ${BOLD}%-8s %-18s %-16s %s${NC}\n" "VLAN" "Zone" "Subnet" "Systems"
    printf "  ${DARK_GRAY}%-8s %-18s %-16s %s${NC}\n" "───────" "─────────────────" "───────────────" "────────────────────"
    while IFS='|' read -r vlan zone subnet systems; do
        printf "  ${CYAN}%-8s${NC} ${GOLD}%-18s${NC} ${MUTED}%-16s${NC} %s\n" \
            "$vlan" "$zone" "$subnet" "$systems"
    done << 'TABLE'
VLAN 10|Management|10.0.10.0/24|Switches, APs, OOB, Jump hosts
VLAN 20|Servers|10.0.20.0/24|Application, web, API servers
VLAN 30|Database|10.0.30.0/24|MySQL, PostgreSQL, Redis, MongoDB
VLAN 40|Workstations|10.0.40.0/24|User endpoints
VLAN 50|Guest/IoT|10.0.50.0/24|Untrusted devices (isolated)
VLAN 60|DMZ|10.0.60.0/24|Perimeter-facing services
VLAN 99|OOB (IPMI)|10.0.99.0/24|IPMI/iDRAC/iLO (tightly restricted)
TABLE

    section "Micro-Segmentation"
    cat << 'INFO'
  Micro-segmentation extends firewall policy to the workload level.
  "Never trust, always verify" — even east-west traffic within a zone.

  Implementation approaches:
    Host-based: iptables/nftables rules on each server
    SDN overlay: VMware NSX, Cisco ACI, Open vSwitch with OpenFlow
    Cloud security groups: AWS SG, Azure NSG, GCP VPC Firewall
    Service mesh: Istio/Linkerd (mTLS between microservices)

  Identity-based segmentation (Zero Trust):
    Authenticate workload identity (SPIFFE/SPIRE, certificates)
    Policy = "workload A can talk to workload B on port X"
    Implementation: Hashicorp Consul Connect, Cilium (eBPF)
INFO

    section "Current Segmentation Status"
    echo -e "${INFO}VLANs / bridges on this system:${NC}"
    local has_vlan=0
    ip link show 2>/dev/null | grep "@" | while read -r _ if_at_parent _; do
        local token="${if_at_parent%:}"
        local iface="${token%%@*}" parent="${token##*@}"
        local vid
        vid=$(ip -d link show "${iface}" 2>/dev/null | grep -oP 'id \K[0-9]+' | head -1)
        echo -e "  ${SUCCESS}VLAN interface:${NC} ${iface}  (ID: ${GOLD}${vid:-?}${NC}, parent: ${CYAN}${parent}${NC})"
        has_vlan=1
    done
    for iface in /sys/class/net/*; do
        [[ -d "${iface}/bridge" ]] && echo -e "  ${SUCCESS}Bridge:${NC} $(basename "$iface")"
    done
    [[ $has_vlan -eq 0 ]] && status_line neutral "No VLAN/bridge interfaces — flat network (consider segmentation)"
}

#  ZERO TRUST NETWORKING
check_zero_trust() {
    header "Zero Trust Network Architecture (ZTNA)"

    cat << 'INFO'
  Zero Trust: "Never trust, always verify"
  Coined by John Kindervag (Forrester, 2010). NIST SP 800-207 (2020).

  Core tenets:
    1. Assume breach — act as if the perimeter is already compromised
    2. Verify explicitly — authenticate and authorize every request
    3. Least privilege access — minimal rights, just-in-time access

  Traditional vs Zero Trust:
    Traditional: Trust the network (inside = safe, outside = hostile)
    Zero Trust:  No implicit trust based on network location

  Zero Trust components:
    Identity Provider (IdP):  MFA, SSO, device compliance (Azure AD, Okta)
    Policy Engine:            Evaluates who/what/where/when for each request
    Policy Enforcement Point: Proxy/gateway that enforces the decision
    Device Trust:             MDM attestation, certificate, EDR health check
    Micro-segmentation:       Enforce at workload level (not just perimeter)
    Continuous monitoring:    Re-evaluate trust posture on every access

  Zero Trust Access flow:
    User+Device → [IdP: MFA + Device Posture Check]
               → [Policy Engine: evaluate context]
               → [PEP/Gateway: allow or deny]
               → [Application: minimum access granted]
               → [Monitoring: log + alert + re-evaluate]

  Products:
    Cloudflare Access, Zscaler ZPA, Google BeyondCorp,
    Palo Alto Prisma Access, Okta Identity Engine
INFO

    section "ZTNA Implementation Checklist"
    echo
    local checklist=(
        "Enforce MFA for all users (phishing-resistant: FIDO2/WebAuthn preferred)"
        "Implement device health attestation (EDR + MDM compliance check)"
        "Replace VPN with application-level access proxy (Cloudflare/Zscaler)"
        "Eliminate standing privileges — use just-in-time (JIT) access"
        "Log and monitor all access attempts (centralised SIEM)"
        "Segment network by workload identity, not IP address"
        "Encrypt all internal service-to-service traffic (mTLS)"
        "Apply least-privilege on cloud IAM roles and API access"
        "Continuous re-evaluation — revoke on posture change"
        "Treat every network as untrusted (use HTTPS internally too)"
    )
    for item in "${checklist[@]}"; do
        echo -e "  ${MUTED}○${NC}  ${VALUE}${item}${NC}"
    done

    section "BeyondCorp Reference Architecture"
    cat << 'INFO'
  Google BeyondCorp (2011) — first major ZTNA implementation:
    - Moved from VPN-based to access proxy model
    - Every request authenticated + device verified (no implicit LAN trust)
    - Device inventory database + certificate issuance for enrolled devices
    - Access proxy evaluates: user identity, group, device cert, device state

  Key lesson: Users work from any network equally (office = coffee shop = cloud)
  Eliminated the privileged network — LAN is no more trusted than Internet.
INFO
}

#  VPN TECHNOLOGIES
check_vpn() {
    header "VPN Technologies"

    section "VPN Protocol Comparison"
    echo
    printf "  ${BOLD}%-14s %-8s %-10s %-12s %-10s %s${NC}\n" \
        "Protocol" "Port" "Crypto" "Performance" "NAT-T" "Use Case"
    printf "  ${DARK_GRAY}%-14s %-8s %-10s %-12s %-10s %s${NC}\n" \
        "─────────────" "───────" "─────────" "───────────" "─────────" "──────────────"
    while IFS='|' read -r proto port crypto perf nat use; do
        printf "  ${CYAN}%-14s${NC} ${MUTED}%-8s${NC} %-10s ${GOLD}%-12s${NC} %-10s ${MUTED}%s${NC}\n" \
            "$proto" "$port" "$crypto" "$perf" "$nat" "$use"
    done << 'TABLE'
OpenVPN|UDP1194|AES-GCM|Good|Yes|Remote access,site-site
WireGuard|UDP51820|ChaCha20|Excellent|Yes|Modern all-purpose
IPSec/IKEv2|UDP500/4500|AES-GCM|Excellent|Yes|Enterprise,mobile
L2TP/IPSec|UDP1701|AES|Moderate|Yes|Legacy Windows
PPTP|TCP1723|RC4|Good|Yes|BROKEN-never use
SSTP|TCP443|AES|Good|Yes|Windows,HTTP bypass
GRE|IP/47|None|Fast|No|Tunnel protocol (no encrypt)
TABLE

    section "WireGuard — Modern VPN Deep Dive"
    cat << 'INFO'
  WireGuard (2016) — Linus Torvalds: "a work of art" — merged Linux 5.6 (2020).

  Design principles:
    - Minimal codebase: ~4000 lines (OpenVPN: 70,000+; IPSec: 100,000+)
    - Cryptography: fixed, modern, no negotiation (no downgrade attacks)
    - Stateless: no sessions, no handshakes per connection
    - Silent drop of unauthorized packets (stealth — no response to probes)

  Cryptographic primitives (not configurable — chosen by design):
    Key exchange:   Curve25519 (ECDH)
    Encryption:     ChaCha20
    MAC:            Poly1305
    Hash:           BLAKE2s
    Header MAC:     SipHash24
    KDF:            HKDF

  Roaming: IP change is handled transparently — endpoint updates on first packet.
  Handshake: 1-RTT (initiator → responder → initiator = 3 messages total).
  Cookies: DTLS-style handshake throttling against DoS.
INFO

    section "WireGuard Status & Configuration"
    if cmd_exists wg; then
        echo -e "${INFO}WireGuard interfaces:${NC}"
        sudo wg show all 2>/dev/null | sed 's/^/  /' \
            || echo -e "  ${MUTED}Cannot read (requires sudo) or no interfaces configured${NC}"
    else
        status_line neutral "WireGuard not installed (apt install wireguard)"
    fi

    section "OpenVPN Status"
    if cmd_exists openvpn || systemctl is-active openvpn &>/dev/null; then
        echo -e "${INFO}OpenVPN:${NC}"
        systemctl status openvpn 2>/dev/null | head -8 | sed 's/^/  /'
        ip link show 2>/dev/null | grep "tun\|tap" | sed 's/^/  /'
    else
        status_line neutral "OpenVPN not running"
    fi

    section "IPSec Status"
    for ipsec_cmd in ipsec strongswan; do
        if cmd_exists "$ipsec_cmd" || systemctl is-active "$ipsec_cmd" &>/dev/null; then
            echo -e "${INFO}IPSec (${ipsec_cmd}):${NC}"
            sudo ipsec status 2>/dev/null | head -10 | sed 's/^/  /' \
                || status_line neutral "${ipsec_cmd} installed but not running"
        fi
    done

    section "VPN Tunnel Interfaces"
    echo -e "${INFO}Active tunnel interfaces:${NC}"
    ip link show 2>/dev/null | grep -E "tun|tap|wg|ipsec|vti" | sed 's/^/  /' \
        || echo -e "  ${MUTED}No VPN tunnel interfaces detected${NC}"
}

#  HONEYPOTS
check_honeypots() {
    header "Honeypots & Deception Technology"

    section "Honeypot Types"
    cat << 'INFO'
  A honeypot is a decoy system designed to attract and detect attackers.

  By interaction level:
    Low-interaction:  Emulates services/ports. Simple, low-risk, limited intel.
                      Tools: Honeyd, OpenCanary, Artillery
    Medium-interaction: Partial service emulation. More realistic.
                        Tools: Cowrie (SSH/Telnet), Dionaea (Malware)
    High-interaction: Real systems. Full attack surface; maximum intel.
                      High risk if not properly isolated. Tool: HoneyDrive

  By purpose:
    Production honeypot: Deployed in real networks to detect active attackers
    Research honeypot:   Captures malware, 0-days, attacker TTPs
    Honeytoken:          Fake credential/data that triggers alert if accessed
    Honeypot farm:       Multiple honeypots (Project Honey Pot, Shodan data)

  Honeynets: full network of honeypots + real-looking infrastructure.

  Legal consideration:
    Generally legal to deploy on your own network.
    Entrapment arguments rarely succeed (attackers choose to attack).
    Jurisdiction matters for cross-border attackers.
INFO

    section "Cowrie — SSH Honeypot"
    cat << 'INFO'
  Cowrie emulates an SSH/Telnet server and logs all attacker activity:
    - Username/password attempts (credential intelligence)
    - Commands executed in fake shell
    - Files uploaded/downloaded (malware samples)
    - Full session replay

  Deployment (Docker):
    docker run -p 2222:2222 cowrie/cowrie:latest
    # Or on port 22 (move real SSH to non-standard port first)

  Log analysis:
    tail -f /home/cowrie/var/log/cowrie/cowrie.json | jq .
    jq '.eventid, .username, .password' cowrie.json
INFO

    section "OpenCanary — Lightweight Production Honeypot"
    cat << 'INFO'
  OpenCanary emulates multiple services and alerts on any interaction:
    Services: SSH, HTTP, FTP, Telnet, MySQL, Redis, VNC, RDP, NFS, SMB

  Configuration: /etc/opencanaryd/opencanary.conf
  Alert channels: email, syslog, Slack webhook, TCP

  Excellent for detecting:
    - Lateral movement (internal host hitting honeypot)
    - Port scans
    - Default credential attempts
    - Insider threat reconnaissance
INFO

    section "Honeytokens — Deception in Data"
    cat << 'INFO'
  Honeytokens are fake resources that generate alerts when accessed:

  Types:
    Fake credentials:    AWS keys, passwords in config files (canarytoken.org)
    Fake documents:      PDF/Word with tracking pixel or DNS beacon
    Fake database rows:  "admin@fakeemail.com" → triggers alert on exfiltration
    Fake API keys:       Monitor for usage in third-party APIs
    Fake DNS entries:    Internal hostnames that shouldn't be resolved externally
    Canary files:        Honey files in sensitive directories (audit on open)

  canarytokens.org — free hosted honeytoken service:
    Generates unique URLs, emails, documents with callbacks
    Email/Slack/webhook alert on access
    Tracks IP, User-Agent, geolocation of the attacker
INFO

    section "Honeypot Deployment Check"
    local found_hp=0
    for proc in cowrie opencanaryd honeyd artillery dionaea; do
        if pgrep -x "$proc" &>/dev/null || systemctl is-active "$proc" &>/dev/null; then
            status_line ok "${proc} honeypot is active"
            found_hp=1
        fi
    done
    [[ $found_hp -eq 0 ]] && status_line neutral "No active honeypot processes detected"

    section "Simple Bash Honeypot (Netcat Listener)"
    cat << 'CMDS'
  # Listen on a common attack port, log every connection
  while true; do
      date >> /tmp/honeypot.log
      echo "Connection from:" >> /tmp/honeypot.log
      nc -l -p 23 -w 5 2>&1 | tee -a /tmp/honeypot.log
  done &

  # Watch the log
  tail -f /tmp/honeypot.log
CMDS
}

#  SIEM & LOG MANAGEMENT
check_siem() {
    header "SIEM & Centralised Log Management"

    section "SIEM Architecture"
    cat << 'INFO'
  SIEM (Security Information and Event Management) provides:
    - Log collection and aggregation (all sources)
    - Normalisation (parse diverse log formats into common schema)
    - Correlation (connect events across sources to detect attacks)
    - Alerting (trigger on rule matches, thresholds, anomalies)
    - Forensics (search, timeline, case management)
    - Compliance reporting (PCI-DSS, HIPAA, SOX)

  Data sources:
    Network: Firewall, IDS/IPS, DNS, DHCP, NetFlow, proxy
    Host:    Syslog, Windows Event Log, auditd, application logs
    Identity: AD/LDAP, VPN, MFA
    Cloud:   CloudTrail, Azure Monitor, GCP Cloud Logging

  Common SIEMs:
    Open source:  Elastic SIEM (ELK), Wazuh, OSSIM, Graylog
    Commercial:   Splunk, IBM QRadar, Microsoft Sentinel, Exabeam

  SIEM detection categories:
    Rules-based:    Known attack patterns (SIGMA rules)
    Threshold:      N events in T seconds from source X
    Correlation:    Combine events across multiple sources (kill chain)
    Behavioural:    UEBA (User/Entity Behaviour Analytics) — ML baseline
    Threat intel:   IOC matching (IP, domain, hash from feeds)
INFO

    section "Log Collection — rsyslog"
    if systemctl is-active rsyslog &>/dev/null; then
        status_line ok "rsyslog is active"
        echo -e "${INFO}rsyslog configuration:${NC}"
        grep -v "^#\|^$" /etc/rsyslog.conf 2>/dev/null | head -20 | sed 's/^/  /'
    elif systemctl is-active syslog &>/dev/null; then
        status_line ok "syslog is active"
    else
        status_line neutral "rsyslog not active"
    fi

    section "systemd Journal"
    echo -e "${INFO}Journal disk usage:${NC}"
    journalctl --disk-usage 2>/dev/null | sed 's/^/  /'
    echo
    echo -e "${INFO}Recent security-relevant events:${NC}"
    journalctl -p warning --since "1 hour ago" --no-pager 2>/dev/null \
        | tail -15 | sed 's/^/  /' \
        || echo -e "  ${MUTED}No recent warnings or cannot access journal${NC}"

    section "Key Log Files for Security Monitoring"
    echo
    local logfiles=(
        "/var/log/auth.log:Authentication, sudo, SSH"
        "/var/log/syslog:General system events"
        "/var/log/kern.log:Kernel messages (netfilter drops)"
        "/var/log/fail2ban.log:fail2ban bans"
        "/var/log/apache2/access.log:HTTP requests"
        "/var/log/nginx/access.log:Nginx HTTP requests"
        "/var/log/audit/audit.log:auditd — syscalls, file access"
        "/var/log/ufw.log:UFW firewall denies"
    )
    for entry in "${logfiles[@]}"; do
        local path="${entry%%:*}" desc="${entry##*:}"
        if [[ -f "$path" ]]; then
            local size
            size=$(du -sh "$path" 2>/dev/null | cut -f1)
            printf "  ${SUCCESS}%-40s${NC} ${MUTED}%-12s${NC} %s\n" "$path" "$size" "$desc"
        else
            printf "  ${MUTED}%-40s${NC} not present   %s\n" "$path" "$desc"
        fi
    done

    section "SIGMA Rules — Universal Detection Format"
    cat << 'INFO'
  SIGMA is an open rule format for SIEM-agnostic detections.
  One rule → compiled to Splunk SPL, Elastic KQL, Chronicle YARA-L, etc.

  Example SIGMA rule (SSH brute force):
  ───────────────────────────────────
  title: SSH Brute Force Attempt
  id: 5f873a75-...
  status: stable
  description: Detects multiple failed SSH login attempts
  logsource:
    product: linux
    service: auth
  detection:
    selection:
      eventid: sshd
      message|contains: "Failed password"
    timeframe: 30s
    condition: selection | count() by src_ip > 5
  fields:
    - src_ip
    - username
  level: high
  tags:
    - attack.credential_access
    - attack.t1110.001            # MITRE ATT&CK
  ───────────────────────────────────
  Repository: github.com/SigmaHQ/sigma
INFO

    section "NetFlow / IPFIX Analysis"
    cat << 'INFO'
  NetFlow (Cisco) / IPFIX (IETF RFC 7011) — flow-level traffic records.
  Instead of capturing packets, record metadata per connection:
    src IP, dst IP, src port, dst port, protocol, bytes, packets, timestamps

  Use cases:
    - Long-term traffic trending (SIEM storage efficient)
    - Detect beaconing (regular intervals to same IP)
    - Detect data exfiltration (high outbound bytes)
    - Top talkers, bandwidth accounting
    - Compliance audit trails

  Collector: nfcapd, ntopng, Elastic Beats (packetbeat), Argus
  Analyser:  nfdump, Kibana, Grafana, Splunk NetFlow app

  sFlow: sampling variant — samples 1 in N packets (scalable for 100G).
INFO
}

#  NETWORK HARDENING FINAL CHECKLIST
check_hardening_summary() {
    header "Network Hardening — Summary Audit"

    section "System-wide Security Checks"
    echo

    local checks_pass=0 checks_fail=0

    run_check() {
        local desc="$1" cmd="$2" expected_ok="$3"
        local result
        result=$(eval "$cmd" 2>/dev/null)
        if [[ -n "$result" && "$result" == "$expected_ok" ]] || \
           [[ "$expected_ok" == "*" && -n "$result" ]]; then
            status_line ok "$desc"
            (( checks_pass++ ))
        else
            status_line fail "$desc  ${MUTED}[got: ${result:-empty}]${NC}"
            (( checks_fail++ ))
        fi
    }

    # sysctl checks
    run_check "SYN cookies enabled"      "sysctl -n net.ipv4.tcp_syncookies"       "1"
    run_check "IP forwarding disabled"   "sysctl -n net.ipv4.ip_forward"           "0"
    run_check "RP filter enabled (all)"  "sysctl -n net.ipv4.conf.all.rp_filter"   "1"
    run_check "Source routing disabled"  "sysctl -n net.ipv4.conf.all.accept_source_route" "0"
    run_check "ICMP redirects disabled"  "sysctl -n net.ipv4.conf.all.accept_redirects"    "0"
    run_check "Martians logged"          "sysctl -n net.ipv4.conf.all.log_martians"         "1"
    run_check "Broadcast ping ignored"   "sysctl -n net.ipv4.icmp_echo_ignore_broadcasts"  "1"
    run_check "IPv6 redirects disabled"  "sysctl -n net.ipv6.conf.all.accept_redirects"    "0"

    # SSH checks
    if [[ -r /etc/ssh/sshd_config ]]; then
        local root_login
        root_login=$(grep -iE '^PermitRootLogin\s' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | head -1 | tr '[:upper:]' '[:lower:]')
        if [[ "$root_login" == "no" ]]; then
            status_line ok "SSH: PermitRootLogin = no"
            (( checks_pass++ ))
        else
            status_line fail "SSH: PermitRootLogin = ${root_login:-not set} (should be 'no')"
            (( checks_fail++ ))
        fi

        local pw_auth
        pw_auth=$(grep -iE '^PasswordAuthentication\s' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | head -1 | tr '[:upper:]' '[:lower:]')
        if [[ "$pw_auth" == "no" ]]; then
            status_line ok "SSH: PasswordAuthentication = no (key-only)"
            (( checks_pass++ ))
        else
            status_line warn "SSH: PasswordAuthentication = ${pw_auth:-not set} (consider key-only)"
            (( checks_fail++ ))
        fi
    fi

    # Firewall
    if sudo iptables -L 2>/dev/null | grep -q "DROP\|REJECT"; then
        status_line ok "Firewall: iptables rules with DROP/REJECT detected"
        (( checks_pass++ ))
    elif cmd_exists ufw && sudo ufw status 2>/dev/null | grep -q "active"; then
        status_line ok "Firewall: UFW is active"
        (( checks_pass++ ))
    else
        status_line fail "Firewall: No active firewall detected"
        (( checks_fail++ ))
    fi

    echo
    echo -e "  ${DARK_GRAY}$(printf '─%.0s' {1..50})${NC}"
    printf "  ${SUCCESS}Passed: %-3s${NC}  ${FAILURE}Failed: %-3s${NC}  ${MUTED}Total: %s${NC}\n" \
        "$checks_pass" "$checks_fail" "$(( checks_pass + checks_fail ))"

    pause
}

main() {
    check_ssh_hardening
    check_port_knocking
    check_segmentation
    check_zero_trust
    check_vpn
    check_honeypots
    check_siem
    check_hardening_summary
}

main