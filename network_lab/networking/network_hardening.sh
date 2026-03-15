#!/bin/bash

# /network_lab/networking/network_hardening.sh
# Topic: Network Hardening & Defence in Depth
# Covers: SSH hardening, port knocking, DMZ design, zero trust,
#         network segmentation, VPNs, honeypots, SIEM concepts

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

#  SSH HARDENING
check_ssh_hardening() {
    header "SSH Hardening — Comprehensive Audit"
 
    #  1. PROTOCOL OVERVIEW 
    section "SSH Protocol Overview"
    cat << 'INFO'
  SSH (Secure Shell) — RFC 4251–4256.  Default port 22/TCP.
 
  Protocol layers:
    1. Transport Layer   — key exchange, encryption, MAC, compression
    2. User Auth Layer   — authenticates the client to the server
    3. Connection Layer  — multiplexes the encrypted channel into logical sessions
 
  Key Exchange Algorithms (preference order):
    curve25519-sha256          — ECDH over Curve25519 (RECOMMENDED)
    ecdh-sha2-nistp521/384/256 — NIST curves (acceptable)
    diffie-hellman-group16-sha512 — 4096-bit DH group (safe fallback)
    diffie-hellman-group14-sha256 — 2048-bit (minimum acceptable)
    ⚠ diffie-hellman-group1-sha1  — DEPRECATED (Logjam-vulnerable)
 
  Host Key Algorithms:
    ed25519     — best: compact, fast, timing-attack resistant
    rsa-sha2-512/256 — acceptable (≥4096-bit key strongly recommended)
    ecdsa       — acceptable
    ⚠ dsa       — DEPRECATED (1024-bit max, broken)
    ⚠ ssh-rsa   — SHA-1 signature deprecated in OpenSSH 8.8+
 
  Cipher Suite (NIST/Mozilla Modern profile):
    chacha20-poly1305@openssh.com — preferred (hardware-independent AEAD)
    aes256-gcm@openssh.com        — strong AEAD
    aes128-gcm@openssh.com        — acceptable AEAD
    ⚠ arcfour / 3des-cbc / blowfish — INSECURE, never use
 
  MAC Algorithms (Encrypt-then-MAC only):
    hmac-sha2-512-etm@openssh.com  — preferred
    hmac-sha2-256-etm@openssh.com  — acceptable
    ⚠ hmac-md5 / hmac-sha1         — DEPRECATED
INFO
 
    #  2. sshd_config AUDIT 
    section "sshd_config Security Audit"
 
    local sshd_conf="/etc/ssh/sshd_config"
    local sshd_dir="/etc/ssh/sshd_config.d"
 
    # Build a merged effective config: main file + drop-in directory
    local effective_config
    effective_config=$(mktemp)
    trap 'rm -f "$effective_config"' RETURN
 
    if [[ -r "$sshd_conf" ]]; then
        cat "$sshd_conf" > "$effective_config"
    else
        echo -e "  ${FAILURE}[!] /etc/ssh/sshd_config not readable — run as root for a full audit.${NC}"
    fi
 
    # Include drop-in files (OpenSSH ≥ 8.2 pattern)
    if [[ -d "$sshd_dir" ]]; then
        for dropin in "$sshd_dir"/*.conf; do
            [[ -r "$dropin" ]] && cat "$dropin" >> "$effective_config"
        done
    fi
 
    # Helper: extract the *last* (effective) value for a directive
    # OpenSSH uses last-wins for most directives.
    _sshd_get() {
        local directive="$1"
        grep -iE "^[[:space:]]*${directive}[[:space:]]" "$effective_config" 2>/dev/null \
            | awk '{print $2}' | tail -1
    }
 
    # Directives: [name]="recommended_value|risk_if_wrong|note"
    # Format: recommended | risk_level (critical/high/medium/low) | short note
    declare -A directives=(
        ["PermitRootLogin"]="no|critical|Direct root login allows privilege escalation with no audit trail"
        ["PasswordAuthentication"]="no|critical|Passwords are brute-forceable; require key-based auth"
        ["PubkeyAuthentication"]="yes|critical|Must be enabled when passwords are disabled"
        ["PermitEmptyPasswords"]="no|critical|Empty passwords allow trivial authentication bypass"
        ["ChallengeResponseAuthentication"]="no|high|Can fall back to keyboard-interactive password auth"
        ["KbdInteractiveAuthentication"]="no|high|Newer alias for ChallengeResponseAuthentication"
        ["X11Forwarding"]="no|high|Remote X11 exposes local display; often unnecessary"
        ["AllowAgentForwarding"]="no|medium|Leaked agent socket can be abused on the remote host"
        ["AllowTcpForwarding"]="no|medium|Prevents using SSH as a general-purpose proxy/tunnel"
        ["PermitTunnel"]="no|medium|Disables layer-3 VPN-style tunnelling over SSH"
        ["MaxAuthTries"]="3|medium|Limits brute-force attempts per connection"
        ["LoginGraceTime"]="30|medium|Reduces exposure from half-open unauthenticated sessions"
        ["MaxSessions"]="3|low|Caps multiplexed sessions per connection"
        ["UsePAM"]="yes|low|Required for account/session PAM modules; keep enabled"
        ["PrintLastLog"]="yes|low|Displays last login info — useful for detecting unauthorised access"
        ["Banner"]="\/etc\/issue.net|low|Legal warning banner deters casual attackers"
        ["LogLevel"]="VERBOSE|low|Captures key fingerprints in auth log for forensics"
        ["Protocol"]="2|critical|Protocol 1 is cryptographically broken (never use)"
    )
 
    # Print table header
    echo
    printf "  ${BOLD}${TITLE}%-34s %-18s %-18s %-8s %s${NC}\n" \
        "Directive" "Current" "Recommended" "Risk" "Status"
    printf "  ${DARK_GRAY}%s${NC}\n" \
        "$(printf '%.0s' {1..90})"
 
    local pass_count=0 fail_count=0 unknown_count=0
 
    # Risk colour map
    _risk_colour() {
        case "$1" in
            critical) echo "$FAILURE"  ;;
            high)     echo "$WARNING"  ;;
            medium)   echo "$AMBER"    ;;
            low)      echo "$MUTED"    ;;
            *)        echo "$NC"       ;;
        esac
    }
 
    for directive in $(echo "${!directives[@]}" | tr ' ' '\n' | sort); do
        local meta="${directives[$directive]}"
        local recommended risk note
        IFS='|' read -r recommended risk note <<< "$meta"
 
        local current
        current=$(_sshd_get "$directive")
        current="${current:-[not set]}"
 
        local status_sym status_col risk_col
        risk_col=$(_risk_colour "$risk")
 
        if [[ "$current" == "[not set]" ]]; then
            status_sym="?" ; status_col="$MUTED" ; (( unknown_count++ ))
        elif [[ "${current,,}" == "${recommended,,}" ]]; then
            status_sym="✔" ; status_col="$SUCCESS" ; (( pass_count++ ))
        else
            status_sym="✘" ; status_col="$FAILURE" ; (( fail_count++ ))
        fi
 
        printf "  ${LABEL}%-34s${NC}${MUTED}%-18s${NC}%-18s${risk_col}%-8s${NC}${status_col}%s${NC}\n" \
            "$directive" "$current" "$recommended" "[$risk]" "$status_sym"
    done
 
    echo
    printf "  Summary:  ${SUCCESS}%d passed${NC}  ${FAILURE}%d failed${NC}  ${MUTED}%d not set${NC}\n" \
        "$pass_count" "$fail_count" "$unknown_count"
 
    #  3. SSH PORT CHECK 
    section "SSH Port & Listener Analysis"
 
    local ssh_port
    ssh_port=$(_sshd_get "Port")
    ssh_port="${ssh_port:-22}"
 
    if [[ "$ssh_port" == "22" ]]; then
        echo -e "  ${WARNING}[~] SSH is on default port 22 — consider a non-standard port to reduce noise${NC}"
    else
        echo -e "  ${SUCCESS}[+] SSH is on non-default port ${ssh_port}${NC}"
    fi
 
    echo
    echo -e "  ${LABEL}Active SSH listeners:${NC}"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep -E ":${ssh_port}|:22 " | sed 's/^/    /' \
            || echo -e "  ${MUTED}  (none found with ss)${NC}"
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep -E ":${ssh_port}|:22 " | sed 's/^/    /' \
            || echo -e "  ${MUTED}  (none found with netstat)${NC}"
    else
        echo -e "  ${MUTED}  ss/netstat not available${NC}"
    fi
 
    #  4. KEY MANAGEMENT AUDIT 
    section "SSH Key Management Audit"
 
    echo -e "  ${LABEL}Authorized keys files:${NC}"
    echo
 
    local found_keys=0
    while IFS= read -r keyfile; do
        (( found_keys++ ))
        local owner keycount perms perm_col age_note
        owner=$(stat -c '%U' "$keyfile" 2>/dev/null || echo "unknown")
        keycount=$(grep -cE "^(ssh-|ecdsa-|sk-)" "$keyfile" 2>/dev/null || echo 0)
        perms=$(stat -c '%a' "$keyfile" 2>/dev/null)
 
        # Permissions check: 600 is ideal; 644 tolerable; anything else is a risk
        case "$perms" in
            600) perm_col="$SUCCESS" ;;
            644) perm_col="$WARNING" ;;
            *)   perm_col="$FAILURE" ;;
        esac
 
        # Flag files with keys not owned by the directory's user
        local homedir_user
        homedir_user=$(echo "$keyfile" | cut -d/ -f3)
 
        printf "  ${CYAN}%-48s${NC} owner:${LABEL}%-12s${NC} keys:${GOLD}%-4s${NC} perms:${perm_col}%s${NC}\n" \
            "$keyfile" "$owner" "$keycount" "$perms"
 
        # Warn on insecure permissions
        [[ "$perms" != "600" ]] && \
            echo -e "    ${WARNING}⚠ Permissions $perms on $keyfile — recommend 600${NC}"
 
        # Scan for deprecated key types in the file
        if grep -qE "^ssh-dss " "$keyfile" 2>/dev/null; then
            echo -e "    ${FAILURE}✘ DSA key found — DEPRECATED and insecure${NC}"
        fi
        if grep -qE "^ssh-rsa " "$keyfile" 2>/dev/null; then
            echo -e "    ${WARNING}⚠ RSA key (ssh-rsa) found — verify key size ≥ 4096 bits${NC}"
        fi
    done < <(find /home /root -name "authorized_keys" 2>/dev/null)
 
    [[ $found_keys -eq 0 ]] && echo -e "  ${MUTED}  No authorized_keys files found${NC}"
 
    #  5. HOST KEY FINGERPRINTS 
    echo
    echo -e "  ${LABEL}SSH host key fingerprints:${NC}"
    local hk_found=0
    for keyfile in /etc/ssh/ssh_host_*_key.pub; do
        [[ -f "$keyfile" ]] || continue
        (( hk_found++ ))
        local fp algo
        fp=$(ssh-keygen -lf "$keyfile" 2>/dev/null)
        algo=$(echo "$fp" | awk '{print $NF}' | tr -d '()')
 
        case "${algo,,}" in
            ed25519)      echo -e "  ${SUCCESS}✔${NC}  $fp" ;;
            rsa)
                local bits
                bits=$(echo "$fp" | awk '{print $1}')
                if (( bits >= 4096 )); then
                    echo -e "  ${SUCCESS}✔${NC}  $fp"
                else
                    echo -e "  ${WARNING}⚠${NC}  $fp  ${WARNING}[RSA < 4096 bits — upgrade recommended]${NC}"
                fi
                ;;
            dsa)          echo -e "  ${FAILURE}✘${NC}  $fp  ${FAILURE}[DEPRECATED — remove immediately]${NC}" ;;
            *)            echo -e "  ${INFO}i${NC}  $fp" ;;
        esac
    done
    [[ $hk_found -eq 0 ]] && echo -e "  ${MUTED}  No host public key files found${NC}"
 
    #  6. RUNNING PROCESSES 
    echo
    echo -e "  ${LABEL}Active sshd process(es):${NC}"
    if pgrep -x sshd &>/dev/null; then
        pgrep -a sshd 2>/dev/null | head -5 | while read -r pid cmdline; do
            echo -e "  ${SUCCESS}✔${NC}  PID ${GOLD}${pid}${NC}  ${MUTED}${cmdline}${NC}"
        done
    else
        echo -e "  ${MUTED}  sshd is not currently running${NC}"
    fi
 
    # OpenSSH version info
    local ssh_version
    ssh_version=$(sshd -V 2>&1 | head -1)
    [[ -n "$ssh_version" ]] && echo -e "\n  ${LABEL}Version:${NC}  ${VALUE}${ssh_version}${NC}"
 
    #  7. FAIL2BAN / BRUTE-FORCE PROTECTION 
    section "Brute-Force Protection"
 
    if command -v fail2ban-client &>/dev/null; then
        echo -e "  ${SUCCESS}✔${NC}  fail2ban is installed"
        if fail2ban-client status sshd &>/dev/null; then
            local banned
            banned=$(fail2ban-client status sshd 2>/dev/null \
                | grep "Currently banned" | awk -F: '{print $2}' | xargs)
            echo -e "  ${LABEL}  sshd jail — currently banned IPs:${NC} ${GOLD}${banned:-0}${NC}"
        else
            echo -e "  ${WARNING}⚠${NC}  fail2ban sshd jail is not active — consider enabling it"
        fi
    else
        echo -e "  ${WARNING}⚠${NC}  fail2ban not found — brute-force protection is recommended"
        echo -e "  ${MUTED}  Install: sudo apt install fail2ban${NC}"
    fi
 
    # Check for sshguard as alternative
    if command -v sshguard &>/dev/null; then
        echo -e "  ${SUCCESS}✔${NC}  sshguard is installed (alternative brute-force protection)"
    fi
 
    #  8. RECENT AUTH LOG SCAN 
    section "Recent Authentication Events"
 
    local auth_log=""
    for candidate in /var/log/auth.log /var/log/secure /var/log/audit/audit.log; do
        [[ -r "$candidate" ]] && auth_log="$candidate" && break
    done
 
    if [[ -n "$auth_log" ]]; then
        echo -e "  ${LABEL}Log source:${NC} $auth_log"
        echo
 
        local failed_count
        failed_count=$(grep -c "Failed password\|authentication failure\|FAILED LOGIN" \
            "$auth_log" 2>/dev/null || echo 0)
 
        local accepted_count
        accepted_count=$(grep -c "Accepted publickey\|Accepted password" \
            "$auth_log" 2>/dev/null || echo 0)
 
        local root_attempts
        root_attempts=$(grep -c "Invalid user root\|Failed.*root\|user root" \
            "$auth_log" 2>/dev/null || echo 0)
 
        printf "  ${LABEL}%-30s${NC}${GOLD}%s${NC}\n"  "Failed auth attempts:"   "$failed_count"
        printf "  ${LABEL}%-30s${NC}${SUCCESS}%s${NC}\n" "Successful logins:"    "$accepted_count"
        printf "  ${LABEL}%-30s${NC}${FAILURE}%s${NC}\n" "Attempts targeting root:" "$root_attempts"
 
        # Top attacking IPs (last 500 lines to keep it fast)
        echo
        echo -e "  ${LABEL}Top source IPs (failed auth — last 500 log lines):${NC}"
        tail -500 "$auth_log" 2>/dev/null \
            | grep -E "Failed password|Invalid user" \
            | grep -oP 'from \K[\d.]+' \
            | sort | uniq -c | sort -rn | head -5 \
            | while read -r count ip; do
                printf "    ${FAILURE}%-5s${NC}  ${VALUE}%s${NC}\n" "$count" "$ip"
              done
    else
        echo -e "  ${MUTED}  Auth log not readable — run as root to include this section${NC}"
    fi
 
    #  9. HARDENED BASELINE CONFIG 
    section "Recommended sshd_config Hardened Baseline"
    cat << 'CONF'
  # /etc/ssh/sshd_config — Hardened Baseline (OpenSSH ≥ 8.2)
  # Generated by Networking & Cybersecurity Toolkit
 
  # Network
  Port 22                            # Change to a non-standard port to reduce noise
  ListenAddress 0.0.0.0              # Restrict to specific interface if possible
  AddressFamily inet                 # Force IPv4 only (use 'any' if IPv6 is needed)
 
  # Protocol & host keys
  Protocol 2                         # Protocol 1 is cryptographically broken
  HostKey /etc/ssh/ssh_host_ed25519_key
  HostKey /etc/ssh/ssh_host_rsa_key  # RSA key must be ≥ 4096 bits
 
  # Cryptography — Mozilla Modern profile
  KexAlgorithms    curve25519-sha256,ecdh-sha2-nistp521,diffie-hellman-group16-sha512
  Ciphers          chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs             hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
 
  # Authentication
  PermitRootLogin                  no
  PasswordAuthentication           no
  PubkeyAuthentication             yes
  PermitEmptyPasswords             no
  ChallengeResponseAuthentication  no
  KbdInteractiveAuthentication     no
  AuthenticationMethods            publickey
  MaxAuthTries                     3
  LoginGraceTime                   30
  MaxSessions                      3
 
  # Forwarding (disable unless explicitly required)
  AllowTcpForwarding   no
  AllowAgentForwarding no
  X11Forwarding        no
  PermitTunnel         no
  GatewayPorts         no
 
  # Access control — whitelist only
  # AllowUsers deploy admin          # Uncomment and set to your allowed users
  # AllowGroups sshusers             # Alternative: control via group
 
  # Session management
  ClientAliveInterval  300          # Send keepalive every 5 min
  ClientAliveCountMax  2            # Disconnect after 10 min of inactivity
  TCPKeepAlive         no           # Rely on ClientAlive, not TCP keepalive
 
  # Logging
  LogLevel       VERBOSE            # Logs key fingerprints — essential for forensics
  SyslogFacility AUTH
 
  # Miscellaneous hardening
  UsePAM              yes           # Required for PAM account/session modules
  PrintLastLog        yes           # Show last login on connect
  Banner              /etc/issue.net
  PermitUserEnvironment no          # Prevent env var injection via ~/.ssh/environment
  AcceptEnv           LANG LC_*    # Restrict accepted env vars to locale only
  Compression         no           # Compression before encryption is a security risk
  UseDNS              no           # Speeds up login; avoids DNS-based auth
CONF
 
    echo
    echo -e "  ${AMBER}Post-change verification:${NC}"
    echo -e "  ${MUTED}  1. sudo sshd -t               # Test config for syntax errors${NC}"
    echo -e "  ${MUTED}  2. sudo systemctl reload sshd  # Apply without dropping sessions${NC}"
    echo -e "  ${MUTED}  3. Test from a NEW terminal before closing the current session${NC}"
    echo
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
    ┌┐
    │                 Internet                           │
    └┬┘
                       │
              [Edge Firewall / NGFW]
                       │
    ┌┴┐
    │                   DMZ                              │
    │   Web Servers │ Mail Relay │ DNS Auth │ VPN GW     │
    └┬┘
                       │
              [Internal Firewall]
                       │
    ┌┴┐
    │              Internal Network                      │
    │  ┌┐ ┌┐ ┌┐│
    │  │  Corp LAN│ │  Dev VLAN│ │  Database VLAN       ││
    │  │ VLAN 10  │ │ VLAN 20  │ │  VLAN 30             ││
    │  └┘ └┘ └┘│
    └┘
INFO

    section "VLAN Segmentation Zones"
    echo
    printf "  ${BOLD}%-8s %-18s %-16s %s${NC}\n" "VLAN" "Zone" "Subnet" "Systems"
    printf "  ${DARK_GRAY}%-8s %-18s %-16s %s${NC}\n" "" "" "" ""
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
}

#  VPN TECHNOLOGIES
check_vpn() {
    header "VPN Technologies"

    section "VPN Protocol Comparison"
    echo
    printf "  ${BOLD}%-14s %-8s %-10s %-12s %-10s %s${NC}\n" \
        "Protocol" "Port" "Crypto" "Performance" "NAT-T" "Use Case"
    printf "  ${DARK_GRAY}%-14s %-8s %-10s %-12s %-10s %s${NC}\n" \
        "" "" "" "" "" ""
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

  Honeytoken types:
    Fake credentials/documents/database rows/API keys/DNS entries/canary files
    canarytokens.org — free hosted honeytoken service
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
      date >> "$OUTPUT_DIR/honeypot.log"
      echo "Connection from:" >> "$OUTPUT_DIR/honeypot.log"
      nc -l -p 23 -w 5 2>&1 | tee -a "$OUTPUT_DIR/honeypot.log"
  done &

  # Watch the log
  tail -f "$OUTPUT_DIR/honeypot.log"
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

  Common SIEMs:
    Open source:  Elastic SIEM (ELK), Wazuh, OSSIM, Graylog
    Commercial:   Splunk, IBM QRadar, Microsoft Sentinel, Exabeam
INFO

    section "Log Collection — rsyslog"
    if systemctl is-active rsyslog &>/dev/null; then
        status_line ok "rsyslog is active"
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

    run_check "SYN cookies enabled"      "sysctl -n net.ipv4.tcp_syncookies"       "1"
    run_check "IP forwarding disabled"   "sysctl -n net.ipv4.ip_forward"           "0"
    run_check "RP filter enabled (all)"  "sysctl -n net.ipv4.conf.all.rp_filter"   "1"
    run_check "Source routing disabled"  "sysctl -n net.ipv4.conf.all.accept_source_route" "0"
    run_check "ICMP redirects disabled"  "sysctl -n net.ipv4.conf.all.accept_redirects"    "0"
    run_check "Martians logged"          "sysctl -n net.ipv4.conf.all.log_martians"         "1"
    run_check "Broadcast ping ignored"   "sysctl -n net.ipv4.icmp_echo_ignore_broadcasts"  "1"
    run_check "IPv6 redirects disabled"  "sysctl -n net.ipv6.conf.all.accept_redirects"    "0"

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
    echo -e "  ${DARK_GRAY}$(printf '%.0s' {1..50})${NC}"
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