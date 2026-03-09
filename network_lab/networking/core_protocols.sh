#!/bin/bash

# /network_lab/networking/core_protocols.sh
# Topic: Core Protocols — Interactive Deep-Dive
# Covers: TCP/UDP, HTTP/HTTPS, FTP/SFTP, SMTP/POP3/IMAP, DNS, ICMP

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

check_tcp_udp() {
    header "TCP vs UDP — Transport Layer Protocols"

    echo -e "${BOLD}${WHITE}Conceptual Comparison${NC}"
    printf "\n  ${BOLD}%-32s %-32s${NC}\n" "TCP" "UDP"
    printf "  ${DARK_GRAY}%-32s %-32s${NC}\n" "$(printf '─%.0s' {1..30})" "$(printf '─%.0s' {1..30})"
    local -A tcp=( [mode]="Connection-oriented" [reliable]="Yes (ACK + retransmit)" [order]="Guaranteed" [flow]="Yes" [speed]="Slower" [uses]="HTTP, SSH, FTP, Email" )
    local -A udp=( [mode]="Connectionless" [reliable]="No guarantee" [order]="Not guaranteed" [flow]="No" [speed]="Faster" [uses]="DNS, VoIP, Streaming, Gaming" )
    local fields=(mode reliable order flow speed uses)
    local labels=("Mode" "Reliability" "Ordering" "Flow control" "Speed" "Common uses")
    for i in "${!fields[@]}"; do
        printf "  ${GREEN}%-32s${NC} ${CYAN}%-32s${NC}\n" "${labels[$i]}: ${tcp[${fields[$i]}]}" "${labels[$i]}: ${udp[${fields[$i]}]}"
    done

    echo
    echo -e "${YELLOW}${BOLD}TCP Three-Way Handshake:${NC}"
    echo -e "  ${GREEN}Client${NC}  ──── SYN ────►  ${BLUE}Server${NC}"
    echo -e "  ${GREEN}Client${NC}  ◄── SYN-ACK ──  ${BLUE}Server${NC}"
    echo -e "  ${GREEN}Client${NC}  ──── ACK ────►  ${BLUE}Server${NC}"
    echo -e "  ${MUTED}[Connection Established — data transfer begins]${NC}"

    echo
    echo -e "${YELLOW}${BOLD}TCP Four-Way Teardown:${NC}"
    echo -e "  ${GREEN}Client${NC}  ──── FIN ────►  ${BLUE}Server${NC}"
    echo -e "  ${GREEN}Client${NC}  ◄─── ACK ─────  ${BLUE}Server${NC}"
    echo -e "  ${GREEN}Client${NC}  ◄─── FIN ─────  ${BLUE}Server${NC}"
    echo -e "  ${GREEN}Client${NC}  ──── ACK ────►  ${BLUE}Server${NC}"

    section "Live TCP/UDP Observations"

    echo -e "${INFO}Active TCP connections:${NC}"
    ss -tn 2>/dev/null | head -12 || netstat -tn 2>/dev/null | head -12

    echo
    echo -e "${INFO}Listening TCP ports:${NC}"
    ss -tlnp 2>/dev/null | head -12 || netstat -tlnp 2>/dev/null | head -12

    echo
    echo -e "${INFO}Active UDP sockets:${NC}"
    ss -ulnp 2>/dev/null | head -10 || netstat -ulnp 2>/dev/null | head -10

    echo
    echo -e "${INFO}Socket summary:${NC}"
    ss -s 2>/dev/null

    section "Custom Port Probe"
    read -rp "$(echo -e "  ${PROMPT}Enter host to probe [default: localhost]:${NC} ")" probe_host
    probe_host="${probe_host:-localhost}"
    if is_valid_host "$probe_host" || is_valid_ip "$probe_host"; then
        echo -e "  ${MUTED}Scanning common ports on ${probe_host}...${NC}"
        for port in 21 22 23 25 53 80 110 143 443 3306 3389 5432 8080 8443; do
            if port_open "$probe_host" "$port"; then
                printf "  ${SUCCESS}%-6s OPEN${NC}\n" "$port"
            else
                printf "  ${MUTED}%-6s closed${NC}\n" "$port"
            fi
        done
    else
        log_warning "Invalid host input — skipping probe."
    fi

    header "Advanced TCP State Analysis"

    echo -e "${INFO}TCP connection states:${NC}"
    ss -tan | awk '{print $1}' | sort | uniq -c | sort -nr

    echo
    echo -e "${INFO}Top connections (ESTABLISHED):${NC}"
    ss -tan state established | head -10
}

check_http_protocols() {
    header "HTTP / HTTPS — Web Protocols"

    cat << 'INFO'
  HTTP (Hypertext Transfer Protocol)
    Port    : 80
    Security: Unencrypted — plaintext over the wire
    Methods : GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS

  HTTPS (HTTP over TLS)
    Port    : 443
    Security: TLS 1.2 / 1.3 encrypted
    Features: Certificate authentication, HSTS, ALPN

  HTTP Status Code Groups
    1xx — Informational  (100 Continue, 101 Switching Protocols)
    2xx — Success        (200 OK, 201 Created, 204 No Content)
    3xx — Redirection    (301 Moved, 302 Found, 304 Not Modified)
    4xx — Client Error   (400 Bad Request, 401 Unauth, 403 Forbidden, 404 Not Found)
    5xx — Server Error   (500 Internal, 502 Bad Gateway, 503 Unavailable)
INFO

    section "Local Web Services"
    echo -e "${INFO}Listening on common web ports:${NC}"
    ss -tlnp 2>/dev/null | grep -E ":80 |:443 |:8080 |:8443 |:8888 " \
        || echo -e "  ${MUTED}None detected${NC}"

    section "Live HTTP/HTTPS Probe"
    read -rp "$(echo -e "  ${PROMPT}Enter domain to probe [default: example.com]:${NC} ")" test_domain
    test_domain="${test_domain:-example.com}"
    if ! (is_valid_host "$test_domain" || is_valid_ip "$test_domain"); then
        log_warning "Invalid input — using example.com"
        test_domain="example.com"
    fi

    if cmd_exists curl; then
        echo
        echo -e "${INFO}HTTP response headers for ${test_domain}:${NC}"
        curl -sI --max-time 5 "http://${test_domain}" 2>/dev/null | head -15 \
            || echo -e "  ${MUTED}No response${NC}"

        echo
        echo -e "${INFO}HTTPS response headers for ${test_domain}:${NC}"
        curl -sI --max-time 5 "https://${test_domain}" 2>/dev/null | head -15 \
            || echo -e "  ${MUTED}No response${NC}"

        echo
        echo -e "${INFO}Measuring HTTP response time:${NC}"
        curl -so /dev/null \
            -w "  DNS lookup   : %{time_namelookup}s\n  TCP connect  : %{time_connect}s\n  TLS handshake: %{time_appconnect}s\n  TTFB         : %{time_starttransfer}s\n  Total        : %{time_total}s\n  HTTP status  : %{http_code}\n" \
            --max-time 8 "https://${test_domain}" 2>/dev/null \
            || echo -e "  ${MUTED}Timing unavailable${NC}"
    else
        log_warning "curl not available — skipping live probes"
    fi

    if cmd_exists openssl; then
        echo
        echo -e "${INFO}TLS certificate details for ${test_domain}:${NC}"
        echo | openssl s_client -connect "${test_domain}:443" -servername "$test_domain" 2>/dev/null \
            | openssl x509 -noout -subject -issuer -dates 2>/dev/null \
            || echo -e "  ${MUTED}Could not retrieve certificate${NC}"

        echo
        echo -e "${INFO}Supported TLS versions for ${test_domain}:${NC}"
        for proto in tls1_2 tls1_3; do
            if echo | openssl s_client -connect "${test_domain}:443" \
                    -"$proto" 2>/dev/null | grep -q "Cipher is"; then
                echo -e "  ${SUCCESS}TLS ${proto/tls1_/1.} supported${NC}"
            else
                echo -e "  ${MUTED}TLS ${proto/tls1_/1.} not negotiated${NC}"
            fi
        done
    fi
}

tls_cipher_scan() {
    header "TLS Cipher Strength Check"

    read -rp "Enter domain: " domain

    echo | openssl s_client -connect "$domain:443" 2>/dev/null \
        | grep "Cipher is"
}

http_security_check() {
    header "HTTP Security Header Analysis"

    read -rp "Enter domain: " domain

    local headers
    headers=$(curl -sI "https://$domain")

    for h in \
        "Strict-Transport-Security" \
        "Content-Security-Policy" \
        "X-Frame-Options" \
        "X-XSS-Protection" \
        "X-Content-Type-Options"; do

        if echo "$headers" | grep -qi "$h"; then
            echo -e "${SUCCESS}$h present${NC}"
        else
            echo -e "${WARNING}$h missing${NC}"
        fi
    done
}

check_ftp_protocols() {
    header "FTP / SFTP — File Transfer Protocols"

    cat << 'INFO'
  FTP (File Transfer Protocol)
    Ports   : 20 (data), 21 (control)
    Security: Unencrypted — credentials sent in cleartext
    Modes   : Active (server connects back), Passive (client initiates data)
    Risk    : Eavesdropping, credential theft

  SFTP (SSH File Transfer Protocol)
    Port    : 22 (tunneled over SSH)
    Security: Fully encrypted (session + data)
    Auth    : Password or SSH key pairs
    Note    : Not the same as FTP over SSH (different protocol)

  FTPS (FTP Secure)
    Ports   : 989/990 (explicit/implicit TLS)
    Security: FTP wrapped in TLS

  SCP (Secure Copy)
    Port    : 22
    Security: Encrypted via SSH
INFO

    section "FTP/SFTP/SSH Service Status"

    for port_label in "21:FTP" "22:SSH/SFTP" "989:FTPS-data" "990:FTPS-ctrl"; do
        local port="${port_label%%:*}" label="${port_label##*:}"
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            status_line ok "${label} (port ${port}) — LISTENING"
        else
            status_line neutral "${label} (port ${port}) — not detected"
        fi
    done

    echo
    echo -e "${INFO}SSH server (SFTP capability):${NC}"
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        status_line ok "SSH service is running"
        if [[ -r /etc/ssh/sshd_config ]]; then
            local sftp_line
            sftp_line=$(grep -E "^Subsystem.*sftp" /etc/ssh/sshd_config 2>/dev/null)
            if [[ -n "$sftp_line" ]]; then
                status_line ok "SFTP subsystem: $sftp_line"
            else
                status_line warn "SFTP Subsystem line not found in sshd_config"
            fi
            echo
            echo -e "${INFO}Relevant sshd_config settings:${NC}"
            grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Protocol)" \
                /etc/ssh/sshd_config 2>/dev/null | while read -r line; do
                echo -e "  ${MUTED}$line${NC}"
            done
        fi
    else
        status_line neutral "SSH service not running (SFTP unavailable)"
    fi
}

check_email_protocols() {
    header "Email Protocols — SMTP, POP3, IMAP"

    cat << 'INFO'
  SMTP   — Port 25 (server-to-server), 587 (STARTTLS), 465 (SMTPS)
           Purpose: SENDING mail
           Direction: push (client → server → server)

  POP3   — Port 110 (plain), 995 (SSL)
           Purpose: RECEIVING mail — downloads to device, often deletes from server
           Best for: single-device, offline use

  IMAP   — Port 143 (STARTTLS), 993 (SSL)
           Purpose: RECEIVING mail — keeps mail on server, syncs across devices
           Best for: multi-device, online use

  Email Flow Diagram:
    Sender's MUA → [SMTP:587] → Sender's MTA
        → [SMTP:25] → Recipient's MTA
        ← [IMAP:993 / POP3:995] ← Recipient's MUA
INFO

    section "Mail Service Status"
    echo -e "${INFO}Listening email ports:${NC}"
    local email_ports="25|587|465|110|995|143|993"
    local found=0
    while IFS= read -r line; do
        echo -e "  ${CYAN}$line${NC}"
        found=1
    done < <(ss -tlnp 2>/dev/null | grep -E ":($email_ports) ")
    [[ $found -eq 0 ]] && status_line neutral "No email services detected on standard ports"

    echo
    echo -e "${INFO}Mail Transfer Agent (MTA) process check:${NC}"
    local any_mta=0
    for mta in postfix sendmail exim4 dovecot; do
        if systemctl is-active "$mta" &>/dev/null; then
            status_line ok "${mta} is running"
            any_mta=1
        elif pgrep -x "$mta" &>/dev/null; then
            status_line ok "${mta} running (not systemd)"
            any_mta=1
        fi
    done
    [[ $any_mta -eq 0 ]] && status_line neutral "No common MTA/MDA services detected"

    section "SMTP Banner Grab"
    read -rp "$(echo -e "  ${PROMPT}Enter SMTP server to probe [default: skip]:${NC} ")" smtp_host
    if [[ -n "$smtp_host" ]] && (is_valid_host "$smtp_host" || is_valid_ip "$smtp_host"); then
        echo -e "  ${MUTED}Grabbing SMTP banner from ${smtp_host}:25 ...${NC}"
        timeout 5 bash -c "echo QUIT | nc -w3 '$smtp_host' 25 2>/dev/null" | head -5 \
            || echo -e "  ${MUTED}Could not connect${NC}"
    fi

    header "SMTP Open Relay Test"
    read -rp "SMTP server: " server
    {
        echo "HELO test.com"
        echo "MAIL FROM:<test@test.com>"
        echo "RCPT TO:<test@gmail.com>"
        echo "DATA"
        echo "Test"
        echo "."
        echo "QUIT"
    } | nc "$server" 25
}

check_dns() {
    header "DNS — Domain Name System"

    cat << 'INFO'
  DNS Record Types:
    A      — IPv4 address
    AAAA   — IPv6 address
    CNAME  — Canonical name (alias)
    MX     — Mail exchange server
    TXT    — Arbitrary text (SPF, DKIM, verification)
    NS     — Authoritative name servers
    PTR    — Reverse DNS (IP → name)
    SOA    — Start of Authority (zone info)
    SRV    — Service location (used by SIP, XMPP, etc.)
    CAA    — Certificate Authority Authorization

  Hierarchy:  Root (.) → TLD (.com) → Domain (example.com) → Sub (www)
  Port: 53 UDP (queries) / 53 TCP (zone transfers, large replies)
INFO

    section "Resolver Configuration"
    echo -e "${INFO}Configured nameservers:${NC}"
    grep nameserver /etc/resolv.conf 2>/dev/null | while read -r _ ip; do
        echo -e "  ${CYAN}${ip}${NC}"
    done

    if systemctl is-active systemd-resolved &>/dev/null; then
        status_line ok "systemd-resolved caching resolver is active"
        resolvectl statistics 2>/dev/null | head -8 | sed 's/^/  /'
    elif systemctl is-active dnsmasq &>/dev/null; then
        status_line ok "dnsmasq caching resolver is active"
    else
        status_line neutral "No local caching resolver detected"
    fi

    section "Interactive DNS Lookup"
    read -rp "$(echo -e "  ${PROMPT}Enter domain to query [default: cloudflare.com]:${NC} ")" q_domain
    q_domain="${q_domain:-cloudflare.com}"
    if ! (is_valid_host "$q_domain"); then
        log_warning "Invalid domain — using cloudflare.com"
        q_domain="cloudflare.com"
    fi

    if cmd_exists dig; then
        for rtype in A AAAA MX NS TXT SOA; do
            echo
            echo -e "  ${GOLD}${BOLD}${rtype} records for ${q_domain}:${NC}"
            dig +short "$rtype" "$q_domain" 2>/dev/null \
                | sed 's/^/    /' \
                || echo -e "    ${MUTED}(none)${NC}"
        done

        section "Reverse DNS Lookup"
        read -rp "$(echo -e "  ${PROMPT}Enter IP for reverse lookup [default: 1.1.1.1]:${NC} ")" r_ip
        r_ip="${r_ip:-1.1.1.1}"
        if is_valid_ip "$r_ip"; then
            echo -e "  ${INFO}PTR record for ${r_ip}:${NC}"
            dig +short -x "$r_ip" 2>/dev/null | sed 's/^/    /' || echo -e "    ${MUTED}(none)${NC}"
        else
            log_warning "Invalid IP — skipping"
        fi

        section "DNS Propagation Check"
        read -rp "$(echo -e "  ${PROMPT}Domain to check across resolvers [default: ${q_domain}]:${NC} ")" prop_domain
        prop_domain="${prop_domain:-$q_domain}"
        local resolvers=("8.8.8.8:Google" "1.1.1.1:Cloudflare" "9.9.9.9:Quad9" "208.67.222.222:OpenDNS")
        echo
        for rs in "${resolvers[@]}"; do
            local ip="${rs%%:*}" name="${rs##*:}"
            local result
            result=$(dig +short A "$prop_domain" "@$ip" 2>/dev/null | head -1)
            printf "  ${MUTED}%-14s${NC} ${BOLD}%-12s${NC} → ${CYAN}%s${NC}\n" \
                "$ip" "($name)" "${result:-no answer}"
        done
    else
        log_warning "dig not available — install dnsutils for full DNS queries"
        if cmd_exists nslookup; then
            nslookup "$q_domain" 2>/dev/null | head -10 | sed 's/^/  /'
        fi
    fi

    section "Zone Transfer Attempt (Educational)"
    echo -e "  ${MUTED}Attempting AXFR zone transfer (usually blocked — for learning):${NC}"
    if cmd_exists dig; then
        local ns
        ns=$(dig +short NS "$q_domain" 2>/dev/null | head -1)
        if [[ -n "$ns" ]]; then
            echo -e "  ${MUTED}Using NS: ${ns}${NC}"
            dig AXFR "$q_domain" "@${ns}" 2>/dev/null | head -20 \
                || echo -e "  ${SUCCESS}Transfer refused (expected — server is properly secured)${NC}"
        fi
    fi

    header "DNS Subdomain Enumeration"

    read -rp "Enter domain: " domain

    local wordlist=("www" "mail" "api" "dev" "test" "admin")

    for sub in "${wordlist[@]}"; do
        local full="$sub.$domain"
        if dig +short "$full" | grep -qE '^[0-9]'; then
            echo -e "${SUCCESS}$full exists${NC}"
        else
            echo -e "${MUTED}$full not found${NC}"
        fi
    done
}

check_icmp() {
    header "ICMP — Internet Control Message Protocol"

    cat << 'INFO'
  ICMP is a Network-layer (Layer 3) protocol — no ports.
  Carried directly in IP packets (Protocol 1).

  Key Message Types:
    Type 0  — Echo Reply          (ping response)
    Type 3  — Destination Unreachable
              Code 0: Network unreachable
              Code 1: Host unreachable
              Code 3: Port unreachable
    Type 5  — Redirect
    Type 8  — Echo Request        (ping)
    Type 11 — Time Exceeded       (TTL expired — traceroute)
    Type 12 — Parameter Problem
INFO

    section "Interactive ICMP Tests"
    read -rp "$(echo -e "  ${PROMPT}Enter target host/IP [default: 8.8.8.8]:${NC} ")" icmp_target
    icmp_target="${icmp_target:-8.8.8.8}"
    if ! (is_valid_ip "$icmp_target" || is_valid_host "$icmp_target"); then
        log_warning "Invalid input — using 8.8.8.8"
        icmp_target="8.8.8.8"
    fi

    echo
    echo -e "${INFO}Ping test (5 packets) to ${icmp_target}:${NC}"
    ping -c 5 -i 0.4 "$icmp_target" 2>/dev/null || log_warning "Ping failed or blocked"

    echo
    echo -e "${INFO}Flood ping check (0.2s interval, 10 packets — low rate):${NC}"
    ping -c 10 -i 0.2 -q "$icmp_target" 2>/dev/null \
        | tail -3 || echo -e "  ${MUTED}Unavailable${NC}"

    section "Traceroute Analysis"
    read -rp "$(echo -e "  ${PROMPT}Traceroute target [default: ${icmp_target}]:${NC} ")" tr_target
    tr_target="${tr_target:-$icmp_target}"
    echo -e "  ${INFO}Tracing route to ${tr_target} (max 15 hops):${NC}"
    if cmd_exists traceroute; then
        traceroute -m 15 -w 2 "$tr_target" 2>/dev/null
    elif cmd_exists tracepath; then
        tracepath -n "$tr_target" 2>/dev/null | head -20
    else
        log_warning "traceroute/tracepath not available"
    fi

    section "ICMP System Settings"
    kv "Ignore all pings" "$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null || echo 'N/A')"
    kv "Ignore broadcast pings" "$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null || echo 'N/A')"
    kv "ICMP rate limit (ms)" "$(cat /proc/sys/net/ipv4/icmp_ratelimit 2>/dev/null || echo 'N/A')"
    kv "Rate mask" "$(cat /proc/sys/net/ipv4/icmp_ratemask 2>/dev/null || echo 'N/A')"

    echo
    echo -e "${INFO}ICMP packet counters (/proc/net/snmp):${NC}"
    if [[ -r /proc/net/snmp ]]; then
        paste <(grep "^Icmp:" /proc/net/snmp | head -1 | tr ' ' '\n') \
              <(grep "^Icmp:" /proc/net/snmp | tail -1 | tr ' ' '\n') \
              | tail -n +2 | awk '{printf "  %-28s %s\n", $1, $2}'
    fi

    header "ICMP Anomaly Detection"
    echo -e "${INFO}Monitoring ICMP traffic (5 seconds)...${NC}"
    timeout 5 tcpdump -nn icmp 2>/dev/null | awk '{print $0}' | head -10
    echo
    echo -e "${WARNING}Look for:${NC}"
    echo "  - Large payload sizes"
    echo "  - Repeated echo requests"
    echo "  - Unusual frequency"
}

protocol_traffic_monitor() {
    header "Live Protocol Traffic Monitor"

    timeout 5 tcpdump -nn 2>/dev/null | awk '
    /TCP/ {tcp++}
    /UDP/ {udp++}
    /ICMP/ {icmp++}
    END {
        print "TCP:", tcp
        print "UDP:", udp
        print "ICMP:", icmp
    }'
}

main() {
    check_tcp_udp
    check_http_protocols
    check_ftp_protocols
    check_email_protocols
    check_dns
    check_icmp
    protocol_traffic_monitor
}

main