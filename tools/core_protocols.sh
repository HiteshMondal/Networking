#!/bin/bash

# /tools/core_protocols.sh
# Topic: Core Protocols
# - TCP vs UDP
# - HTTP / HTTPS
# - FTP / SFTP
# - SMTP, POP3, IMAP
# - DNS (records: A, AAAA, CNAME, MX, TXT)
# - ICMP (ping, traceroute)

header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  $1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

section() {
    echo -e "\n${YELLOW}▶ $1${NC}"
    echo "─────────────────────────────────────────────────────"
}

# TCP vs UDP
check_tcp_udp() {
    header "1. TCP vs UDP - Transport Layer Protocols"
    
    echo -e "${GREEN}Comparing TCP and UDP:${NC}\n"
    
    echo "TCP (Transmission Control Protocol):"
    echo "  • Connection-oriented (3-way handshake)"
    echo "  • Reliable delivery (acknowledgments, retransmission)"
    echo "  • Ordered delivery (packets arrive in sequence)"
    echo "  • Flow control & congestion control"
    echo "  • Error checking"
    echo "  • Slower, more overhead"
    echo "  • Use cases: HTTP, HTTPS, FTP, SSH, Email"
    
    echo ""
    echo "UDP (User Datagram Protocol):"
    echo "  • Connectionless (no handshake)"
    echo "  • Unreliable (no delivery guarantee)"
    echo "  • No ordering guarantee"
    echo "  • No flow control"
    echo "  • Minimal error checking"
    echo "  • Faster, less overhead"
    echo "  • Use cases: DNS, VoIP, Video streaming, Gaming"
    
    echo ""
    echo "TCP Three-Way Handshake:"
    echo "  1. SYN     →  Client to Server"
    echo "  2. SYN-ACK ←  Server to Client"
    echo "  3. ACK     →  Client to Server"
    echo "  [Connection Established]"
    
    section "TCP and UDP connections on this system"
    
    echo -e "${BLUE}Active TCP connections:${NC}"
    ss -tn 2>/dev/null | head -15 || netstat -tn 2>/dev/null | head -15
    
    echo -e "\n${BLUE}Listening TCP ports:${NC}"
    ss -tln 2>/dev/null | head -10 || netstat -tln 2>/dev/null | head -10
    
    echo -e "\n${BLUE}Active UDP sockets:${NC}"
    ss -un 2>/dev/null | head -10 || netstat -un 2>/dev/null | head -10
    
    echo -e "\n${BLUE}TCP/UDP statistics:${NC}"
    ss -s 2>/dev/null || netstat -s 2>/dev/null | grep -A 10 "Tcp:\|Udp:"
}

# HTTP / HTTPS
check_http_protocols() {
    header "2. HTTP / HTTPS - Web Protocols"
    
    echo -e "${GREEN}Understanding HTTP and HTTPS:${NC}\n"
    
    echo "HTTP (Hypertext Transfer Protocol):"
    echo "  • Port: 80"
    echo "  • Stateless request/response protocol"
    echo "  • Methods: GET, POST, PUT, DELETE, HEAD, etc."
    echo "  • Unencrypted - visible to eavesdroppers"
    echo "  • Text-based protocol"
    
    echo ""
    echo "HTTPS (HTTP Secure):"
    echo "  • Port: 443"
    echo "  • HTTP over TLS/SSL encryption"
    echo "  • Encrypts data in transit"
    echo "  • Certificate-based authentication"
    echo "  • Essential for sensitive data"
    
    echo ""
    echo "HTTP Request Methods:"
    echo "  GET     - Retrieve data"
    echo "  POST    - Submit data"
    echo "  PUT     - Update/replace data"
    echo "  DELETE  - Remove data"
    echo "  HEAD    - Get headers only"
    echo "  PATCH   - Partial update"
    
    section "Testing HTTP/HTTPS"
    
    echo -e "${BLUE}Checking for listening web servers:${NC}"
    ss -tln 2>/dev/null | grep -E ":80 |:443 |:8080 " || netstat -tln 2>/dev/null | grep -E ":80 |:443 |:8080 "
    
    echo -e "\n${BLUE}Making HTTP request (example.com):${NC}"
    if command -v curl &> /dev/null; then
        echo "HTTP response headers:"
        curl -sI http://example.com 2>/dev/null | head -10
    else
        echo "curl not available"
    fi
    
    echo -e "\n${BLUE}Making HTTPS request (example.com):${NC}"
    if command -v curl &> /dev/null; then
        echo "HTTPS response with TLS info:"
        curl -sI https://example.com 2>/dev/null | head -5
        echo ""
        echo "TLS/SSL certificate info:"
        echo | openssl s_client -connect example.com:443 2>/dev/null | grep -E "subject=|issuer=" || echo "OpenSSL not available"
    else
        echo "curl not available"
    fi
}

# FTP / SFTP
check_ftp_protocols() {
    header "3. FTP / SFTP - File Transfer Protocols"
    
    echo -e "${GREEN}Understanding file transfer protocols:${NC}\n"
    
    echo "FTP (File Transfer Protocol):"
    echo "  • Ports: 20 (data), 21 (control)"
    echo "  • Unencrypted file transfer"
    echo "  • Active vs Passive modes"
    echo "  • Authentication with username/password"
    echo "  • Security risk - transmits credentials in clear text"
    
    echo ""
    echo "SFTP (SSH File Transfer Protocol):"
    echo "  • Port: 22 (over SSH)"
    echo "  • Encrypted file transfer"
    echo "  • Part of SSH protocol suite"
    echo "  • Secure authentication"
    echo "  • Preferred over FTP"
    
    echo ""
    echo "Other secure alternatives:"
    echo "  • FTPS (FTP over SSL/TLS) - Ports 989/990"
    echo "  • SCP (Secure Copy) - Port 22"
    
    section "FTP/SFTP services on this system"
    
    echo -e "${BLUE}Checking for FTP/SFTP listeners:${NC}"
    if ss -tln 2>/dev/null | grep -E ":21 |:22 |:989 |:990 "; then
        ss -tln 2>/dev/null | grep -E ":21 |:22 |:989 |:990 "
    else
        echo "No FTP/SFTP services detected on standard ports"
    fi
    
    echo -e "\n${BLUE}SSH server status (SFTP capability):${NC}"
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        echo "  ✓ SSH server is running (SFTP available)"
        if [[ -f /etc/ssh/sshd_config ]]; then
            grep -E "^Subsystem.*sftp" /etc/ssh/sshd_config 2>/dev/null || echo "  SFTP subsystem configuration not found"
        fi
    else
        echo "  ✗ SSH server not running"
    fi
}

# SMTP, POP3, IMAP
check_email_protocols() {
    header "4. Email Protocols - SMTP, POP3, IMAP"
    
    echo -e "${GREEN}Understanding email protocols:${NC}\n"
    
    echo "SMTP (Simple Mail Transfer Protocol):"
    echo "  • Port: 25 (unencrypted), 587 (STARTTLS), 465 (SSL/TLS)"
    echo "  • Purpose: SENDING email"
    echo "  • Mail Transfer Agent (MTA) protocol"
    echo "  • Push protocol (client to server)"
    echo "  • Used by email clients and servers"
    
    echo ""
    echo "POP3 (Post Office Protocol v3):"
    echo "  • Port: 110 (unencrypted), 995 (SSL/TLS)"
    echo "  • Purpose: RECEIVING email"
    echo "  • Downloads emails to local device"
    echo "  • Typically deletes from server after download"
    echo "  • Simple, but no synchronization"
    echo "  • Good for single device access"
    
    echo ""
    echo "IMAP (Internet Message Access Protocol):"
    echo "  • Port: 143 (unencrypted), 993 (SSL/TLS)"
    echo "  • Purpose: RECEIVING email"
    echo "  • Keeps emails on server"
    echo "  • Synchronizes across multiple devices"
    echo "  • Supports folders and server-side search"
    echo "  • Preferred for modern email access"
    
    echo ""
    echo "Email Flow:"
    echo "  [Sender] --SMTP→ [Mail Server] --SMTP→ [Recipient Server]"
    echo "                                         ↓"
    echo "                          [Recipient] ←POP3/IMAP--"
    
    section "Email services on this system"
    
    echo -e "${BLUE}Checking for email service listeners:${NC}"
    if ss -tln 2>/dev/null | grep -E ":25 |:587 |:465 |:110 |:995 |:143 |:993 "; then
        ss -tln 2>/dev/null | grep -E ":25 |:587 |:465 |:110 |:995 |:143 |:993 "
    else
        echo "No email services detected on standard ports"
    fi
    
    echo -e "\n${BLUE}Mail Transfer Agent (MTA) status:${NC}"
    for mta in postfix sendmail exim4; do
        if systemctl is-active $mta &>/dev/null; then
            echo "  ✓ $mta is running"
        fi
    done
    
    if ! systemctl is-active postfix &>/dev/null && \
       ! systemctl is-active sendmail &>/dev/null && \
       ! systemctl is-active exim4 &>/dev/null; then
        echo "  ○ No common MTA services running"
    fi
}

# DNS (Domain Name System)
check_dns() {
    header "5. DNS - Domain Name System"
    
    echo -e "${GREEN}Understanding DNS and Record Types:${NC}\n"
    
    echo "DNS Purpose:"
    echo "  • Translates domain names to IP addresses"
    echo "  • Distributed, hierarchical database"
    echo "  • Port: 53 (UDP for queries, TCP for zone transfers)"
    
    echo ""
    echo "DNS Record Types:"
    echo "  A      - Maps domain to IPv4 address"
    echo "  AAAA   - Maps domain to IPv6 address"
    echo "  CNAME  - Canonical name (alias to another domain)"
    echo "  MX     - Mail exchange (email server)"
    echo "  TXT    - Text records (SPF, DKIM, verification)"
    echo "  NS     - Name server (authoritative servers)"
    echo "  PTR    - Pointer (reverse DNS, IP to domain)"
    echo "  SOA    - Start of Authority (zone information)"
    
    section "DNS configuration on this system"
    
    echo -e "${BLUE}DNS resolvers configured:${NC}"
    cat /etc/resolv.conf 2>/dev/null | grep nameserver
    
    echo -e "\n${BLUE}Testing DNS record types:${NC}"
    
    test_domain="google.com"
    
    echo -e "\n${MAGENTA}A Record (IPv4):${NC}"
    if command -v dig &> /dev/null; then
        dig +short A $test_domain 2>/dev/null | head -3
    elif command -v nslookup &> /dev/null; then
        nslookup $test_domain 2>/dev/null | grep "Address:" | tail -n +2 | head -3
    else
        echo "dig/nslookup not available"
    fi
    
    echo -e "\n${MAGENTA}AAAA Record (IPv6):${NC}"
    if command -v dig &> /dev/null; then
        dig +short AAAA $test_domain 2>/dev/null | head -3
    else
        echo "dig not available"
    fi
    
    echo -e "\n${MAGENTA}MX Record (Mail servers):${NC}"
    if command -v dig &> /dev/null; then
        dig +short MX $test_domain 2>/dev/null | head -5
    elif command -v nslookup &> /dev/null; then
        nslookup -type=MX $test_domain 2>/dev/null | grep "mail exchanger"
    else
        echo "dig/nslookup not available"
    fi
    
    echo -e "\n${MAGENTA}TXT Record:${NC}"
    if command -v dig &> /dev/null; then
        dig +short TXT $test_domain 2>/dev/null | head -3
    else
        echo "dig not available"
    fi
    
    echo -e "\n${MAGENTA}NS Record (Name servers):${NC}"
    if command -v dig &> /dev/null; then
        dig +short NS $test_domain 2>/dev/null | head -5
    else
        echo "dig not available"
    fi
    
    echo -e "\n${BLUE}DNS query demonstration:${NC}"
    if command -v dig &> /dev/null; then
        echo "Full DNS query for $test_domain:"
        dig $test_domain 2>/dev/null | head -20
    fi
    
    section "DNS caching"
    
    echo -e "${BLUE}Local DNS cache status:${NC}"
    if systemctl is-active systemd-resolved &>/dev/null; then
        echo "  ✓ systemd-resolved is running (local DNS cache)"
        resolvectl statistics 2>/dev/null | head -10 || echo "  Statistics not available"
    elif systemctl is-active dnsmasq &>/dev/null; then
        echo "  ✓ dnsmasq is running (local DNS cache)"
    else
        echo "  ○ No local DNS caching service detected"
    fi
}

# ICMP (ping, traceroute)
check_icmp() {
    header "6. ICMP - Internet Control Message Protocol"
    
    echo -e "${GREEN}Understanding ICMP:${NC}\n"
    
    echo "ICMP Purpose:"
    echo "  • Network diagnostic and error reporting"
    echo "  • Part of Internet Layer (Layer 3)"
    echo "  • Does not use ports (it's not a transport protocol)"
    echo "  • Carried directly in IP packets"
    
    echo ""
    echo "Common ICMP Message Types:"
    echo "  Type 0  - Echo Reply (ping response)"
    echo "  Type 3  - Destination Unreachable"
    echo "  Type 5  - Redirect"
    echo "  Type 8  - Echo Request (ping)"
    echo "  Type 11 - Time Exceeded (TTL expired, used in traceroute)"
    
    echo ""
    echo "ICMP Tools:"
    echo "  ping       - Tests reachability (Echo Request/Reply)"
    echo "  traceroute - Traces packet path (uses TTL expiration)"
    echo "  pathping   - Combines ping and traceroute"
    
    section "ICMP demonstrations"
    
    echo -e "${BLUE}Ping test (ICMP Echo):${NC}"
    echo "Pinging 8.8.8.8 (Google DNS):"
    ping -c 4 -W 2 8.8.8.8 2>/dev/null || echo "Ping failed or not available"
    
    echo -e "\n${BLUE}Ping with statistics:${NC}"
    ping -c 5 -i 0.5 1.1.1.1 2>/dev/null | tail -5 || echo "Ping failed"
    
    echo -e "\n${BLUE}Traceroute (ICMP Time Exceeded):${NC}"
    echo "Tracing route to google.com (max 10 hops):"
    traceroute -m 10 -w 2 google.com 2>/dev/null | head -12 || echo "Traceroute not available"
    
    echo -e "\n${BLUE}ICMP statistics on this system:${NC}"
    if [[ -f /proc/net/snmp ]]; then
        echo "ICMP packet counts:"
        cat /proc/net/snmp 2>/dev/null | grep "Icmp:" | head -2
    fi
    
    section "ICMP security considerations"
    
    echo -e "${BLUE}Checking ICMP settings:${NC}"
    if [[ -f /proc/sys/net/ipv4/icmp_echo_ignore_all ]]; then
        ignore_ping=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all)
        if [[ $ignore_ping -eq 0 ]]; then
            echo "  ○ ICMP Echo (ping) responses: ENABLED"
        else
            echo "  ✓ ICMP Echo (ping) responses: DISABLED (security)"
        fi
    fi
    
    if [[ -f /proc/sys/net/ipv4/icmp_ratelimit ]]; then
        rate=$(cat /proc/sys/net/ipv4/icmp_ratelimit)
        echo "  ICMP rate limit: $rate ms"
    fi
}

# MAIN EXECUTION
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                   CORE PROTOCOLS CHECKER                         ║
║                                                                  ║
║  Exploring: TCP/UDP, HTTP, FTP, Email, DNS, ICMP                ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

check_tcp_udp
check_http_protocols
check_ftp_protocols
check_email_protocols
check_dns
check_icmp

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ Core Protocols Check Complete!                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"