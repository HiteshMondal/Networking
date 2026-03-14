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

    echo -e "  ${INFO}Both TCP and UDP live at Layer 4 (Transport) of the OSI model.${NC}"
    echo -e "  ${MUTED}They answer one question: how do we move data between two programs${NC}"
    echo -e "  ${MUTED}running on different machines? They answer it in opposite ways.${NC}"
    echo

    section "Real-World Analogy"
    echo -e "  ${AMBER}${BOLD}TCP  →  Certified Mail${NC}"
    echo -e "  ${DARK_GRAY}  $(printf '-%.0s' {1..62})${NC}"
    echo -e "  ${MUTED}  You send a package. The courier gets a signature on delivery.${NC}"
    echo -e "  ${MUTED}  If it never arrives, it gets resent. Order is preserved.${NC}"
    echo -e "  ${SUCCESS}  Guaranteed delivery — but slower, more overhead.${NC}"
    echo -e "  ${DARK_GRAY}  $(printf '-%.0s' {1..62})${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}UDP  →  Shouting across a room${NC}"
    echo -e "  ${DARK_GRAY}  $(printf '-%.0s' {1..62})${NC}"
    echo -e "  ${MUTED}  You broadcast your message. No handshake. No confirmation.${NC}"
    echo -e "  ${MUTED}  Some listeners may miss a word — that's acceptable.${NC}"
    echo -e "  ${WARNING}  No delivery guarantee — but fast, zero setup cost.${NC}"
    echo -e "  ${DARK_GRAY}  $(printf '-%.0s' {1..62})${NC}"
    echo

    section "Feature Comparison"
    printf "\n  ${BOLD}${TITLE}%-18s  %-28s  %-28s${NC}\n" "" "TCP" "UDP"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..76})"

    local -A tcp=(
        [mode]="Connection-oriented"
        [reliable]="Yes (ACK + retransmit)"
        [order]="Guaranteed"
        [flow]="Yes (sliding window)"
        [congestion]="Yes (CUBIC, BBR, Reno)"
        [speed]="Lower throughput"
        [header]="20–60 bytes"
        [uses]="HTTP/S, SSH, FTP, SMTP"
        [when]="Data integrity critical"
    )
    local -A udp=(
        [mode]="Connectionless"
        [reliable]="None"
        [order]="Not guaranteed"
        [flow]="No"
        [congestion]="No"
        [speed]="Higher throughput"
        [header]="8 bytes (fixed)"
        [uses]="DNS, VoIP, QUIC, Gaming"
        [when]="Speed/latency critical"
    )

    local fields=(mode reliable order flow congestion speed header uses when)
    local labels=(
        "Mode"
        "Reliability"
        "Ordering"
        "Flow Control"
        "Congestion Ctrl"
        "Speed"
        "Header Size"
        "Common Uses"
        "Choose When"
    )

    for i in "${!fields[@]}"; do
        printf "  ${LABEL}%-18s${NC}  ${GREEN}%-28s${NC}  ${CYAN}%-28s${NC}\n" \
            "${labels[$i]}:" \
            "${tcp[${fields[$i]}]}" \
            "${udp[${fields[$i]}]}"
    done
    echo

    section "TCP Header Anatomy  (20 bytes minimum)"
    echo -e "  ${MUTED}Every TCP segment carries this header before the payload:${NC}"
    echo
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}  %-30s${NC}  ${LABEL}%-28s${NC}\n"  "Source Port      (16 bit)"  "Destination Port (16 bit)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}  %-58s${NC}\n" "Sequence Number                                  (32 bit)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}  %-58s${NC}\n" "Acknowledgment Number                            (32 bit)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}  %-18s${NC}  ${LABEL}%-18s${NC}  ${LABEL}%-18s${NC}\n" \
        "Data Offset" "Flags  (9 bit)" "Window Size (16 bit)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}  %-28s${NC}  ${LABEL}%-28s${NC}\n"  "Checksum         (16 bit)"  "Urgent Pointer   (16 bit)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${MUTED}  %-58s${NC}\n" "Options  (0–40 bytes, present if Data Offset > 5)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${VALUE}  %-58s${NC}\n" "Payload / Application Data"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Key Fields Explained:${NC}"
    kv "  Sequence Number"  "Tracks byte position in the stream — enables ordering & gap detection"
    kv "  Acknowledgment"   "Confirms bytes received; tells sender what to send next"
    kv "  Window Size"      "How many bytes sender can transmit before waiting for ACK"
    kv "  Data Offset"      "Where the header ends and payload begins (in 32-bit words)"
    kv "  Urgent Pointer"   "Points to urgent data when URG flag is set (rarely used)"
    echo

    section "TCP Control Flags  (the 9-bit field)"
    echo -e "  ${MUTED}Flags are single-bit switches in the TCP header. Multiple can be set simultaneously.${NC}"
    echo
    printf "  ${BOLD}${TITLE}%-8s  %-14s  %s${NC}\n" "Flag" "Full Name" "Purpose"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..70})"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "SYN"  "Synchronize"   "Initiates a connection; carries initial sequence number"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "ACK"  "Acknowledge"   "Confirms receipt of data; accompanies almost every segment"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "FIN"  "Finish"        "Requests graceful connection termination"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "RST"  "Reset"         "Abruptly terminates connection; sent on error or port closed"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "PSH"  "Push"          "Tell receiver to deliver data to app immediately, don't buffer"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "URG"  "Urgent"        "Data at Urgent Pointer should be processed out-of-band"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "ECE"  "ECN-Echo"      "Signals network congestion to sender (ECN support)"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "CWR"  "Cong.Reduced"  "Confirms ECE received; congestion window was reduced"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n"  "NS"   "Nonce Sum"     "Experimental; ECN nonce concealment protection"
    echo

    section "UDP Header Anatomy  (8 bytes, always fixed)"
    echo -e "  ${MUTED}UDP's entire header fits in 8 bytes — its simplicity is its strength:${NC}"
    echo
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}  %-28s${NC}  ${LABEL}%-28s${NC}\n"  "Source Port      (16 bit)"  "Destination Port (16 bit)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}  %-28s${NC}  ${LABEL}%-28s${NC}\n"  "Length           (16 bit)"  "Checksum         (16 bit)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${VALUE}  %-58s${NC}\n" "Payload / Application Data"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Key Fields Explained:${NC}"
    kv "  Source Port"  "Originating port (can be 0 if reply not needed)"
    kv "  Length"       "Header + data in bytes; minimum value is 8"
    kv "  Checksum"     "Optional in IPv4, mandatory in IPv6; covers header + data"
    echo
    echo -e "  ${WARNING}No Sequence Number. No ACK. No flags. No window.${NC}"
    echo -e "  ${MUTED}  Ordering/reliability — if needed — must be handled by the application layer (e.g. QUIC, RTP).${NC}"
    echo

    section "TCP Three-Way Handshake  (Connection Setup)"
    echo -e "  ${MUTED}Before any data flows, TCP establishes shared state via three segments:${NC}"
    echo
    printf "  ${GREEN}%-10s${NC}                              ${BLUE}%s${NC}\n" "Client" "Server"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo -e "  ${MUTED}  send SYN (seq=100)${NC}"
    echo -e "  ${SUCCESS}  ---- SYN ---------------------------------------------->${NC}"
    echo -e "  ${MUTED}  Client picks random ISN (Initial Sequence Number)${NC}"
    echo
    echo -e "  ${MUTED}  recv SYN-ACK (seq=300, ack=101)${NC}"
    echo -e "  ${WARNING}  <--- SYN-ACK -----------------------------------------${NC}"
    echo -e "  ${MUTED}  Server acks client ISN, sends its own ISN${NC}"
    echo
    echo -e "  ${MUTED}  send ACK (ack=301)${NC}"
    echo -e "  ${INFO}  ---- ACK ---------------------------------------------->${NC}"
    echo -e "  ${MUTED}  Client acks server ISN — connection OPEN${NC}"
    echo
    echo -e "  ${BOLD}${TITLE}  ==== DATA TRANSFER BEGINS ==============================${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Why three steps?${NC}"
    echo -e "  ${MUTED}  Both sides must synchronize sequence numbers AND confirm the other${NC}"
    echo -e "  ${MUTED}  side received them. Two messages can't do both simultaneously.${NC}"
    echo

    section "TCP Four-Way Teardown  (Graceful Close)"
    echo -e "  ${MUTED}Each direction of the connection closes independently:${NC}"
    echo
    printf "  ${GREEN}%-10s${NC}                              ${BLUE}%s${NC}\n" "Client" "Server"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Client done sending — half-close initiated${NC}"
    echo -e "  ${WARNING}  ---- FIN ---------------------------------------------->${NC}"
    echo
    echo -e "  ${MUTED}  Server acks — can still send data${NC}"
    echo -e "  ${INFO}  <--- ACK ---------------------------------------------${NC}"
    echo
    echo -e "  ${MUTED}  Server done too — its half-close${NC}"
    echo -e "  ${WARNING}  <--- FIN ---------------------------------------------${NC}"
    echo
    echo -e "  ${MUTED}  Client acks — connection fully closed${NC}"
    echo -e "  ${INFO}  ---- ACK ---------------------------------------------->${NC}"
    echo
    echo -e "  ${MUTED}  [TIME_WAIT 2×MSL ≈ 120s] Client waits for any delayed segments${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}TIME_WAIT explained:${NC}"
    echo -e "  ${MUTED}  The client waits 2× Maximum Segment Lifetime (~60–120 s) before${NC}"
    echo -e "  ${MUTED}  truly closing. This ensures delayed duplicate segments from the${NC}"
    echo -e "  ${MUTED}  old connection don't corrupt a new connection on the same port tuple.${NC}"
    echo

    section "TCP State Machine"
    echo -e "  ${MUTED}TCP tracks connection progress through 11 states:${NC}"
    echo
    printf "  ${MUTED}%-38s  %s${NC}\n" "[Client Side]" "[Server Side]"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo
    printf "  ${MUTED}%-38s  %s${NC}\n"              "CLOSED"                    "CLOSED"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "  send SYN"                "  passive open"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "    ▼"                     "    ▼"
    printf "  ${GREEN}%-38s${NC}  ${BLUE}%s${NC}\n"  "SYN_SENT"                  "LISTEN"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "  recv SYN-ACK, send ACK"  "  recv SYN, send SYN-ACK"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "    ▼"                     "    ▼"
    printf "  ${SUCCESS}%-38s${NC}  ${SUCCESS}%s${NC}\n" "ESTABLISHED"           "SYN_RCVD  ==> ESTABLISHED"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "  send FIN"                "  recv FIN, send ACK"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "    ▼"                     "    ▼"
    printf "  ${WARNING}%-38s${NC}  ${MUTED}%s${NC}\n"  "FIN_WAIT_1"            "CLOSE_WAIT"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "  recv ACK"                "  send FIN"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "    ▼"                     "    ▼"
    printf "  ${WARNING}%-38s${NC}  ${CORAL}%s${NC}\n"  "FIN_WAIT_2"            "LAST_ACK"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "  recv FIN, send ACK"      "  recv ACK"
    printf "  ${MUTED}%-38s  %s${NC}\n"              "    ▼"                     "    ▼"
    printf "  ${AMBER}%-38s${NC}  ${MUTED}%s${NC}\n" "TIME_WAIT"                 "CLOSED"
    printf "  ${MUTED}%s${NC}\n"                     "  2×MSL timeout"
    printf "  ${MUTED}%s${NC}\n"                     "    ▼"
    printf "  ${MUTED}%s${NC}\n"                     "CLOSED"
    echo

    section "Live TCP/UDP Observations"
    echo -e "  ${INFO}[1] Active TCP connections (ESTABLISHED):${NC}"
    ss -tn state established 2>/dev/null | head -12 \
        || netstat -tn 2>/dev/null | grep ESTABLISHED | head -12
    echo

    echo -e "  ${INFO}[2] Listening TCP ports (services accepting connections):${NC}"
    ss -tlnp 2>/dev/null | head -14 \
        || netstat -tlnp 2>/dev/null | head -14
    echo

    echo -e "  ${INFO}[3] Active UDP sockets:${NC}"
    ss -ulnp 2>/dev/null | head -10 \
        || netstat -ulnp 2>/dev/null | head -10
    echo

    echo -e "  ${INFO}[4] TCP connection state distribution:${NC}"
    ss -tan 2>/dev/null | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn \
        | while read -r count state; do
            printf "  ${LABEL}%-18s${NC} ${VALUE}%s connections${NC}\n" "$state" "$count"
          done
    echo

    echo -e "  ${INFO}[5] Socket summary (all protocols):${NC}"
    ss -s 2>/dev/null
    echo

    echo -e "  ${INFO}[6] Top 5 destination IPs in ESTABLISHED connections:${NC}"
    ss -tn state established 2>/dev/null \
        | awk 'NR>1 {print $5}' \
        | cut -d: -f1 \
        | sort | uniq -c | sort -rn | head -5 \
        | while read -r count ip; do
            printf "  ${LABEL}%-18s${NC}  ${VALUE}%s connections${NC}\n" "$ip" "$count"
          done
    echo

    echo -e "  ${INFO}[7] Retransmission & error counters:${NC}"
    if cmd_exists netstat; then
        netstat -s 2>/dev/null | grep -E 'retransmit|failed|error|reset|drop' \
            | head -10 | while IFS= read -r line; do
                echo -e "  ${MUTED}${line}${NC}"
              done
    else
        cat /proc/net/snmp 2>/dev/null | grep -E '^Tcp' | awk '
            NR==1 { split($0,keys) }
            NR==2 { for(i=2;i<=NF;i++) printf "  %-22s %s\n", keys[i], $i }
        ' | grep -i -E 'retrans|error|reset|drop' \
          | while IFS= read -r line; do echo -e "  ${MUTED}${line}${NC}"; done
    fi
    echo

    echo -e "  ${INFO}[8] Kernel TCP tuning parameters (current values):${NC}"
    local params=(
        net.ipv4.tcp_fin_timeout
        net.ipv4.tcp_keepalive_time
        net.ipv4.tcp_keepalive_intvl
        net.ipv4.tcp_keepalive_probes
        net.ipv4.tcp_max_syn_backlog
        net.ipv4.tcp_syncookies
        net.core.rmem_max
        net.core.wmem_max
    )
    for param in "${params[@]}"; do
        local val
        val=$(sysctl -n "$param" 2>/dev/null || echo "unavailable")
        kv "  ${param##*.}" "$val"
    done
    echo

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
    echo

    header "Advanced TCP State Analysis"
    echo -e "  ${INFO}TCP connection states (all):${NC}"
    ss -tan | awk '{print $1}' | sort | uniq -c | sort -nr
    echo

    echo -e "  ${INFO}Top ESTABLISHED connections:${NC}"
    ss -tan state established | head -10
    echo

    section "Attack Context — TCP & UDP Exploitation"
    echo -e "  ${FAILURE}${BOLD}[!] SYN Flood Attack  (TCP DoS)${NC}"
    echo
    echo -e "  ${MUTED}  Attacker sends thousands of SYN packets with spoofed source IPs.${NC}"
    echo -e "  ${MUTED}  Server allocates a half-open connection entry for each one,${NC}"
    echo -e "  ${MUTED}  waiting for the final ACK that never comes.${NC}"
    echo -e "  ${MUTED}  The SYN backlog fills up — legitimate connections are rejected.${NC}"
    echo
    printf "  ${GREEN}%-12s${NC}                          ${BLUE}%s${NC}\n" "Attacker" "Server"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo -e "  ${FAILURE}  ---- SYN (src=1.2.3.4 FAKE) -------------------------->${NC}  allocates slot"
    echo -e "  ${FAILURE}  ---- SYN (src=5.6.7.8 FAKE) -------------------------->${NC}  allocates slot"
    echo -e "  ${FAILURE}  ---- SYN (src=9.0.1.2 FAKE) -------------------------->${NC}  allocates slot"
    echo -e "  ${MUTED}  ... ×10,000/second${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${GREEN}%s${NC}\n" "  LegitUser"
    echo -e "  ${SUCCESS}  ---- SYN ---------------------------------------------->${NC}  ${FAILURE}Connection refused!${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Mitigations:${NC}"
    kv "  SYN Cookies"         "Encodes state into ISN — no slot allocated until ACK received"
    kv "  tcp_max_syn_backlog" "Increase queue depth (sysctl net.ipv4.tcp_max_syn_backlog)"
    kv "  Rate limiting"       "iptables: limit SYN rate per source IP"
    kv "  tcp_syncookies"      "sysctl net.ipv4.tcp_syncookies=1  (should always be 1)"
    echo
    echo -e "  ${INFO}Current syncookies status on this host:${NC}"
    local syncookies
    syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "unavailable")
    if [[ "$syncookies" == "1" ]]; then
        status_line ok   "SYN cookies ENABLED  (net.ipv4.tcp_syncookies=1)"
    else
        status_line fail "SYN cookies DISABLED  (net.ipv4.tcp_syncookies=${syncookies})"
    fi
    echo

    echo -e "  ${FAILURE}${BOLD}[!] RST Injection  (TCP Session Hijack / Teardown)${NC}"
    echo
    echo -e "  ${MUTED}  Attacker on-path (or who can guess sequence numbers) sends a${NC}"
    echo -e "  ${MUTED}  forged RST segment to either endpoint with a valid sequence number.${NC}"
    echo -e "  ${MUTED}  The receiving end tears down the connection immediately.${NC}"
    echo -e "  ${MUTED}  Used by: BGP session killing, censorship (GFW), DoS.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Mitigations:${NC}"
    kv "  RFC 5961"  "Stricter ACK validation — reduces blind RST acceptance"
    kv "  TCP-AO"    "TCP Authentication Option — cryptographic segment auth"
    kv "  TLS"       "Encrypted payload; RST still works but data is protected"
    echo

    echo -e "  ${FAILURE}${BOLD}[!] UDP Amplification Attack  (DDoS Reflection)${NC}"
    echo
    echo -e "  ${MUTED}  UDP has no handshake — attacker spoofs victim's IP as source,${NC}"
    echo -e "  ${MUTED}  sends a tiny request to an open UDP service.${NC}"
    echo -e "  ${MUTED}  The service sends a large response directly to the victim.${NC}"
    echo -e "  ${MUTED}  The attacker's tiny bandwidth is amplified into a flood.${NC}"
    echo
    printf "  ${GREEN}%-12s${NC}                          ${BLUE}%s${NC}\n" "Attacker" "DNS/NTP/SSDP"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo -e "  ${FAILURE}  ---- small req (src=VICTIM IP) ------------------------>${NC}"
    echo -e "  ${FAILURE}  <--- HUGE response ------------------------------------${NC}  → floods Victim"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    echo
    printf "  ${BOLD}${TITLE}%-22s  %-12s  %-12s  %s${NC}\n" \
        "Protocol" "Request" "Response" "Amplification"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..62})"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-12s${NC}  ${WARNING}%-12s${NC}  ${FAILURE}%s${NC}\n" \
        "DNS (ANY query)"  "60 bytes"  "3000 bytes"  "~50×"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-12s${NC}  ${WARNING}%-12s${NC}  ${FAILURE}%s${NC}\n" \
        "NTP (monlist)"    "8 bytes"   "~48 KB"      "~556×"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-12s${NC}  ${WARNING}%-12s${NC}  ${FAILURE}%s${NC}\n" \
        "SSDP"             "110 bytes" "~1900 bytes" "~17×"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-12s${NC}  ${WARNING}%-12s${NC}  ${FAILURE}%s${NC}\n" \
        "Memcached (UDP)"  "15 bytes"  "~134 KB"     "~51,000×"
    echo
    echo -e "  ${AMBER}${BOLD}Mitigations:${NC}"
    kv "  BCP38 / uRPF"    "ISPs drop packets with spoofed source IPs at the edge"
    kv "  Rate limiting"   "Limit UDP response rate on open resolvers/NTP servers"
    kv "  Disable monlist" "ntpdc -c 'disable monitor'  or  restrict default noquery"
    kv "  Firewall"        "Block external access to UDP services not meant to be public"
    echo

    echo -e "  ${FAILURE}${BOLD}[!] TCP Port Scanning Techniques  (Reconnaissance)${NC}"
    echo
    printf "  ${BOLD}${TITLE}%-24s  %s${NC}\n" "Scan Type" "How It Works"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '-%.0s' {1..70})"
    printf "  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "SYN Scan (half-open)"  "Send SYN; OPEN=SYN-ACK received, CLOSED=RST; never completes handshake"
    printf "  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Connect Scan"          "Full 3-way handshake; logged by target; used when no raw socket access"
    printf "  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "FIN / NULL / XMAS"     "Send malformed flags; closed ports reply RST; open ports silent (RFC 793)"
    printf "  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "ACK Scan"              "Probes firewall rules; RST=unfiltered, no reply=filtered"
    printf "  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "UDP Scan"              "Send empty UDP; ICMP port-unreachable=closed, no reply=open|filtered"
    echo
}

check_http_protocols() {

    #  SECTION 1 -- OVERVIEW
    header "HTTP / HTTPS -- Web Protocols"

    echo -e "  ${INFO}HTTP (Hypertext Transfer Protocol) is the foundation of all data exchange${NC}"
    echo -e "  ${MUTED}on the Web. It is a stateless, application-layer protocol that defines${NC}"
    echo -e "  ${MUTED}how clients request resources and how servers respond to those requests.${NC}"
    echo -e "  ${MUTED}HTTPS adds a TLS encryption layer beneath HTTP, keeping that same${NC}"
    echo -e "  ${MUTED}request/response model while making it private and authenticated.${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}HTTP   -- HyperText Transfer Protocol${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    kv "  Port"      "80  (TCP)"
    kv "  Security"  "None -- plaintext over the wire, trivially intercepted"
    kv "  State"     "Stateless -- each request is independent by default"
    kv "  Methods"   "GET  POST  PUT  PATCH  DELETE  HEAD  OPTIONS  TRACE"
    kv "  Versions"  "HTTP/0.9  HTTP/1.0  HTTP/1.1  HTTP/2  HTTP/3"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}HTTPS  -- HTTP over TLS${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    kv "  Port"      "443  (TCP)"
    kv "  Security"  "TLS 1.2 / TLS 1.3 -- encrypted, authenticated, integrity-checked"
    kv "  Features"  "Certificate auth, HSTS, ALPN protocol negotiation, OCSP stapling"
    kv "  Trust"     "X.509 certificate signed by a trusted Certificate Authority (CA)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    #  SECTION 2 -- HTTP METHODS
    section "HTTP Request Methods"

    echo -e "  ${MUTED}Each method expresses the intended action on the target resource.${NC}"
    echo -e "  ${MUTED}Safe = no side-effects.  Idempotent = same result if repeated.${NC}"
    echo
    printf "  ${BOLD}${TITLE}%-10s  %-12s  %-12s  %s${NC}\n" "Method" "Safe" "Idempotent" "Purpose"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "GET"     "Yes"  "Yes"  "Retrieve a resource -- no body sent, no server state changed"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "POST"    "No"   "No"   "Submit data; create a resource or trigger an action"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "PUT"     "No"   "Yes"  "Replace a resource entirely at a known URI"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "PATCH"   "No"   "No"   "Apply partial modifications to a resource"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "DELETE"  "No"   "Yes"  "Remove the target resource"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "HEAD"    "Yes"  "Yes"  "GET without body -- check headers/existence only"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "OPTIONS" "Yes"  "Yes"  "Discover allowed methods -- used in CORS preflight"
    printf "  ${GREEN}%-10s${NC}  ${LABEL}%-12s${NC}  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "TRACE"   "Yes"  "Yes"  "Echo request back -- useful for loop-back diagnostics"
    echo

    #  SECTION 3 -- REQUEST / RESPONSE STRUCTURE
    section "HTTP Request / Response Structure"

    echo -e "  ${MUTED}Every HTTP exchange has two parts: a client Request and a server Response.${NC}"
    echo -e "  ${MUTED}Both follow the same wire format: start-line, headers, blank line, body.${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}HTTP Request -- wire format${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${SUCCESS}  %-58s${NC}\n" "Request Line:   METHOD  /path  HTTP/version"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}  %-58s${NC}\n" "Host:           example.com"
    printf "  ${LABEL}  %-58s${NC}\n" "User-Agent:     Mozilla/5.0 ..."
    printf "  ${LABEL}  %-58s${NC}\n" "Accept:         text/html,application/json"
    printf "  ${LABEL}  %-58s${NC}\n" "Accept-Encoding: gzip, deflate, br"
    printf "  ${LABEL}  %-58s${NC}\n" "Connection:     keep-alive"
    printf "  ${LABEL}  %-58s${NC}\n" "Authorization:  Bearer <token>          (if auth required)"
    printf "  ${LABEL}  %-58s${NC}\n" "Content-Type:   application/json        (if body present)"
    printf "  ${LABEL}  %-58s${NC}\n" "Content-Length: 42                      (if body present)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${MUTED}  %-58s${NC}\n" "<blank line>    -- signals end of headers"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${VALUE}  %-58s${NC}\n" "{ \"key\": \"value\" }   -- optional body (POST/PUT/PATCH)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}Concrete GET example:${NC}"
    echo -e "  ${MUTED}  GET /index.html HTTP/1.1${NC}"
    echo -e "  ${MUTED}  Host: example.com${NC}"
    echo -e "  ${MUTED}  Accept: text/html${NC}"
    echo -e "  ${MUTED}  Connection: keep-alive${NC}"
    echo -e "  ${MUTED}  <blank line>${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}HTTP Response -- wire format${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${SUCCESS}  %-58s${NC}\n" "Status Line:    HTTP/version  STATUS_CODE  Reason-Phrase"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}  %-58s${NC}\n" "Date:           Mon, 01 Jan 2025 00:00:00 GMT"
    printf "  ${LABEL}  %-58s${NC}\n" "Server:         nginx/1.25.3"
    printf "  ${LABEL}  %-58s${NC}\n" "Content-Type:   text/html; charset=UTF-8"
    printf "  ${LABEL}  %-58s${NC}\n" "Content-Length: 1256"
    printf "  ${LABEL}  %-58s${NC}\n" "Cache-Control:  max-age=3600, public"
    printf "  ${LABEL}  %-58s${NC}\n" "Set-Cookie:     session=abc123; HttpOnly; Secure"
    printf "  ${LABEL}  %-58s${NC}\n" "Strict-Transport-Security: max-age=31536000"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${MUTED}  %-58s${NC}\n" "<blank line>    -- signals end of headers"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${VALUE}  %-58s${NC}\n" "<!DOCTYPE html>...  -- response body"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}Concrete 200 OK example:${NC}"
    echo -e "  ${MUTED}  HTTP/1.1 200 OK${NC}"
    echo -e "  ${MUTED}  Content-Type: text/html; charset=UTF-8${NC}"
    echo -e "  ${MUTED}  Content-Length: 1256${NC}"
    echo -e "  ${MUTED}  <blank line>${NC}"
    echo -e "  ${MUTED}  <!DOCTYPE html>...${NC}"
    echo

    #  SECTION 4 -- HTTP STATUS CODES
    section "HTTP Status Codes"

    echo -e "  ${MUTED}Status codes are three-digit numbers grouped by their first digit.${NC}"
    echo -e "  ${MUTED}The server includes one in every response to tell the client what happened.${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}1xx -- Informational${NC}"
    echo -e "  ${MUTED}  Provisional response. Request received, processing continues.${NC}"
    echo -e "  ${MUTED}  The client should wait for a follow-up response.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${GREEN}%-6s${NC}  ${VALUE}%s${NC}\n" "100"  "Continue         -- server got headers, client may send body"
    printf "  ${GREEN}%-6s${NC}  ${VALUE}%s${NC}\n" "101"  "Switching Protocols -- server agrees to protocol upgrade (e.g. WebSocket)"
    printf "  ${GREEN}%-6s${NC}  ${VALUE}%s${NC}\n" "103"  "Early Hints      -- pre-send Link headers before final response"
    echo

    echo -e "  ${AMBER}${BOLD}2xx -- Success${NC}"
    echo -e "  ${MUTED}  The request was received, understood, and accepted.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${SUCCESS}%-6s${NC}  ${VALUE}%s${NC}\n" "200"  "OK               -- standard success; body contains result"
    printf "  ${SUCCESS}%-6s${NC}  ${VALUE}%s${NC}\n" "201"  "Created          -- resource created; Location header points to it"
    printf "  ${SUCCESS}%-6s${NC}  ${VALUE}%s${NC}\n" "202"  "Accepted         -- request queued; processing not yet complete"
    printf "  ${SUCCESS}%-6s${NC}  ${VALUE}%s${NC}\n" "204"  "No Content       -- success but nothing to return (e.g. DELETE)"
    printf "  ${SUCCESS}%-6s${NC}  ${VALUE}%s${NC}\n" "206"  "Partial Content  -- range request fulfilled (streaming/resumable download)"
    echo

    echo -e "  ${AMBER}${BOLD}3xx -- Redirection${NC}"
    echo -e "  ${MUTED}  Client must take further action, usually follow a Location header.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${WARNING}%-6s${NC}  ${VALUE}%s${NC}\n" "301"  "Moved Permanently  -- URL changed forever; update bookmarks/links"
    printf "  ${WARNING}%-6s${NC}  ${VALUE}%s${NC}\n" "302"  "Found              -- temporary redirect; keep using original URL"
    printf "  ${WARNING}%-6s${NC}  ${VALUE}%s${NC}\n" "304"  "Not Modified       -- cached version is fresh; no body sent"
    printf "  ${WARNING}%-6s${NC}  ${VALUE}%s${NC}\n" "307"  "Temporary Redirect -- like 302 but method must not change"
    printf "  ${WARNING}%-6s${NC}  ${VALUE}%s${NC}\n" "308"  "Permanent Redirect -- like 301 but method must not change"
    echo

    echo -e "  ${AMBER}${BOLD}4xx -- Client Error${NC}"
    echo -e "  ${MUTED}  The request contains bad syntax or cannot be fulfilled by the server.${NC}"
    echo -e "  ${MUTED}  The error is on the client side -- fix the request before retrying.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "400"  "Bad Request      -- malformed syntax, invalid parameters"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "401"  "Unauthorized     -- authentication required (WWW-Authenticate header)"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "403"  "Forbidden        -- authenticated but not allowed; no credentials will help"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "404"  "Not Found        -- resource does not exist at this URI"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "405"  "Method Not Allowed -- server knows the resource but rejects the method"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "408"  "Request Timeout  -- server timed out waiting for the client"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "409"  "Conflict         -- state conflict (e.g. duplicate create, edit conflict)"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "410"  "Gone             -- resource permanently removed (stronger than 404)"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "413"  "Payload Too Large -- request body exceeds server limit"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "422"  "Unprocessable    -- valid syntax but semantic errors (common in APIs)"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "429"  "Too Many Requests -- rate limit hit; check Retry-After header"
    echo

    echo -e "  ${AMBER}${BOLD}5xx -- Server Error${NC}"
    echo -e "  ${MUTED}  The server failed to fulfil a valid request.${NC}"
    echo -e "  ${MUTED}  The error is on the server side -- retry may succeed later.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "500"  "Internal Server Error -- unhandled exception, bug in server code"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "501"  "Not Implemented  -- method valid but server has no handler for it"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "502"  "Bad Gateway      -- upstream server returned an invalid response"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "503"  "Service Unavail  -- server overloaded or down for maintenance"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "504"  "Gateway Timeout  -- upstream did not respond in time"
    printf "  ${FAILURE}%-6s${NC}  ${VALUE}%s${NC}\n" "507"  "Insufficient Storage -- server cannot store the representation"
    echo

    #  SECTION 5 -- HTTP VERSION COMPARISON
    section "HTTP/1.1 vs HTTP/2 vs HTTP/3"

    echo -e "  ${MUTED}Each version solves the performance bottlenecks of the one before it.${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}HTTP/1.1  (1997, RFC 2616 / RFC 7230)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Transport    : TCP${NC}"
    echo -e "  ${MUTED}  Multiplexing : None -- one request per TCP connection${NC}"
    echo -e "  ${MUTED}  Keep-Alive   : Yes -- reuse connection across requests${NC}"
    echo -e "  ${MUTED}  Headers      : Plain text, repeated on every request${NC}"
    echo -e "  ${MUTED}  Problem      : Head-of-Line (HOL) blocking -- if req 1 stalls,${NC}"
    echo -e "  ${MUTED}                 req 2 and 3 wait even on the same connection.${NC}"
    echo -e "  ${MUTED}  Workaround   : Browsers open 6-8 parallel TCP connections per host${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}HTTP/2  (2015, RFC 7540)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Transport    : TCP (1 connection per host)${NC}"
    echo -e "  ${MUTED}  Multiplexing : Yes -- multiple streams interleaved on 1 connection${NC}"
    echo -e "  ${MUTED}  Headers      : HPACK compression -- eliminates repetition${NC}"
    echo -e "  ${MUTED}  Push         : Server can push resources before client asks${NC}"
    echo -e "  ${MUTED}  Binary       : Binary framing layer replaces plain-text protocol${NC}"
    echo -e "  ${MUTED}  Problem      : TCP HOL blocking still exists at the transport layer.${NC}"
    echo -e "  ${MUTED}                 A single lost TCP packet stalls ALL streams.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}HTTP/3  (2022, RFC 9114)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Transport    : QUIC over UDP (not TCP)${NC}"
    echo -e "  ${MUTED}  Multiplexing : Yes -- streams are independent; no HOL blocking${NC}"
    echo -e "  ${MUTED}  TLS          : Built-in TLS 1.3 -- 0-RTT / 1-RTT connection setup${NC}"
    echo -e "  ${MUTED}  Migration    : Connection ID survives IP/network changes (mobile)${NC}"
    echo -e "  ${MUTED}  Headers      : QPACK compression (HPACK adapted for QUIC)${NC}"
    echo -e "  ${MUTED}  Benefit      : Packet loss only hurts the affected stream, not all${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}Side-by-side summary${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..76})"
    printf "  ${BOLD}${TITLE}%-20s  %-16s  %-16s  %-16s${NC}\n" "Feature" "HTTP/1.1" "HTTP/2" "HTTP/3"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..76})"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "Transport"       "TCP"              "TCP"              "QUIC (UDP)"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "Multiplexing"    "No"               "Yes"              "Yes"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "HOL Blocking"    "App + TCP"        "TCP only"         "None"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "Header Compress" "None"             "HPACK"            "QPACK"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "TLS"             "Optional"         "Effectively req." "Built-in (1.3)"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "Server Push"     "No"               "Yes"              "Limited"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "Conn. Migration" "No"               "No"               "Yes"
    printf "  ${LABEL}%-20s${NC}  ${MUTED}%-16s${NC}  ${WARNING}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" \
        "Wire Format"     "Plain text"       "Binary"           "Binary"
    echo

    #  SECTION 6 -- TLS HANDSHAKE FLOW
    section "TLS Handshake -- How HTTPS Establishes a Secure Channel"

    echo -e "  ${MUTED}Before any HTTP data flows over HTTPS, TLS negotiates keys and${NC}"
    echo -e "  ${MUTED}authenticates the server. TLS 1.3 does this in 1 round-trip (1-RTT).${NC}"
    echo -e "  ${MUTED}TLS 1.2 takes 2 round-trips. Here is the TLS 1.3 flow:${NC}"
    echo

    printf "  ${GREEN}%-14s${NC}                          ${BLUE}%s${NC}\n" "Client" "Server"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"

    echo -e "  ${MUTED}  [1] ClientHello${NC}"
    echo -e "  ${SUCCESS}  ---- ClientHello ------------------------------------>${NC}"
    echo -e "  ${MUTED}       TLS version, random nonce, supported cipher suites,${NC}"
    echo -e "  ${MUTED}       supported groups (key exchange), SNI (hostname)${NC}"
    echo

    echo -e "  ${MUTED}  [2] ServerHello + EncryptedExtensions + Certificate + Finished${NC}"
    echo -e "  ${WARNING}  <--- ServerHello + Certificate + Finished ------------${NC}"
    echo -e "  ${MUTED}       Chosen cipher suite, server's key share (ECDHE),${NC}"
    echo -e "  ${MUTED}       X.509 certificate chain, CertificateVerify, Finished MAC${NC}"
    echo -e "  ${MUTED}       (Everything after ServerHello is already encrypted)${NC}"
    echo

    echo -e "  ${MUTED}  [3] Client verifies certificate against trusted CA store${NC}"
    echo -e "  ${MUTED}      Derives session keys from key shares (no key sent over wire)${NC}"
    echo
    echo -e "  ${INFO}  ---- Finished (Client) -------------------------------->${NC}"
    echo -e "  ${MUTED}       Client Finished MAC -- confirms handshake integrity${NC}"
    echo

    echo -e "  ${BOLD}${TITLE}  ==== HTTPS DATA TRANSFER (encrypted) ==================${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Key Exchange -- why no key is ever sent over the wire:${NC}"
    echo -e "  ${MUTED}  TLS 1.3 uses ECDHE (Elliptic Curve Diffie-Hellman Ephemeral).${NC}"
    echo -e "  ${MUTED}  Both sides generate a keypair, exchange public keys, and each${NC}"
    echo -e "  ${MUTED}  independently derives the SAME session secret. An eavesdropper${NC}"
    echo -e "  ${MUTED}  who sees both public keys cannot compute the shared secret without${NC}"
    echo -e "  ${MUTED}  solving the elliptic-curve discrete log problem (computationally${NC}"
    echo -e "  ${MUTED}  infeasible). This also provides Perfect Forward Secrecy (PFS):${NC}"
    echo -e "  ${MUTED}  compromising the server's private key later cannot decrypt old sessions.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}TLS 1.2 vs TLS 1.3:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${BOLD}${TITLE}%-24s  %-16s  %-16s${NC}\n" "Feature" "TLS 1.2" "TLS 1.3"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-24s${NC}  ${MUTED}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" "Handshake RTTs"    "2-RTT"             "1-RTT (0-RTT opt.)"
    printf "  ${LABEL}%-24s${NC}  ${MUTED}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" "Key Exchange"      "RSA or ECDHE"      "ECDHE only"
    printf "  ${LABEL}%-24s${NC}  ${MUTED}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" "Forward Secrecy"   "Optional"          "Mandatory"
    printf "  ${LABEL}%-24s${NC}  ${MUTED}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" "Cipher suites"     "Many (incl. weak)" "5 strong only"
    printf "  ${LABEL}%-24s${NC}  ${MUTED}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" "Encrypted handshk" "No"                "Yes (after Hello)"
    printf "  ${LABEL}%-24s${NC}  ${MUTED}%-16s${NC}  ${SUCCESS}%-16s${NC}\n" "Renegotiation"     "Yes (risky)"       "Removed"
    echo

    #  SECTION 7 -- ATTACK CONTEXT
    section "Attack Context -- HTTP & HTTPS Exploitation"

    # --- MITM ---
    echo -e "  ${FAILURE}${BOLD}[!] Man-in-the-Middle (MITM)${NC}"
    echo
    echo -e "  ${MUTED}  Attacker positions themselves between client and server,${NC}"
    echo -e "  ${MUTED}  relaying and optionally modifying all traffic.${NC}"
    echo -e "  ${MUTED}  Over plain HTTP this is trivial -- attacker sees and edits everything.${NC}"
    echo -e "  ${MUTED}  Over HTTPS the attacker must also forge a trusted certificate.${NC}"
    echo
    printf "  ${GREEN}%-10s${NC}              ${FAILURE}%-12s${NC}              ${BLUE}%s${NC}\n" \
        "Client" "Attacker" "Server"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${SUCCESS}  ---- HTTP GET /login ----->${NC}  ${FAILURE}(intercept)${NC}  ${WARNING}---- GET /login -->${NC}"
    echo -e "  ${WARNING}  <-- 200 OK + form --------${NC}  ${FAILURE}(modify) ${NC}  ${SUCCESS}<--- 200 OK + form${NC}"
    echo -e "  ${SUCCESS}  ---- POST credentials ---->${NC}  ${FAILURE}(harvest)${NC}  ${WARNING}---- POST -------->${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Mitigations:${NC}"
    kv "  HTTPS everywhere"  "Encrypt all traffic -- no sensitive data over HTTP"
    kv "  HSTS"              "Strict-Transport-Security forces HTTPS even if user types http://"
    kv "  Cert pinning"      "App rejects certs not matching a known fingerprint (mobile apps)"
    kv "  MFA"               "Stolen credentials alone are not sufficient to log in"
    echo

    # --- SSL Stripping ---
    echo -e "  ${FAILURE}${BOLD}[!] SSL Stripping${NC}"
    echo
    echo -e "  ${MUTED}  Attack invented by Moxie Marlinspike (sslstrip, 2009).${NC}"
    echo -e "  ${MUTED}  The attacker intercepts the client's initial HTTP request (before${NC}"
    echo -e "  ${MUTED}  any redirect to HTTPS) and proxies the server's HTTPS responses${NC}"
    echo -e "  ${MUTED}  back over HTTP. The client never gets a chance to use TLS.${NC}"
    echo
    printf "  ${GREEN}%-10s${NC}              ${FAILURE}%-12s${NC}              ${BLUE}%s${NC}\n" \
        "Client" "sslstrip" "Server"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${SUCCESS}  ---- http://bank.com ----->${NC}"
    echo -e "  ${MUTED}                              ${FAILURE}---- https://bank.com -->${NC}"
    echo -e "  ${MUTED}                              ${FAILURE}<--- HTTPS response ----${NC}"
    echo -e "  ${SUCCESS}  <--- http:// response ----${NC}  ${FAILURE}(https rewritten to http)${NC}"
    echo -e "  ${MUTED}  Client never sees TLS${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Mitigations:${NC}"
    kv "  HSTS preload"      "Browser refuses HTTP for domain before first visit"
    kv "  HSTS max-age"      "Set high max-age (>1 year) so browsers remember"
    kv "  includeSubDomains" "HSTS must cover all subdomains too"
    echo

    # --- HTTP Header Injection ---
    echo -e "  ${FAILURE}${BOLD}[!] HTTP Header Injection / Response Splitting${NC}"
    echo
    echo -e "  ${MUTED}  Occurs when user-supplied input is embedded in HTTP response headers${NC}"
    echo -e "  ${MUTED}  without sanitisation. If the input contains CR (\\r) + LF (\\n),${NC}"
    echo -e "  ${MUTED}  the attacker can inject arbitrary headers or even a second response.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Vulnerable redirect code (pseudo):${NC}"
    echo -e "  ${FAILURE}  Location: /redirect?url=<USER_INPUT>${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Malicious input:${NC}"
    echo -e "  ${FAILURE}  /page\\r\\nSet-Cookie: session=evil; HttpOnly${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Resulting injected response:${NC}"
    echo -e "  ${MUTED}  HTTP/1.1 302 Found${NC}"
    echo -e "  ${MUTED}  Location: /page${NC}"
    echo -e "  ${FAILURE}  Set-Cookie: session=evil; HttpOnly    <-- injected!${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Mitigations:${NC}"
    kv "  Input validation"   "Strip or reject CR/LF in any value placed into headers"
    kv "  Framework encoding" "Use framework header APIs -- never raw string concat"
    kv "  WAF rules"          "Web Application Firewall blocks CRLF sequences in params"
    echo

    # --- Clickjacking ---
    echo -e "  ${FAILURE}${BOLD}[!] Clickjacking${NC}"
    echo
    echo -e "  ${MUTED}  Attacker embeds the target site in a hidden <iframe> on their page.${NC}"
    echo -e "  ${MUTED}  Victim thinks they are clicking the attacker's UI but actually${NC}"
    echo -e "  ${MUTED}  interacts with the target site (transferring funds, changing settings).${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Mitigations:${NC}"
    kv "  X-Frame-Options"   "DENY or SAMEORIGIN -- prevents framing by other origins"
    kv "  CSP frame-ancestors" "Content-Security-Policy: frame-ancestors 'none'"
    echo

    # --- Security Headers Summary ---
    echo -e "  ${FAILURE}${BOLD}[!] Missing Security Headers (common finding)${NC}"
    echo
    echo -e "  ${MUTED}  Many attacks are defeated purely by returning the right HTTP headers.${NC}"
    echo
    printf "  ${BOLD}${TITLE}%-32s  %s${NC}\n" "Header" "What it does"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${LABEL}%-32s${NC}  ${VALUE}%s${NC}\n" \
        "Strict-Transport-Security"  "Forces HTTPS for max-age seconds (HSTS)"
    printf "  ${LABEL}%-32s${NC}  ${VALUE}%s${NC}\n" \
        "Content-Security-Policy"    "Restricts sources of scripts, styles, frames"
    printf "  ${LABEL}%-32s${NC}  ${VALUE}%s${NC}\n" \
        "X-Frame-Options"            "Prevents clickjacking via iframe embedding"
    printf "  ${LABEL}%-32s${NC}  ${VALUE}%s${NC}\n" \
        "X-Content-Type-Options"     "nosniff -- stops MIME-type sniffing attacks"
    printf "  ${LABEL}%-32s${NC}  ${VALUE}%s${NC}\n" \
        "Referrer-Policy"            "Controls how much referrer info is leaked"
    printf "  ${LABEL}%-32s${NC}  ${VALUE}%s${NC}\n" \
        "Permissions-Policy"         "Disables browser features (camera, mic, geo)"
    printf "  ${LABEL}%-32s${NC}  ${VALUE}%s${NC}\n" \
        "Cache-Control"              "Prevents sensitive pages being cached by proxy"
    echo

    #  SECTION 8 -- LOCAL WEB SERVICES (unchanged)
    section "Local Web Services"

    echo -e "  ${INFO}Listening on common web ports:${NC}"
    ss -tlnp 2>/dev/null | grep -E ":80 |:443 |:8080 |:8443 |:8888 " \
        || echo -e "  ${MUTED}None detected${NC}"
    echo

    #  SECTION 9 -- LIVE HTTP/HTTPS PROBE (unchanged)
    section "Live HTTP/HTTPS Probe"

    read -rp "$(echo -e "  ${PROMPT}Enter domain to probe [default: example.com]:${NC} ")" test_domain
    test_domain="${test_domain:-example.com}"

    if ! (is_valid_host "$test_domain" || is_valid_ip "$test_domain"); then
        log_warning "Invalid input -- using example.com"
        test_domain="example.com"
    fi

    if cmd_exists curl; then
        echo
        echo -e "  ${INFO}HTTP response headers for ${test_domain}:${NC}"
        curl -sI --max-time 5 "http://${test_domain}" 2>/dev/null | head -15 \
            || echo -e "  ${MUTED}No response${NC}"
        echo

        echo -e "  ${INFO}HTTPS response headers for ${test_domain}:${NC}"
        curl -sI --max-time 5 "https://${test_domain}" 2>/dev/null | head -15 \
            || echo -e "  ${MUTED}No response${NC}"
        echo

        echo -e "  ${INFO}Measuring HTTP response time:${NC}"
        curl -so /dev/null \
            -w "  DNS lookup   : %{time_namelookup}s\n  TCP connect  : %{time_connect}s\n  TLS handshake: %{time_appconnect}s\n  TTFB         : %{time_starttransfer}s\n  Total        : %{time_total}s\n  HTTP status  : %{http_code}\n" \
            --max-time 8 "https://${test_domain}" 2>/dev/null \
            || echo -e "  ${MUTED}Timing unavailable${NC}"
    else
        log_warning "curl not available -- skipping live probes"
    fi

    if cmd_exists openssl; then
        echo
        echo -e "  ${INFO}TLS certificate details for ${test_domain}:${NC}"
        echo | openssl s_client \
            -connect "${test_domain}:443" \
            -servername "$test_domain" 2>/dev/null \
            | openssl x509 -noout -subject -issuer -dates 2>/dev/null \
            || echo -e "  ${MUTED}Could not retrieve certificate${NC}"
        echo

        echo -e "  ${INFO}Supported TLS versions for ${test_domain}:${NC}"
        for proto in tls1_2 tls1_3; do
            if echo | openssl s_client \
                    -connect "${test_domain}:443" \
                    -"$proto" 2>/dev/null | grep -q "Cipher is"; then
                echo -e "  ${SUCCESS}TLS ${proto/tls1_/1.} supported${NC}"
            else
                echo -e "  ${MUTED}TLS ${proto/tls1_/1.} not negotiated${NC}"
            fi
        done
    fi
    echo
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