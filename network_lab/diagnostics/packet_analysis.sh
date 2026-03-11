#!/bin/bash

# /network_lab/diagnostics/packet_analysis.sh
# Work on all Linux computers independent of distro
# Topic: Packet Analysis & Protocol Dissection — Interactive Lab
# Covers: Ethernet/IP/TCP/UDP headers, Wireshark filters, traffic baselining, PCAP analysis

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# ETHERNET FRAME ANATOMY
check_ethernet_frame() {
    header "Ethernet Frame — Layer 2 Header Anatomy"

    cat << 'INFO'
  Ethernet II Frame (IEEE 802.3) structure:

  ┌──────────────┬──────────────┬──────────┬────────────────────┬─────────┐
  │ Dst MAC      │ Src MAC      │ EtherType│ Payload (data)     │   FCS   │
  │  6 bytes     │  6 bytes     │  2 bytes │  46–1500 bytes     │ 4 bytes │
  └──────────────┴──────────────┴──────────┴────────────────────┴─────────┘
  Total min: 64 bytes (with padding)    Max: 1518 bytes (standard)
  Jumbo frames: up to 9000+ bytes (requires switch/NIC support)

  EtherType values (2 bytes — identifies Layer 3 protocol):
    0x0800 — IPv4
    0x86DD — IPv6
    0x0806 — ARP
    0x8100 — 802.1Q VLAN tag
    0x88A8 — 802.1ad QinQ (double VLAN)
    0x8847 — MPLS unicast
    0x88CC — LLDP

  FCS (Frame Check Sequence): CRC-32 over entire frame.
  Dropped silently by NIC on error; you never see corrupted frames in tcpdump.

  802.1Q VLAN Tag (inserted between Src MAC and EtherType):
  ┌──────────┬──────┬─────┬──────────┐
  │ 0x8100   │ PCP  │ DEI │ VID      │
  │ 2 bytes  │ 3bit │ 1bit│ 12 bits  │
  └──────────┴──────┴─────┴──────────┘
  PCP: Priority Code Point (QoS 0-7)
  DEI: Drop Eligible Indicator
  VID: VLAN ID (0-4095)
INFO

    section "Live Ethernet Frame Capture"
    local iface
    iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1)
    echo -e "  ${MUTED}Capturing 5 Ethernet frames on ${iface:-eth0}...${NC}"
    echo
    if cmd_exists tcpdump; then
        sudo -n tcpdump -i "${iface:-eth0}" -c 5 -e -nn 2>/dev/null | while IFS= read -r line; do
            echo -e "  ${CYAN}${line}${NC}"
        done || echo -e "  ${MUTED}Capture unavailable (requires sudo)${NC}"
    else
        echo -e "  ${MUTED}tcpdump not available — install: apt install tcpdump${NC}"
    fi

    section "MTU & Fragmentation"
    echo -e "${INFO}Interface MTU values:${NC}"
    ip -o link show | awk -F': ' '{print $2}' | while read -r iface; do
        mtu=$(cat /sys/class/net/$iface/mtu 2>/dev/null)
        printf "  %-14s MTU: %s\n" "$iface" "$mtu"
    done

    echo
    echo -e "${INFO}Path MTU discovery test (PMTUD):${NC}"
    ping -c 2 -M do -s 1472 8.8.8.8 2>/dev/null | tail -2 | sed 's/^/  /' \
        || echo -e "  ${MUTED}PMTUD test unavailable${NC}"
}

# IP HEADER ANATOMY
check_ip_header() {
    header "IPv4 Header — Layer 3 Anatomy"

    cat << 'INFO'
  IPv4 Header (20 bytes minimum, up to 60 bytes with options):

  Bit offset→  0       4       8               16              24      31
               ┌───────┬───────┬───────────────┬───────────────────────┐
          0-31 │  Ver  │  IHL  │      DSCP/ECN │    Total Length       │
               ├───────────────┼───────────────┼───┬───────────────────┤
         32-63 │ Identification│               │Flags  Fragment Offset │
               ├───────────────┼───────────────┼───┴───────────────────┤
         64-95 │      TTL      │   Protocol    │   Header Checksum     │
               ├───────────────────────────────────────────────────────┤
        96-127 │                Source IP Address                      │
               ├───────────────────────────────────────────────────────┤
       128-159 │              Destination IP Address                   │
               └───────────────────────────────────────────────────────┘

  Field definitions:
    Ver  (4 bits)  : IP version (4 = IPv4)
    IHL  (4 bits)  : Internet Header Length in 32-bit words (min=5 → 20 bytes)
    DSCP (6 bits)  : Differentiated Services (QoS marking)
    ECN  (2 bits)  : Explicit Congestion Notification
    Total Length   : Entire packet size (header + payload), max 65535
    Identification : Fragment group ID (all fragments share this)
    Flags (3 bits) : Bit 1=DF (Don't Fragment), Bit 2=MF (More Fragments)
    Frag Offset    : Position of this fragment (in 8-byte units)
    TTL (8 bits)   : Hops remaining before discard (decremented each hop)
    Protocol       : Payload type: 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP
    Header Checksum: CRC over header only (not payload)
INFO

    section "Protocol Field Values (Layer 4)"
    echo
    printf "  ${BOLD}%-8s %-6s %s${NC}\n" "Decimal" "Hex" "Protocol"
    printf "  ${DARK_GRAY}%-8s %-6s %s${NC}\n" "───────" "─────" "──────────────────"
    while IFS='|' read -r dec hex proto; do
        printf "  ${CYAN}%-8s${NC} ${MUTED}%-6s${NC} %s\n" "$dec" "$hex" "$proto"
    done << 'TABLE'
1|0x01|ICMP — Internet Control Message Protocol
2|0x02|IGMP — Internet Group Management Protocol
6|0x06|TCP — Transmission Control Protocol
17|0x11|UDP — User Datagram Protocol
41|0x29|IPv6 Encapsulation (6in4 tunnels)
47|0x2F|GRE — Generic Routing Encapsulation
50|0x32|ESP — Encapsulating Security Payload (IPSec)
51|0x33|AH — Authentication Header (IPSec)
89|0x59|OSPF — Open Shortest Path First
132|0x84|SCTP — Stream Control Transmission Protocol
TABLE

    section "TTL Fingerprinting"
    cat << 'INFO'
  Initial TTL values reveal the OS of a remote host:
    64   → Linux, macOS, FreeBSD, iOS, Android
    128  → Windows (all versions)
    255  → Cisco IOS, network devices, Solaris
  Actual observed TTL = Initial TTL − hop count
INFO

    echo -e "${INFO}TTL on packets from common hosts:${NC}"
    for host in 8.8.8.8 1.1.1.1; do
        local ttl
        ttl=$(ping -c 1 -W 2 "$host" 2>/dev/null | grep -oP '^\d+: \K[^:@]+' 'ttl=\K\d+')
        if [[ -n "$ttl" ]]; then
            local initial
            if   (( ttl > 64  )); then initial=128
            elif (( ttl > 32  )); then initial=64
            else                       initial=32
            fi
            printf "  ${LABEL}%-14s${NC} TTL: ${GOLD}%-4s${NC} → Initial ~${CYAN}%s${NC}\n" \
                "$host" "$ttl" "$initial"
        fi
    done

    section "IPv6 Header (Fixed 40 Bytes)"
    cat << 'INFO'
  IPv6 Header is FIXED at 40 bytes — no options, no checksum, no fragmentation.
  Extensions: added as chained Next Header fields after the fixed header.

  ┌────────────────────────────────────────────────────────────┐
  │  Version(4) │ Traffic Class(8) │    Flow Label(20)         │
  ├──────────────────────────────────────────────────────────  ┤
  │  Payload Length(16)          │ Next Header(8) │ Hop Lim(8) │
  ├────────────────────────────────────────────────────────────┤
  │               Source Address (128 bits / 16 bytes)         │
  ├────────────────────────────────────────────────────────────┤
  │            Destination Address (128 bits / 16 bytes)       │
  └────────────────────────────────────────────────────────────┘

  Next Header values: 0=Hop-by-Hop, 43=Routing, 44=Fragment,
    50=ESP, 51=AH, 58=ICMPv6, 59=No Next Header, 6/17=TCP/UDP
INFO
}

# TCP HEADER ANATOMY
check_tcp_header() {
    header "TCP Header — Layer 4 Anatomy"

    cat << 'INFO'
  TCP Header (20 bytes minimum):

  Bit offset→  0               16              24      31
               ┌───────────────┬───────────────────────┐
          0-31 │  Source Port  │   Destination Port     │
               ├───────────────────────────────────────┤
         32-63 │            Sequence Number             │
               ├───────────────────────────────────────┤
         64-95 │         Acknowledgment Number          │
               ├───────┬───┬───────────────────────────┤
        96-127 │Data   │Res│ Flags │   Window Size      │
               │Offset │erv│       │                    │
               ├───────────────┼───────────────────────┤
       128-159 │   Checksum    │    Urgent Pointer      │
               └───────────────────────────────────────┘

  TCP Flags (9 bits):
    NS  CWR ECE URG  ACK  PSH  RST  SYN  FIN

  TCP Options (common):
    MSS, Window Scale, SACK, Timestamps, NOP
INFO

    section "TCP Flag Combinations & Meaning"
    echo
    printf "  ${BOLD}%-16s %-10s %s${NC}\n" "Flags" "Name" "Meaning"
    printf "  ${DARK_GRAY}%-16s %-10s %s${NC}\n" "───────────────" "─────────" "────────────────────────────────────"
    while IFS='|' read -r flags name meaning; do
        printf "  ${CYAN}%-16s${NC} ${GOLD}%-10s${NC} ${MUTED}%s${NC}\n" "$flags" "$name" "$meaning"
    done << 'TABLE'
SYN|SYN|Connection initiation (client → server)
SYN+ACK|SYN-ACK|Server acknowledges client SYN
ACK|ACK|Data acknowledgement; connection established
PSH+ACK|DATA|Data segment with immediate delivery request
FIN+ACK|FIN|Graceful connection termination
RST|RST|Abrupt connection reset; port closed
RST+ACK|RST-ACK|Abrupt reset in response to a packet
FIN|FIN|Half-close — this side done sending
URG+ACK|URGENT|Out-of-band data (rare; used by telnet)
SYN+FIN|ILLEGAL|Scanning technique (RFC 793 violation)
NULL (no flags)|NULL|NULL scan — probe for firewall response
ALL flags|XMAS|Xmas scan — probe for response
TABLE

    section "TCP Connection State Machine"
    cat << 'INFO'
  States and transitions:

  CLOSED → [SYN sent] → SYN_SENT → [SYN-ACK rcvd] → ESTABLISHED
  LISTEN → [SYN rcvd] → SYN_RCVD → [ACK rcvd]     → ESTABLISHED
  ESTABLISHED → [FIN sent] → FIN_WAIT_1 → [FIN-ACK rcvd] → FIN_WAIT_2
             → [FIN rcvd]  → CLOSE_WAIT → [FIN sent]      → LAST_ACK
             FIN_WAIT_2    → [FIN rcvd]  → TIME_WAIT (2×MSL=60-120s) → CLOSED

  Key states:
    TIME_WAIT  — Wait to ensure remote side received last ACK (2 min)
    CLOSE_WAIT — App hasn't called close() yet (may indicate application bug)
    SYN_RCVD   — In SYN queue; target of SYN flood → exhausts backlog
INFO

    section "Live TCP Header Analysis"
    echo -e "${INFO}Current TCP connections with state:${NC}"
    echo
    printf "  ${BOLD}%-22s %-22s %-14s${NC}\n" "Local" "Remote" "State"
    printf "  ${DARK_GRAY}%-22s %-22s %-14s${NC}\n" "─────────────────────" "─────────────────────" "─────────────"
    ss -tn 2>/dev/null | tail -n +2 | head -20 | while read -r state recv_q send_q local remote; do
        local sc
        case "$state" in
            ESTAB*)    sc="$SUCCESS" ;;
            TIME-WAIT) sc="$MUTED"   ;;
            CLOSE-WAIT)sc="$WARNING" ;;
            SYN*)      sc="$YELLOW"  ;;
            *)         sc="$CYAN"    ;;
        esac
        printf "  ${CYAN}%-22s${NC} ${MUTED}%-22s${NC} ${sc}%-14s${NC}\n" \
            "$local" "$remote" "$state"
    done

    echo
    echo -e "${INFO}TCP socket statistics:${NC}"
    ss -s 2>/dev/null | grep -E "TCP|estab|closed|orphan|timewait" | sed 's/^/  /'
}

# UDP HEADER & OTHER PROTOCOLS
check_udp_other_headers() {
    header "UDP, ICMP & Other Protocol Headers"

    section "UDP Header (8 bytes — minimal overhead)"
    cat << 'INFO'
  ┌───────────────┬───────────────┐
  │  Source Port  │   Dest Port   │  (2+2 bytes)
  ├───────────────┼───────────────┤
  │    Length     │   Checksum    │  (2+2 bytes)
  └───────────────┴───────────────┘
  Total: 8 bytes fixed. No connection, no reliability, no ordering.
  Checksum is optional in IPv4 (0x0000 = not computed).

  UDP use cases:
    DNS (port 53)     — small queries, low latency needed
    DHCP (67/68)      — broadcast-based; TCP impossible
    VoIP/RTP (>1024)  — timing-sensitive; retransmit is useless
    QUIC (UDP 443)    — HTTP/3; reliability handled in QUIC layer
    TFTP (port 69)    — simple file transfer (embedded systems)
    SNMP (161/162)    — network management
    NTP (port 123)    — time synchronization
INFO

    section "ICMP Message Structure"
    cat << 'INFO'
  ICMP is carried in IP (Protocol 1). No ports.

  ┌────────────┬────────────┬───────────────────────────────┐
  │  Type(8)   │  Code(8)   │        Checksum(16)           │
  ├────────────────────────────────────────────────────────  ┤
  │                Type-specific data                        │
  └──────────────────────────────────────────────────────────┘

  Traceroute mechanism:
    Send UDP/ICMP with TTL=1,2,3...N
    Each router decrements TTL; at TTL=0 → sends ICMP Time Exceeded (Type 11)
    Final destination → ICMP Port Unreachable (Type 3 Code 3) or Echo Reply
INFO

    section "QUIC — HTTP/3 Transport"
    cat << 'INFO'
  QUIC (Quick UDP Internet Connections) — RFC 9000, 2021
  Runs over UDP, provides:
    ✓ Reliable delivery (sequence numbers + ACKs in QUIC layer)
    ✓ Stream multiplexing (no head-of-line blocking like HTTP/2 over TCP)
    ✓ 0-RTT and 1-RTT connection establishment
    ✓ Connection migration (survive IP/port changes on mobile)
    ✓ Mandatory encryption (TLS 1.3 integrated)

  HTTP/3 = HTTP/2 semantics over QUIC
INFO

    section "Live UDP Traffic Analysis"
    echo -e "${INFO}Active UDP sockets:${NC}"
    ss -ulnp 2>/dev/null | tail -n +2 | head -15 | while read -r proto _ _ local _ process; do
        printf "  ${CYAN}%-8s${NC} ${LABEL}%-30s${NC} %s\n" "$proto" "$local" "${process:-}"
    done
}

# WIRESHARK FILTERS
check_wireshark_filters() {
    header "Wireshark & tcpdump Filters"

    section "BPF (Berkeley Packet Filter) Syntax — tcpdump"
    cat << 'INFO'
  BPF filters are applied at capture time (kernel space — efficient).

  Primitives:
    host 192.168.1.1              — src or dst is this IP
    src host 10.0.0.1             — source IP only
    dst host 10.0.0.1             — destination IP only
    net 10.0.0.0/24               — any IP in subnet
    port 443                      — src or dst port 443
    portrange 1024-65535          — port range
    proto tcp / proto udp / icmp  — protocol filter
    ether host aa:bb:cc:dd:ee:ff  — MAC address filter
    vlan 10                       — 802.1Q VLAN ID 10

  Operators: and (&&), or (||), not (!)

  Examples:
    tcpdump -i eth0 'tcp port 80 or tcp port 443'
    tcpdump -i eth0 'src 192.168.1.0/24 and not dst port 22'
    tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'
    tcpdump -i eth0 'tcp[tcpflags] == tcp-rst'
    tcpdump -i eth0 'ip[6:2] & 0x1fff != 0'
    tcpdump -i eth0 -w capture.pcap
    tcpdump -r capture.pcap 'tcp port 80'
INFO

    section "Wireshark Display Filters"
    cat << 'INFO'
  Display filters run AFTER capture (userspace — full protocol awareness).

  Protocol filters:
    tcp  udp  icmp  http  https  dns  dhcp  tls  arp

  Field filters:
    ip.src == 192.168.1.1
    ip.dst == 10.0.0.0/8
    tcp.port == 443
    tcp.flags.syn == 1
    tcp.flags.reset == 1 and tcp.flags.ack == 1
    tcp.analysis.retransmission
    tcp.analysis.out_of_order
    http.request.method == "POST"
    http.response.code == 200
    tls.handshake.type == 1
    dns.qry.name == "malware.example"
    dns.flags.response == 0
    arp.opcode == 2
    frame.time_delta > 1
    ip.ttl < 5
    !(arp or icmp or dns)
    frame contains "password"
INFO

    section "tcpdump One-Liners"
    cat << 'CMDS'
  # Show HTTP GET/POST in ASCII
  tcpdump -i eth0 -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

  # Detect SYN scan
  tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'

  # Capture DNS queries only
  tcpdump -i eth0 -nn 'udp port 53'

  # Monitor for ARP replies (ARP spoofing detection)
  tcpdump -i eth0 -n 'arp[6:2] == 2'

  # Write rotating captures (100MB per file, keep 5)
  tcpdump -i eth0 -G 60 -W 5 -w 'capture-%Y%m%d-%H%M%S.pcap'
CMDS

    section "Live Capture Demo"
    local iface
    iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1)
    read -rp "$(echo -e "  ${PROMPT}Run live 10-packet capture on ${iface:-eth0}? [y/N]:${NC} ")" yn
    if [[ "$yn" =~ ^[yY] ]]; then
        echo
        echo -e "  ${MUTED}Capturing 10 packets — press Ctrl+C to stop early...${NC}"
        echo
        sudo -n tcpdump -i "${iface:-eth0}" -c 10 -nn -q 2>/dev/null | sed 's/^/  /' \
            || echo -e "  ${MUTED}Capture failed — requires sudo or tcpdump${NC}"
    fi
}

# TRAFFIC BASELINING
check_traffic_baselining() {
    header "Traffic Baselining & Anomaly Detection"

    section "What is a Network Baseline?"
    cat << 'INFO'
  A baseline captures normal network behaviour over time:
    - Typical byte/packet counts per interface
    - Common protocol distribution (TCP/UDP/ICMP ratios)
    - Expected connection counts and states
    - DNS query rates and top domains
    - Top talkers (IP pairs with most traffic)

  Deviations from baseline indicate potential issues:
    Spike in SYN packets         → SYN flood / port scan
    Spike in DNS queries         → DNS amplification / tunnelling
    High ICMP volume             → ping flood / data exfil via ICMP
    Unusual outbound ports       → C2 beaconing, data exfiltration
    High UDP on non-standard port→ P2P, tunnelling, crypto mining
INFO

    section "Current Traffic Snapshot (3-second baseline)"
    echo -e "  ${MUTED}Sampling interface statistics...${NC}"
    echo

    local ifaces
    ifaces=$(ip link show 2>/dev/null | grep -oP '^\d+: \K[^:@]+' '^\d+: \K[^:@]+' | grep -v lo)

    declare -A rx1 tx1 rxp1 txp1
    for iface in $ifaces; do
        rx1["$iface"]=$(cat "/sys/class/net/${iface}/statistics/rx_bytes"   2>/dev/null || echo 0)
        tx1["$iface"]=$(cat "/sys/class/net/${iface}/statistics/tx_bytes"   2>/dev/null || echo 0)
        rxp1["$iface"]=$(cat "/sys/class/net/${iface}/statistics/rx_packets" 2>/dev/null || echo 0)
        txp1["$iface"]=$(cat "/sys/class/net/${iface}/statistics/tx_packets" 2>/dev/null || echo 0)
    done

    sleep 3

    echo
    printf "  ${BOLD}%-14s %-16s %-16s %-14s %-14s${NC}\n" \
        "Interface" "RX bytes/s" "TX bytes/s" "RX pkts/s" "TX pkts/s"
    printf "  ${DARK_GRAY}%-14s %-16s %-16s %-14s %-14s${NC}\n" \
        "─────────────" "───────────────" "───────────────" "─────────────" "─────────────"

    for iface in $ifaces; do
        local rx2 tx2 rxp2 txp2
        rx2=$(cat  "/sys/class/net/${iface}/statistics/rx_bytes"   2>/dev/null || echo 0)
        tx2=$(cat  "/sys/class/net/${iface}/statistics/tx_bytes"   2>/dev/null || echo 0)
        rxp2=$(cat "/sys/class/net/${iface}/statistics/rx_packets"  2>/dev/null || echo 0)
        txp2=$(cat "/sys/class/net/${iface}/statistics/tx_packets"  2>/dev/null || echo 0)

        local rxdiff=$(( (rx2  - rx1["$iface"])  / 3 ))
        local txdiff=$(( (tx2  - tx1["$iface"])  / 3 ))
        local rxpdiff=$(( (rxp2 - rxp1["$iface"]) / 3 ))
        local txpdiff=$(( (txp2 - txp1["$iface"]) / 3 ))

        printf "  ${CYAN}%-14s${NC} ${GREEN}%-16s${NC} ${YELLOW}%-16s${NC} ${MUTED}%-14s${NC} %-14s\n" \
            "$iface" "${rxdiff} B/s" "${txdiff} B/s" "${rxpdiff} p/s" "${txpdiff} p/s"
    done

    section "Protocol Distribution (from /proc/net/snmp)"
    echo
    if [[ -r /proc/net/snmp ]]; then
        echo -e "  ${LABEL}TCP Statistics:${NC}"
        paste <(grep "^Tcp:" /proc/net/snmp | head -1 | tr ' ' '\n') \
              <(grep "^Tcp:" /proc/net/snmp | tail -1 | tr ' ' '\n') \
              | tail -n +2 | awk '{printf "  %-28s %s\n", $1":", $2}' | head -8

        echo
        echo -e "  ${LABEL}UDP Statistics:${NC}"
        paste <(grep "^Udp:" /proc/net/snmp | head -1 | tr ' ' '\n') \
              <(grep "^Udp:" /proc/net/snmp | tail -1 | tr ' ' '\n') \
              | tail -n +2 | awk '{printf "  %-28s %s\n", $1":", $2}' | head -6
    fi

    section "Top Connections by Volume"
    echo -e "${INFO}Established connections (current):${NC}"
    ss -tn state established 2>/dev/null | awk 'NR>1{print $5}' | cut -d: -f1 \
        | sort | uniq -c | sort -rn | head -10 \
        | while read -r count ip; do
            printf "  ${GOLD}%4s connections${NC} ← ${CYAN}%s${NC}\n" "$count" "$ip"
        done

    section "Anomaly Indicators to Monitor"
    echo
    local anomalies=(
        "SYN_RECV  >100 : SYN flood / half-open connection attack"
        "CLOSE_WAIT>50  : Application not closing sockets (memory leak)"
        "TIME_WAIT >1000: High connection churn (may need TCP tuning)"
        "RX errors  >0  : Packet loss, bad cable, duplex mismatch"
        "TX drops   >0  : Congestion, buffer overflow"
    )
    for a in "${anomalies[@]}"; do
        local cond="${a%%:*}" desc="${a##*:}"
        printf "  ${WARNING}%-24s${NC} ${MUTED}%s${NC}\n" "$cond" "$desc"
    done

    echo
    echo -e "${INFO}Current socket state counts:${NC}"
    ss -tan 2>/dev/null | awk 'NR>1{print $1}' | sort | uniq -c | sort -rn | \
        while read -r count state; do
            printf "  ${CYAN}%-6s${NC} ${LABEL}%s${NC}\n" "$count" "$state"
        done
}

# PCAP ANALYSIS
check_pcap_analysis() {
    header "PCAP File Analysis"

    section "PCAP File Format"
    cat << 'INFO'
  PCAP (Packet CAPture) — libpcap format, widely supported.
  Magic number: 0xa1b2c3d4 (microsecond) or 0xa1b23c4d (nanosecond)

  File header (24 bytes):
    magic_number (4) | version_major (2) | version_minor (2)
    thiszone (4) | sigfigs (4) | snaplen (4) | network (4)
    network=1: Ethernet, network=113: Linux SLL, network=127: 802.11

  Per-packet header (16 bytes):
    ts_sec (4) | ts_usec (4) | incl_len (4) | orig_len (4)

  Tools:
    tcpdump -r file.pcap            — display
    tshark  -r file.pcap            — Wireshark CLI
    capinfos file.pcap              — file metadata
    editcap -r file.pcap out.pcap 1-100  — slice packets
    mergecap -w out.pcap a.pcap b.pcap   — merge files
INFO

    section "Useful tshark Analysis Commands"
    cat << 'CMDS'
  # Protocol hierarchy statistics
  tshark -r capture.pcap -q -z io,phs

  # Top talkers by IP
  tshark -r capture.pcap -q -z conv,ip

  # HTTP requests
  tshark -r capture.pcap -Y "http.request" -T fields \
    -e frame.time -e ip.src -e http.request.uri

  # Extract DNS queries
  tshark -r capture.pcap -Y "dns.flags.response == 0" \
    -T fields -e ip.src -e dns.qry.name

  # Find cleartext credentials (FTP)
  tshark -r capture.pcap -Y "ftp.request.command == PASS" \
    -T fields -e ftp.request.arg

  # TLS certificate subjects
  tshark -r capture.pcap -Y "tls.handshake.type == 11" \
    -T fields -e x509sat.uTF8String

  # Follow TCP stream
  tshark -r capture.pcap -q -z follow,tcp,ascii,0
CMDS

    section "PCAP Files Available"
    echo -e "${INFO}Checking for capture files:${NC}"
    local pcap_dirs=("/tmp" "$OUTPUT_DIR" "/var/log" "$HOME")
    local found_pcap=0
    for dir in "${pcap_dirs[@]}"; do
        local files
        files=$(find "$dir" -maxdepth 2 \( -name "*.pcap" -o -name "*.pcapng" \) 2>/dev/null | head -5)
        if [[ -n "$files" ]]; then
            echo -e "\n  ${GOLD}${dir}:${NC}"
            echo "$files" | while read -r f; do
                local size
                size=$(du -sh "$f" 2>/dev/null | cut -f1)
                printf "  ${CYAN}%-40s${NC} ${MUTED}%s${NC}\n" "$f" "$size"
            done
            found_pcap=1
        fi
    done
    [[ $found_pcap -eq 0 ]] && status_line neutral "No PCAP files found in common locations"

    section "Quick PCAP Analysis"
    read -rp "$(echo -e "  ${PROMPT}Enter path to a PCAP file to analyse [or press Enter to skip]:${NC} ")" pcap_path
    if [[ -n "$pcap_path" && -f "$pcap_path" ]]; then
        if cmd_exists tshark; then
            echo
            echo -e "${INFO}Capture summary:${NC}"
            capinfos "$pcap_path" 2>/dev/null | sed 's/^/  /' \
                || tshark -r "$pcap_path" -q 2>/dev/null | tail -3 | sed 's/^/  /'

            echo
            echo -e "${INFO}Protocol distribution:${NC}"
            tshark -r "$pcap_path" -q -z io,phs 2>/dev/null | head -25 | sed 's/^/  /'

            echo
            echo -e "${INFO}Top IP conversations:${NC}"
            tshark -r "$pcap_path" -q -z conv,ip 2>/dev/null | head -15 | sed 's/^/  /'
        elif cmd_exists tcpdump; then
            echo
            echo -e "${INFO}First 10 packets:${NC}"
            tcpdump -r "$pcap_path" -nn -q 2>/dev/null | head -10 | sed 's/^/  /'
        else
            log_warning "Install tshark or tcpdump for PCAP analysis"
        fi
    fi
}

main() {
    check_ethernet_frame
    check_ip_header
    check_tcp_header
    check_udp_other_headers
    check_wireshark_filters
    check_traffic_baselining
    check_pcap_analysis

    pause
}

main