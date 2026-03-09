#!/bin/bash

# /network_lab/networking/networking_basics.sh
# Topic: Networking Basics
# Covers: OSI Model (all 7 layers), TCP/IP Model, Bandwidth/Latency/Throughput, Packet switching vs Circuit switching

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

#  OSI MODEL
check_osi_model() {
    header "OSI Model — 7 Layers"

    echo -e "${GREEN}The OSI (Open Systems Interconnection) Model:${NC}\n"

    echo -e "  ${BOLD_WHITE}Layer 7 — APPLICATION  ${NC}${MUTED}User interface, protocols (HTTP, FTP, SMTP, DNS)${NC}"
    echo -e "  ${BOLD_WHITE}Layer 6 — PRESENTATION ${NC}${MUTED}Data formatting, encryption, compression${NC}"
    echo -e "  ${BOLD_WHITE}Layer 5 — SESSION      ${NC}${MUTED}Session management, dialog control${NC}"
    echo -e "  ${BOLD_WHITE}Layer 4 — TRANSPORT    ${NC}${MUTED}End-to-end connections (TCP, UDP, ports)${NC}"
    echo -e "  ${BOLD_WHITE}Layer 3 — NETWORK      ${NC}${MUTED}Logical addressing, routing (IP, ICMP)${NC}"
    echo -e "  ${BOLD_WHITE}Layer 2 — DATA LINK    ${NC}${MUTED}Physical addressing (MAC, switches, frames)${NC}"
    echo -e "  ${BOLD_WHITE}Layer 1 — PHYSICAL     ${NC}${MUTED}Cables, signals, bit transmission${NC}"

    section "System Components by OSI Layer"

    echo -e "\n${BLUE}[Layer 7 — Application]${NC}"
    echo -e "${INFO}Active network services:${NC}"
    if cmd_exists ss; then
        ss -tulpn 2>/dev/null | head -10
    else
        netstat -tulpn 2>/dev/null | head -10
    fi

    echo -e "\n${BLUE}[Layer 4 — Transport]${NC}"
    echo -e "${INFO}TCP/UDP socket summary:${NC}"
    ss -s 2>/dev/null || netstat -s 2>/dev/null | grep -E "(TCP|UDP)" | head -10

    echo -e "\n${BLUE}[Layer 3 — Network]${NC}"
    echo -e "${INFO}IP routing table:${NC}"
    ip route 2>/dev/null | sed 's/^/  /' || route -n 2>/dev/null | sed 's/^/  /'

    echo -e "\n${BLUE}[Layer 2 — Data Link]${NC}"
    echo -e "${INFO}Network interfaces with MAC addresses:${NC}"
    ip link show 2>/dev/null | sed 's/^/  /' || ifconfig -a 2>/dev/null | sed 's/^/  /'

    echo -e "\n${BLUE}[Layer 1 — Physical]${NC}"
    echo -e "${INFO}Physical interface status:${NC}"
    ip -s link 2>/dev/null | grep -E "(state|RX:|TX:)" | sed 's/^/  /' \
        || ifconfig 2>/dev/null | grep -E "(UP|DOWN|RX|TX)" | sed 's/^/  /'

    pause
}

#  TCP/IP MODEL
check_tcpip_model() {
    header "TCP/IP Model — 4 Layers"

    echo -e "${GREEN}The TCP/IP Model (simplified version of OSI):${NC}\n"

    printf "  ${BOLD}%-22s %s${NC}\n" "Layer" "Protocols / Function"
    printf "  ${DARK_GRAY}%-22s %s${NC}\n" "──────────────────────" "──────────────────────────────────────"
    printf "  ${CYAN}%-22s${NC} %s\n" "4 — Application"    "HTTP, FTP, SMTP, DNS, SSH  (OSI 5–7)"
    printf "  ${CYAN}%-22s${NC} %s\n" "3 — Transport"      "TCP, UDP, port numbers     (OSI 4)"
    printf "  ${CYAN}%-22s${NC} %s\n" "2 — Internet"       "IP, ICMP, routing          (OSI 3)"
    printf "  ${CYAN}%-22s${NC} %s\n" "1 — Network Access" "Ethernet, WiFi, ARP        (OSI 1–2)"

    section "Examining the TCP/IP Stack"

    echo -e "\n${BLUE}[Application Layer]${NC}"
    echo -e "${INFO}DNS servers configured:${NC}"
    grep nameserver /etc/resolv.conf 2>/dev/null | sed 's/^/  /' \
        || echo -e "  ${MUTED}(not available)${NC}"

    echo -e "\n${BLUE}[Transport Layer]${NC}"
    echo -e "${INFO}TCP statistics:${NC}"
    grep "^Tcp:" /proc/net/snmp 2>/dev/null | paste - - \
        | awk '{for(i=2;i<=NF/2+1;i++) printf "  %-30s %s\n", $i":", $(i+NF/2-1)}' \
        | head -8

    echo -e "\n${BLUE}[Internet Layer]${NC}"
    echo -e "${INFO}IP addresses on this system:${NC}"
    ip addr show 2>/dev/null | grep "inet " | sed 's/^/  /' \
        || ifconfig 2>/dev/null | grep "inet " | sed 's/^/  /'

    echo -e "\n${BLUE}[Network Access Layer]${NC}"
    echo -e "${INFO}ARP cache (IP→MAC mappings):${NC}"
    ip neigh show 2>/dev/null | sed 's/^/  /' \
        || arp -n 2>/dev/null | sed 's/^/  /'

    pause
}

#  BANDWIDTH vs LATENCY vs THROUGHPUT
check_bandwidth_concepts() {
    header "Bandwidth vs Latency vs Throughput"

    echo -e "${GREEN}Understanding the differences:${NC}\n"
    kv "Bandwidth"   "Maximum data capacity  (like highway lanes) — Mbps, Gbps"
    kv "Latency"     "Time delay for data to travel (like travel time) — ms"
    kv "Throughput"  "Actual data transferred (cars that arrived) — Mbps, Gbps"

    section "Interface Bandwidth (Maximum)"
    echo -e "${INFO}Reported link speed per interface:${NC}"
    for eth_iface in $(ip link show 2>/dev/null \
            | grep -oP '^\d+: \K[^:]+' | grep -v lo); do
        local speed
        speed=$(ethtool "$eth_iface" 2>/dev/null | grep -i "^.*speed:" | awk '{print $2}')
        if [[ -n "$speed" ]]; then
            kv "$eth_iface" "$speed"
        fi
    done
    echo -e "  ${MUTED}(No output = virtual/wireless interface or ethtool not available)${NC}"

    section "Latency Measurement"
    echo -e "${INFO}RTT to 8.8.8.8 (Round Trip Time):${NC}"
    ping -c 4 -W 2 8.8.8.8 2>/dev/null | grep -E "(time=|rtt)" | sed 's/^/  /' \
        || echo -e "  ${MUTED}Ping not available or no connectivity${NC}"

    section "Current Throughput Snapshot"
    echo -e "${INFO}Interface RX/TX byte counters:${NC}"
    ip -s link show 2>/dev/null \
        | awk '
            /^[0-9]+: / { iface=$2 }
            /RX:/       { getline; printf "  %-14s RX: %s bytes\n", iface, $1 }
            /TX:/       { getline; printf "  %-14s TX: %s bytes\n", iface, $1 }
        ' \
        || ifconfig 2>/dev/null | grep -E "RX|TX" | sed 's/^/  /'

    echo -e "\n  ${MUTED}Tip: use iperf3 or speedtest-cli for true throughput measurement${NC}"

    pause
}

#  PACKET SWITCHING vs CIRCUIT SWITCHING
check_switching_types() {
    header "Packet Switching vs Circuit Switching"

    echo -e "${GREEN}Two fundamental network switching methods:${NC}\n"

    section "Circuit Switching"
    echo -e "  ${MUTED}• Dedicated path established before communication${NC}"
    echo -e "  ${MUTED}• Resources reserved for entire session${NC}"
    echo -e "  ${MUTED}• Example: Traditional telephone networks (PSTN)${NC}"
    echo -e "  ${GREEN}+ Guaranteed bandwidth, predictable performance${NC}"
    echo -e "  ${YELLOW}− Inefficient (idle capacity wasted), expensive, rigid${NC}"

    section "Packet Switching"
    echo -e "  ${MUTED}• Data broken into packets, each routed independently${NC}"
    echo -e "  ${MUTED}• No dedicated path — shared resources${NC}"
    echo -e "  ${MUTED}• Example: The Internet (IP networks)${NC}"
    echo -e "  ${GREEN}+ Efficient, flexible, cost-effective${NC}"
    echo -e "  ${YELLOW}− Variable delay, no guaranteed delivery${NC}"

    section "Packet Switching in Action"

    echo -e "${INFO}IP forwarding status:${NC}"
    local fwd
    fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$fwd" == "1" ]]; then
        status_line ok "IP forwarding ENABLED — this host routes/forwards packets"
    else
        status_line neutral "IP forwarding DISABLED — endpoint mode (normal workstation)"
    fi

    echo
    echo -e "${INFO}Traceroute — packets taking hops through the Internet:${NC}"
    if cmd_exists traceroute; then
        traceroute -m 8 -w 2 google.com 2>/dev/null | head -10 | sed 's/^/  /'
    elif cmd_exists tracepath; then
        tracepath -n google.com 2>/dev/null | head -10 | sed 's/^/  /'
    else
        echo -e "  ${MUTED}traceroute/tracepath not available${NC}"
    fi

    echo
    echo -e "${INFO}Current packet-switched connections:${NC}"
    ss -tn 2>/dev/null | head -10 | sed 's/^/  /' \
        || netstat -tn 2>/dev/null | head -10 | sed 's/^/  /'

    pause
}

main() {
    check_osi_model
    check_tcpip_model
    check_bandwidth_concepts
    check_switching_types
}

main