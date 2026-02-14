#!/bin/bash

###############################################################################
# Topic 1: Networking Basics
# - OSI Model (all 7 layers)
# - TCP/IP Model
# - Bandwidth vs Latency vs Throughput
# - Packet switching vs Circuit switching
###############################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  $1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

section() {
    echo -e "\n${YELLOW}▶ $1${NC}"
    echo "─────────────────────────────────────────────────────"
}

###############################################################################
# 1. OSI MODEL - All 7 Layers
###############################################################################
check_osi_model() {
    header "1. OSI MODEL - 7 LAYERS"
    
    echo -e "${GREEN}The OSI (Open Systems Interconnection) Model has 7 layers:${NC}\n"
    
    echo "Layer 7 - APPLICATION   : User interface, protocols (HTTP, FTP, SMTP, DNS)"
    echo "Layer 6 - PRESENTATION  : Data formatting, encryption, compression"
    echo "Layer 5 - SESSION       : Session management, dialog control"
    echo "Layer 4 - TRANSPORT     : End-to-end connections (TCP, UDP, ports)"
    echo "Layer 3 - NETWORK       : Logical addressing, routing (IP, ICMP)"
    echo "Layer 2 - DATA LINK     : Physical addressing (MAC, switches, frames)"
    echo "Layer 1 - PHYSICAL      : Cables, signals, bits transmission"
    
    section "Checking system components by OSI layer"
    
    # Layer 7 - Application Layer
    echo -e "\n${BLUE}[Layer 7 - Application]${NC}"
    echo "Active network services and listening applications:"
    if command -v ss &> /dev/null; then
        ss -tulpn 2>/dev/null | head -10 || netstat -tulpn 2>/dev/null | head -10
    else
        netstat -tulpn 2>/dev/null | head -10
    fi
    
    # Layer 4 - Transport Layer
    echo -e "\n${BLUE}[Layer 4 - Transport]${NC}"
    echo "TCP/UDP connections and ports:"
    ss -s 2>/dev/null || netstat -s 2>/dev/null | grep -E "(TCP|UDP)" | head -10
    
    # Layer 3 - Network Layer
    echo -e "\n${BLUE}[Layer 3 - Network]${NC}"
    echo "IP routing table:"
    ip route 2>/dev/null || route -n
    
    # Layer 2 - Data Link Layer
    echo -e "\n${BLUE}[Layer 2 - Data Link]${NC}"
    echo "Network interfaces with MAC addresses:"
    ip link show 2>/dev/null || ifconfig -a
    
    # Layer 1 - Physical Layer
    echo -e "\n${BLUE}[Layer 1 - Physical]${NC}"
    echo "Physical network interface status:"
    ip -s link 2>/dev/null | grep -E "(state|RX:|TX:)" || ifconfig | grep -E "(UP|DOWN|RX|TX)"
}

###############################################################################
# 2. TCP/IP MODEL
###############################################################################
check_tcpip_model() {
    header "2. TCP/IP MODEL - 4 Layers"
    
    echo -e "${GREEN}The TCP/IP Model has 4 layers (simplified version of OSI):${NC}\n"
    
    echo "Layer 4 - APPLICATION    : HTTP, FTP, SMTP, DNS, SSH (OSI 5-7)"
    echo "Layer 3 - TRANSPORT      : TCP, UDP, port numbers (OSI 4)"
    echo "Layer 2 - INTERNET       : IP, ICMP, routing (OSI 3)"
    echo "Layer 1 - NETWORK ACCESS : Ethernet, WiFi, ARP (OSI 1-2)"
    
    section "Examining TCP/IP stack on this system"
    
    echo -e "\n${BLUE}[Application Layer Protocols]${NC}"
    echo "DNS servers configured:"
    cat /etc/resolv.conf 2>/dev/null | grep nameserver
    
    echo -e "\n${BLUE}[Transport Layer]${NC}"
    echo "TCP statistics:"
    cat /proc/net/snmp 2>/dev/null | grep "Tcp:" | head -2
    
    echo -e "\n${BLUE}[Internet Layer]${NC}"
    echo "IP addresses on system:"
    ip addr show 2>/dev/null | grep "inet " || ifconfig | grep "inet "
    
    echo -e "\n${BLUE}[Network Access Layer]${NC}"
    echo "ARP cache (IP to MAC mapping):"
    ip neigh show 2>/dev/null || arp -n
}

###############################################################################
# 3. BANDWIDTH vs LATENCY vs THROUGHPUT
###############################################################################
check_bandwidth_concepts() {
    header "3. BANDWIDTH vs LATENCY vs THROUGHPUT"
    
    echo -e "${GREEN}Understanding the differences:${NC}\n"
    
    echo "BANDWIDTH  : Maximum data capacity (like highway lanes)"
    echo "             Measured in: Mbps, Gbps"
    echo ""
    echo "LATENCY    : Time delay for data to travel (like travel time)"
    echo "             Measured in: ms (milliseconds)"
    echo ""
    echo "THROUGHPUT : Actual data transferred (like cars that arrived)"
    echo "             Measured in: Mbps, Gbps (actual, not theoretical)"
    
    section "Testing these concepts on your system"
    
    echo -e "\n${BLUE}[Interface Bandwidth/Speed]${NC}"
    echo "Network interface speeds (maximum bandwidth):"
    for iface in $(ip link show 2>/dev/null | grep -oP '^\d+: \K[^:]+' | grep -v lo); do
        speed=$(ethtool "$iface" 2>/dev/null | grep Speed | awk '{print $2}')
        if [[ -n "$speed" ]]; then
            echo "  $iface: $speed"
        fi
    done
    
    echo -e "\n${BLUE}[Latency Test]${NC}"
    echo "Measuring latency with ping (RTT = Round Trip Time):"
    ping -c 4 -W 2 8.8.8.8 2>/dev/null | grep -E "(time=|rtt)" || echo "Ping not available or no connectivity"
    
    echo -e "\n${BLUE}[Current Throughput]${NC}"
    echo "Interface statistics (RX/TX = actual throughput over time):"
    ip -s link show 2>/dev/null | grep -A1 -E "^\d+:" | head -20 || ifconfig | grep -E "RX|TX"
    
    echo -e "\n${YELLOW}Note: To measure true throughput, you need tools like iperf3 or speedtest-cli${NC}"
}

###############################################################################
# 4. PACKET SWITCHING vs CIRCUIT SWITCHING
###############################################################################
check_switching_types() {
    header "4. PACKET SWITCHING vs CIRCUIT SWITCHING"
    
    echo -e "${GREEN}Two fundamental network switching methods:${NC}\n"
    
    echo "CIRCUIT SWITCHING:"
    echo "  • Dedicated path established before communication"
    echo "  • Resources reserved for entire session"
    echo "  • Example: Traditional telephone networks (PSTN)"
    echo "  • Pros: Guaranteed bandwidth, predictable performance"
    echo "  • Cons: Inefficient, expensive, rigid"
    
    echo ""
    echo "PACKET SWITCHING:"
    echo "  • Data broken into packets, routed independently"
    echo "  • No dedicated path, shared resources"
    echo "  • Example: Internet (IP networks)"
    echo "  • Pros: Efficient, flexible, cost-effective"
    echo "  • Cons: Variable delay, no guaranteed delivery"
    
    section "Demonstrating packet switching on this system"
    
    echo -e "\n${BLUE}[Packet Routing]${NC}"
    echo "Traceroute shows packets taking different paths to destination:"
    echo "Tracing route to google.com (packets may take different paths):"
    traceroute -m 8 -w 2 google.com 2>/dev/null | head -10 || echo "Traceroute not available"
    
    echo -e "\n${BLUE}[Packet Statistics]${NC}"
    echo "IP packet forwarding status:"
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        forward=$(cat /proc/sys/net/ipv4/ip_forward)
        if [[ $forward -eq 1 ]]; then
            echo "  IP forwarding: ENABLED (this system can route packets)"
        else
            echo "  IP forwarding: DISABLED (this system does not route packets)"
        fi
    fi
    
    echo -e "\n${BLUE}[Active Network Connections]${NC}"
    echo "Current packet-switched connections:"
    ss -tn 2>/dev/null | head -10 || netstat -tn 2>/dev/null | head -10
}

###############################################################################
# MAIN EXECUTION
###############################################################################

echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                   NETWORKING BASICS CHECKER                      ║
║                                                                  ║
║  Exploring: OSI Model, TCP/IP, Bandwidth, Latency, Switching    ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

check_osi_model
check_tcpip_model
check_bandwidth_concepts
check_switching_types

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ Networking Basics Check Complete!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"