#!/bin/bash

# /tools/ip_addressing.sh
# Topic: IP & Addressing
# - IPv4 & IPv6
# - Binary, subnetting (CIDR, VLSM)
# - Private vs Public IP
# - NAT, PAT
# - ARP

header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  $1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

section() {
    echo -e "\n${YELLOW}▶ $1${NC}"
    echo "─────────────────────────────────────────────────────"
}

# IPv4 & IPv6
check_ip_versions() {
    header "1. IPv4 vs IPv6"
    
    echo -e "${GREEN}Comparison of IP versions:${NC}\n"
    
    echo "IPv4:"
    echo "  • Address length: 32 bits (4 bytes)"
    echo "  • Format: Dotted decimal (192.168.1.1)"
    echo "  • Total addresses: ~4.3 billion"
    echo "  • Example: 192.168.1.100"
    
    echo ""
    echo "IPv6:"
    echo "  • Address length: 128 bits (16 bytes)"
    echo "  • Format: Hexadecimal with colons (2001:0db8::1)"
    echo "  • Total addresses: 340 undecillion (nearly infinite)"
    echo "  • Example: 2001:0db8:85a3::8a2e:0370:7334"
    
    section "IPv4 addresses on this system"
    
    echo -e "${BLUE}All IPv4 addresses:${NC}"
    ip -4 addr show 2>/dev/null | grep -oP 'inet \K[\d.]+/\d+' || ifconfig | grep "inet " | awk '{print $2}'
    
    section "IPv6 addresses on this system"
    
    echo -e "${BLUE}All IPv6 addresses:${NC}"
    ip -6 addr show 2>/dev/null | grep -oP 'inet6 \K[0-9a-f:]+/\d+' || ifconfig | grep "inet6" | awk '{print $2}'
    
    echo -e "\n${BLUE}IPv6 status:${NC}"
    if ip -6 addr show 2>/dev/null | grep -q "inet6"; then
        echo "  ✓ IPv6 is enabled and configured"
    else
        echo "  ✗ IPv6 is not configured"
    fi
}

# BINARY & SUBNETTING (CIDR, VLSM)

# Function to convert IP to binary
ip_to_binary() {
    local ip=$1
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        printf "%08d " "$(echo "obase=2;$octet" | bc)"
    done
    echo
}

# Function to calculate network details
calculate_subnet() {
    local cidr=$1
    local ip=${cidr%/*}
    local prefix=${cidr#*/}
    
    echo "CIDR Notation: $cidr"
    echo "IP Address:    $ip"
    echo "Prefix Length: /$prefix"
    
    # Calculate subnet mask
    local mask=""
    local bits=$prefix
    for i in {1..4}; do
        if [ $bits -ge 8 ]; then
            mask="${mask}255"
            bits=$((bits - 8))
        elif [ $bits -gt 0 ]; then
            mask="${mask}$((256 - 2 ** (8 - bits)))"
            bits=0
        else
            mask="${mask}0"
        fi
        [ $i -lt 4 ] && mask="${mask}."
    done
    
    echo "Subnet Mask:   $mask"
    echo "Hosts per subnet: $((2 ** (32 - prefix) - 2))"
}

check_subnetting() {
    header "2. BINARY & SUBNETTING (CIDR, VLSM)"
    
    echo -e "${GREEN}Understanding IP addressing in binary and subnetting:${NC}\n"
    
    echo "CIDR (Classless Inter-Domain Routing):"
    echo "  • Notation: IP/prefix (e.g., 192.168.1.0/24)"
    echo "  • /24 means first 24 bits are network, last 8 are host"
    echo "  • Replaces old Class A, B, C system"
    
    echo ""
    echo "VLSM (Variable Length Subnet Mask):"
    echo "  • Different subnets can have different prefix lengths"
    echo "  • Efficient IP address allocation"
    echo "  • Example: /24, /26, /30 in same network"
    
    section "Subnet examples and calculations"
    
    # Example 1: /24 network
    echo -e "\n${BLUE}Example 1: /24 Network (Class C equivalent)${NC}"
    calculate_subnet "192.168.1.0/24"
    echo "Binary: $(ip_to_binary "192.168.1.0")"
    
    # Example 2: /16 network
    echo -e "\n${BLUE}Example 2: /16 Network (Class B equivalent)${NC}"
    calculate_subnet "172.16.0.0/16"
    
    # Example 3: /30 network (point-to-point)
    echo -e "\n${BLUE}Example 3: /30 Network (Point-to-Point links)${NC}"
    calculate_subnet "10.0.0.0/30"
    
    section "Your system's subnet configuration"
    
    echo -e "${BLUE}Network interfaces with CIDR notation:${NC}"
    ip addr show 2>/dev/null | grep -E "inet " | awk '{print $2, "on", $NF}' || \
    ifconfig | grep -A1 "flags" | grep "inet " | awk '{print $2}'
    
    echo -e "\n${BLUE}Common subnet sizes:${NC}"
    cat << EOF
    /32 - 1 host      (255.255.255.255) - Single host
    /30 - 2 hosts     (255.255.255.252) - Point-to-point
    /29 - 6 hosts     (255.255.255.248) - Small network
    /28 - 14 hosts    (255.255.255.240)
    /27 - 30 hosts    (255.255.255.224)
    /26 - 62 hosts    (255.255.255.192)
    /25 - 126 hosts   (255.255.255.128)
    /24 - 254 hosts   (255.255.255.0)   - Standard LAN
    /16 - 65,534 hosts (255.255.0.0)    - Large network
    /8  - 16M hosts   (255.0.0.0)       - Very large
EOF
}

# PRIVATE vs PUBLIC IP
check_ip_types() {
    header "3. PRIVATE vs PUBLIC IP ADDRESSES"
    
    echo -e "${GREEN}Understanding IP address types:${NC}\n"
    
    echo "PRIVATE IP Addresses (RFC 1918):"
    echo "  • 10.0.0.0/8        (10.0.0.0 - 10.255.255.255)"
    echo "  • 172.16.0.0/12     (172.16.0.0 - 172.31.255.255)"
    echo "  • 192.168.0.0/16    (192.168.0.0 - 192.168.255.255)"
    echo "  • Used in local networks, not routable on Internet"
    echo "  • Requires NAT to access Internet"
    
    echo ""
    echo "PUBLIC IP Addresses:"
    echo "  • All other IPv4 addresses (excluding special ranges)"
    echo "  • Globally routable on the Internet"
    echo "  • Must be unique worldwide"
    echo "  • Assigned by ISPs and registries"
    
    echo ""
    echo "SPECIAL IP Ranges:"
    echo "  • 127.0.0.0/8       - Loopback (localhost)"
    echo "  • 169.254.0.0/16    - Link-local (APIPA)"
    echo "  • 224.0.0.0/4       - Multicast"
    echo "  • 0.0.0.0           - Default route/unspecified"
    
    section "Analyzing your system's IP addresses"
    
    echo -e "${BLUE}Checking local IP addresses:${NC}"
    ip -4 addr show 2>/dev/null | grep "inet " | while read -r line; do
        ip=$(echo "$line" | awk '{print $2}' | cut -d'/' -f1)
        iface=$(echo "$line" | awk '{print $NF}')
        
        if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
            echo "  $ip (on $iface) - PRIVATE"
        elif [[ $ip =~ ^127\. ]]; then
            echo "  $ip (on $iface) - LOOPBACK"
        elif [[ $ip =~ ^169\.254\. ]]; then
            echo "  $ip (on $iface) - LINK-LOCAL"
        else
            echo "  $ip (on $iface) - PUBLIC/OTHER"
        fi
    done
    
    echo -e "\n${BLUE}Attempting to detect public IP:${NC}"
    public_ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || curl -s --max-time 3 icanhazip.com 2>/dev/null)
    if [[ -n "$public_ip" ]]; then
        echo "  Your public IP: $public_ip"
    else
        echo "  Unable to detect (no internet or firewall blocking)"
    fi
}

# NAT & PAT
check_nat() {
    header "4. NAT & PAT (Network/Port Address Translation)"
    
    echo -e "${GREEN}Understanding address translation:${NC}\n"
    
    echo "NAT (Network Address Translation):"
    echo "  • Translates private IPs to public IPs"
    echo "  • Allows multiple devices to share one public IP"
    echo "  • Types: Static NAT (1:1), Dynamic NAT (pool)"
    
    echo ""
    echo "PAT (Port Address Translation) / NAT Overload:"
    echo "  • Maps multiple private IPs to ONE public IP"
    echo "  • Uses different source ports to distinguish connections"
    echo "  • Most common type used in home routers"
    echo "  • Also called NAPT (Network Address Port Translation)"
    
    echo ""
    echo "Example PAT translation:"
    echo "  Inside: 192.168.1.10:52000 → Outside: 203.0.113.5:52000"
    echo "  Inside: 192.168.1.20:52001 → Outside: 203.0.113.5:52001"
    echo "  (Same public IP, different ports)"
    
    section "Checking NAT status on this system"
    
    echo -e "${BLUE}NAT/Masquerading configuration:${NC}"
    if command -v iptables &> /dev/null; then
        if sudo iptables -t nat -L -n 2>/dev/null | grep -q MASQUERADE; then
            echo "  ✓ NAT/Masquerading is configured"
            echo ""
            sudo iptables -t nat -L -n -v 2>/dev/null | grep -A5 MASQUERADE
        else
            echo "  ○ NAT/Masquerading not detected in iptables"
        fi
    else
        echo "  ○ iptables not available (cannot check NAT rules)"
    fi
    
    echo -e "\n${BLUE}Connection tracking (conntrack):${NC}"
    if [[ -f /proc/net/nf_conntrack ]]; then
        echo "  Active tracked connections: $(wc -l < /proc/net/nf_conntrack 2>/dev/null)"
        echo "  Sample NAT'd connections:"
        head -5 /proc/net/nf_conntrack 2>/dev/null | grep -i nat || echo "  None found"
    else
        echo "  Connection tracking not available"
    fi
}

# ARP (Address Resolution Protocol)
check_arp() {
    header "5. ARP (Address Resolution Protocol)"
    
    echo -e "${GREEN}Understanding ARP:${NC}\n"
    
    echo "ARP Purpose:"
    echo "  • Maps IP addresses (Layer 3) to MAC addresses (Layer 2)"
    echo "  • Used within local network segments"
    echo "  • Essential for Ethernet communication"
    
    echo ""
    echo "ARP Process:"
    echo "  1. Host needs to send to IP address"
    echo "  2. Checks ARP cache for MAC address"
    echo "  3. If not found, sends ARP broadcast: 'Who has IP X.X.X.X?'"
    echo "  4. Owner responds: 'I have X.X.X.X, my MAC is YY:YY:YY'"
    echo "  5. Requesting host caches this mapping"
    
    echo ""
    echo "ARP Packet Types:"
    echo "  • ARP Request:  Broadcast (FF:FF:FF:FF:FF:FF)"
    echo "  • ARP Reply:    Unicast (specific MAC)"
    
    section "Current ARP cache on this system"
    
    echo -e "${BLUE}ARP table (IP to MAC mappings):${NC}"
    if command -v ip &> /dev/null; then
        ip neigh show 2>/dev/null
    else
        arp -n 2>/dev/null
    fi
    
    echo -e "\n${BLUE}ARP cache statistics:${NC}"
    arp_entries=$(ip neigh show 2>/dev/null | wc -l)
    echo "  Total ARP entries: $arp_entries"
    
    if command -v ip &> /dev/null; then
        reachable=$(ip neigh show | grep -c "REACHABLE" || echo 0)
        stale=$(ip neigh show | grep -c "STALE" || echo 0)
        echo "  REACHABLE: $reachable (recently confirmed)"
        echo "  STALE: $stale (may need refresh)"
    fi
    
    section "ARP demonstration"
    
    echo -e "${BLUE}Performing ARP lookup for gateway:${NC}"
    gateway=$(ip route | grep default | awk '{print $3}' | head -1)
    if [[ -n "$gateway" ]]; then
        echo "Default gateway: $gateway"
        echo "ARP entry:"
        ip neigh show "$gateway" 2>/dev/null || arp -n "$gateway" 2>/dev/null
        
        echo -e "\n${YELLOW}Pinging gateway to refresh ARP...${NC}"
        ping -c 2 -W 1 "$gateway" > /dev/null 2>&1
        echo "Updated ARP entry:"
        ip neigh show "$gateway" 2>/dev/null || arp -n "$gateway" 2>/dev/null
    else
        echo "No default gateway found"
    fi
}

# MAIN EXECUTION
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                  IP & ADDRESSING CHECKER                         ║
║                                                                  ║
║  Exploring: IPv4, IPv6, Subnetting, NAT, ARP                    ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

check_ip_versions
check_subnetting
check_ip_types
check_nat
check_arp

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ IP & Addressing Check Complete!                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"