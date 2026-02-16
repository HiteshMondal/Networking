#!/bin/bash

###############################################################################
# Topic 4: Switching & Routing
# - Switch vs Router
# - MAC address & CAM table
# - VLANs
# - Routing basics
# - Static vs Dynamic routing
# - Routing protocols: RIP, OSPF, BGP (conceptual)
###############################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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
# 1. SWITCH vs ROUTER
###############################################################################
check_switch_vs_router() {
    header "1. SWITCH vs ROUTER"
    
    echo -e "${GREEN}Understanding the difference:${NC}\n"
    
    echo "SWITCH (Layer 2 Device):"
    echo "  • OSI Layer: Data Link (Layer 2)"
    echo "  • Addressing: MAC addresses"
    echo "  • Function: Connects devices in same network (LAN)"
    echo "  • Forwards frames based on MAC table"
    echo "  • Operates within broadcast domain"
    echo "  • Creates separate collision domains per port"
    echo "  • Does NOT route between different networks"
    
    echo ""
    echo "ROUTER (Layer 3 Device):"
    echo "  • OSI Layer: Network (Layer 3)"
    echo "  • Addressing: IP addresses"
    echo "  • Function: Connects different networks (LANs/WANs)"
    echo "  • Routes packets based on routing table"
    echo "  • Separates broadcast domains"
    echo "  • Makes forwarding decisions based on IP"
    echo "  • Can perform NAT, firewall functions"
    
    echo ""
    echo "Layer 3 Switch:"
    echo "  • Hybrid device combining switch + router capabilities"
    echo "  • Can switch at Layer 2 AND route at Layer 3"
    echo "  • VLAN routing, inter-VLAN communication"
    
    section "Examining this system's role"
    
    echo -e "${BLUE}Network interfaces (potential switch ports):${NC}"
    ip link show 2>/dev/null | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//' || ifconfig -a | grep "^[a-z]" | awk '{print $1}'
    
    echo -e "\n${BLUE}IP Forwarding status (routing capability):${NC}"
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        forward=$(cat /proc/sys/net/ipv4/ip_forward)
        if [[ $forward -eq 1 ]]; then
            echo "  ✓ IP Forwarding: ENABLED"
            echo "    This system CAN act as a router"
        else
            echo "  ✗ IP Forwarding: DISABLED"
            echo "    This system acts as an end host, not a router"
        fi
    fi
    
    echo -e "\n${BLUE}Routing table (Layer 3 operation):${NC}"
    ip route show 2>/dev/null || route -n
    
    echo -e "\n${BLUE}Bridge interfaces (switch-like operation):${NC}"
    if command -v brctl &> /dev/null; then
        brctl show 2>/dev/null || echo "No bridges configured"
    elif [[ -d /sys/class/net ]]; then
        echo "Checking for bridge interfaces:"
        for iface in /sys/class/net/*; do
            if [[ -d "$iface/bridge" ]]; then
                echo "  $(basename $iface) - Bridge interface"
            fi
        done
    else
        echo "Bridge tools not available"
    fi
}

###############################################################################
# 2. MAC ADDRESS & CAM TABLE
###############################################################################
check_mac_cam() {
    header "2. MAC ADDRESS & CAM TABLE"
    
    echo -e "${GREEN}Understanding MAC addresses and CAM tables:${NC}\n"
    
    echo "MAC Address (Media Access Control):"
    echo "  • 48-bit (6 bytes) hardware address"
    echo "  • Format: XX:XX:XX:XX:XX:XX (hexadecimal)"
    echo "  • First 3 bytes (OUI): Manufacturer identifier"
    echo "  • Last 3 bytes: Device-specific identifier"
    echo "  • Burned into network interface (NIC)"
    echo "  • Layer 2 addressing"
    
    echo ""
    echo "CAM Table (Content Addressable Memory):"
    echo "  • Switch's MAC address table"
    echo "  • Maps MAC addresses to switch ports"
    echo "  • Learns by examining source MAC of frames"
    echo "  • Forwards frames to specific ports"
    echo "  • Reduces unnecessary traffic"
    
    echo ""
    echo "MAC Address Types:"
    echo "  Unicast   - Single destination (normal traffic)"
    echo "  Multicast - Group of destinations (01:00:5E:...)"
    echo "  Broadcast - All devices (FF:FF:FF:FF:FF:FF)"
    
    section "MAC addresses on this system"
    
    echo -e "${BLUE}All network interfaces with MAC addresses:${NC}"
    ip link show 2>/dev/null | grep -E "link/ether" | awk '{print $2, "on", $NF}' || \
    ifconfig -a | grep -oP "HWaddr \K[0-9a-fA-F:]{17}" || \
    ifconfig -a | grep "ether" | awk '{print $2}'
    
    echo -e "\n${BLUE}Detailed MAC information:${NC}"
    for iface in $(ip link show 2>/dev/null | grep -oP '^\d+: \K[^:]+' | grep -v lo); do
        mac=$(ip link show "$iface" 2>/dev/null | grep -oP 'link/ether \K[0-9a-f:]+')
        if [[ -n "$mac" ]]; then
            echo "Interface: $iface"
            echo "  MAC Address: $mac"
            
            # Extract OUI (first 3 bytes)
            oui=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
            echo "  OUI (Manufacturer): $oui"
            
            # Check if multicast
            first_byte=$(echo "$mac" | cut -d: -f1)
            first_int=$((16#$first_byte))
            if (( (first_int & 1) == 1 )); then
                echo "  Type: Multicast/Broadcast capable"
            else
                echo "  Type: Unicast"
            fi
            echo ""
        fi
    done
    
    section "Neighbor MAC addresses (similar to switch CAM table)"
    
    echo -e "${BLUE}ARP/Neighbor cache (local MAC address table):${NC}"
    echo "This is similar to a switch's CAM table for this system:"
    echo ""
    if command -v ip &> /dev/null; then
        ip neigh show 2>/dev/null | while read -r line; do
            ip=$(echo "$line" | awk '{print $1}')
            mac=$(echo "$line" | grep -oP 'lladdr \K[0-9a-f:]+')
            iface=$(echo "$line" | grep -oP 'dev \K\S+')
            state=$(echo "$line" | grep -oP 'REACHABLE|STALE|DELAY|PROBE|FAILED')
            
            if [[ -n "$mac" ]]; then
                printf "%-15s → %-17s (via %s) [%s]\n" "$ip" "$mac" "$iface" "$state"
            fi
        done
    else
        arp -n 2>/dev/null
    fi
}

###############################################################################
# 3. VLANs (Virtual LANs)
###############################################################################
check_vlans() {
    header "3. VLANs - Virtual Local Area Networks"
    
    echo -e "${GREEN}Understanding VLANs:${NC}\n"
    
    echo "VLAN Purpose:"
    echo "  • Logically segment a physical network"
    echo "  • Create separate broadcast domains"
    echo "  • Improve security (isolate traffic)"
    echo "  • Better network management and organization"
    echo "  • Reduce broadcast traffic"
    
    echo ""
    echo "VLAN Types:"
    echo "  Port-based   - Assign ports to VLANs statically"
    echo "  MAC-based    - Assign based on device MAC"
    echo "  Protocol-based - Assign based on protocol type"
    
    echo ""
    echo "VLAN Tagging (802.1Q):"
    echo "  • 4-byte tag inserted into Ethernet frame"
    echo "  • VLAN ID: 1-4094 (12 bits)"
    echo "  • VLAN 1: Default/native VLAN"
    echo "  • Priority bits: QoS (Quality of Service)"
    
    echo ""
    echo "Trunk vs Access Ports:"
    echo "  Access Port - Carries traffic for ONE VLAN (untagged)"
    echo "  Trunk Port  - Carries traffic for MULTIPLE VLANs (tagged)"
    
    section "VLAN configuration on this system"
    
    echo -e "${BLUE}Checking for VLAN interfaces:${NC}"
    
    vlan_count=0
    if ip link show 2>/dev/null | grep -q "@"; then
        echo "VLAN interfaces found:"
        ip link show 2>/dev/null | grep "@" | while read -r line; do
            vlan_iface=$(echo "$line" | awk '{print $2}' | cut -d@ -f1 | sed 's/:$//')
            parent=$(echo "$line" | awk '{print $2}' | cut -d@ -f2 | sed 's/:$//')
            echo "  $vlan_iface (on $parent)"
            vlan_count=$((vlan_count + 1))
        done
    fi
    
    if command -v cat &> /dev/null && [[ -f /proc/net/vlan/config ]]; then
        echo ""
        echo "VLAN configuration from /proc/net/vlan/config:"
        cat /proc/net/vlan/config 2>/dev/null
    fi
    
    if ! ip link show 2>/dev/null | grep -q "@" && ! [[ -f /proc/net/vlan/config ]]; then
        echo "No VLAN interfaces detected on this system"
        echo ""
        echo "To create a VLAN interface (example):"
        echo "  # ip link add link eth0 name eth0.10 type vlan id 10"
        echo "  # ip addr add 192.168.10.1/24 dev eth0.10"
        echo "  # ip link set dev eth0.10 up"
    fi
    
    section "802.1Q VLAN tagging support"
    
    echo -e "${BLUE}Kernel VLAN support:${NC}"
    if lsmod 2>/dev/null | grep -q "8021q"; then
        echo "  ✓ 802.1Q VLAN kernel module loaded"
    else
        echo "  ○ 802.1Q VLAN module not loaded"
        echo "    Load with: modprobe 8021q"
    fi
}

###############################################################################
# 4. ROUTING BASICS
###############################################################################
check_routing_basics() {
    header "4. ROUTING BASICS"
    
    echo -e "${GREEN}Understanding routing fundamentals:${NC}\n"
    
    echo "Routing Purpose:"
    echo "  • Determine best path for packets between networks"
    echo "  • Forward packets from source to destination"
    echo "  • Uses routing tables to make decisions"
    
    echo ""
    echo "Routing Table Components:"
    echo "  Destination  - Network/host to reach"
    echo "  Gateway      - Next hop router IP"
    echo "  Interface    - Outgoing network interface"
    echo "  Metric       - Cost/preference of route"
    
    echo ""
    echo "Route Types:"
    echo "  Default route (0.0.0.0/0) - Gateway of last resort"
    echo "  Network route             - To specific network"
    echo "  Host route                - To specific host"
    
    section "Routing table on this system"
    
    echo -e "${BLUE}IPv4 routing table:${NC}"
    if command -v ip &> /dev/null; then
        ip route show 2>/dev/null
    else
        route -n 2>/dev/null
    fi
    
    echo -e "\n${BLUE}Default gateway:${NC}"
    default_gw=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1)
    if [[ -n "$default_gw" ]]; then
        echo "  Gateway: $default_gw"
        echo "  All non-local traffic goes through this router"
    else
        echo "  No default gateway configured"
    fi
    
    echo -e "\n${BLUE}IPv6 routing table:${NC}"
    ip -6 route show 2>/dev/null | head -10 || echo "IPv6 routing not configured"
    
    echo -e "\n${BLUE}Routing cache and statistics:${NC}"
    ip route show cache 2>/dev/null | head -10 || echo "No route cache information available"
    
    section "Routing demonstration"
    
    echo -e "${BLUE}Path to external host (8.8.8.8):${NC}"
    ip route get 8.8.8.8 2>/dev/null || echo "Cannot determine route"
    
    echo -e "\n${BLUE}Path to local network host:${NC}"
    local_ip=$(ip route show | grep -oP 'src \K[\d.]+' | head -1)
    if [[ -n "$local_ip" ]]; then
        ip route get "$local_ip" 2>/dev/null
    fi
}

###############################################################################
# 5. STATIC vs DYNAMIC ROUTING
###############################################################################
check_static_dynamic_routing() {
    header "5. STATIC vs DYNAMIC ROUTING"
    
    echo -e "${GREEN}Comparing routing methods:${NC}\n"
    
    echo "STATIC ROUTING:"
    echo "  • Manual configuration by administrator"
    echo "  • Routes don't change unless manually updated"
    echo "  • Pros: Simple, predictable, no overhead, secure"
    echo "  • Cons: Not scalable, no automatic failover"
    echo "  • Use case: Small networks, stub networks"
    
    echo ""
    echo "DYNAMIC ROUTING:"
    echo "  • Routes learned automatically via routing protocols"
    echo "  • Adapts to network topology changes"
    echo "  • Automatic failover and load balancing"
    echo "  • Pros: Scalable, automatic convergence"
    echo "  • Cons: Complex, overhead, potential security issues"
    echo "  • Use case: Large networks, redundant paths"
    
    section "Routing configuration on this system"
    
    echo -e "${BLUE}Current routes analysis:${NC}"
    if ip route show 2>/dev/null | grep -q "proto"; then
        echo "Routes by protocol:"
        ip route show 2>/dev/null | grep -oP "proto \K\w+" | sort | uniq -c
        echo ""
        echo "Route details:"
        ip route show 2>/dev/null | while read -r route; do
            proto=$(echo "$route" | grep -oP "proto \K\w+")
            case $proto in
                kernel) echo "  [KERNEL/AUTO] $route" ;;
                static) echo "  [STATIC]      $route" ;;
                *)      echo "  [DYNAMIC]     $route" ;;
            esac
        done
    else
        route -n 2>/dev/null
    fi
    
    echo -e "\n${BLUE}Dynamic routing daemons:${NC}"
    routing_daemons=(zebra bgpd ospfd ripd)
    found=0
    for daemon in "${routing_daemons[@]}"; do
        if systemctl is-active "$daemon" &>/dev/null || pgrep "$daemon" &>/dev/null; then
            echo "  ✓ $daemon is running"
            found=1
        fi
    done
    
    if [[ $found -eq 0 ]]; then
        echo "  ○ No dynamic routing daemons detected"
        echo "    This system likely uses static routing only"
    fi
}

###############################################################################
# 6. ROUTING PROTOCOLS (RIP, OSPF, BGP)
###############################################################################
check_routing_protocols() {
    header "6. ROUTING PROTOCOLS - RIP, OSPF, BGP"
    
    echo -e "${GREEN}Understanding major routing protocols:${NC}\n"
    
    echo "════════════════════════════════════════════════════════════"
    echo "RIP (Routing Information Protocol):"
    echo "════════════════════════════════════════════════════════════"
    echo "  • Type: Distance Vector"
    echo "  • Metric: Hop count (max 15 hops)"
    echo "  • Algorithm: Bellman-Ford"
    echo "  • Updates: Broadcast every 30 seconds"
    echo "  • Versions: RIPv1 (classful), RIPv2 (classless, VLSM)"
    echo "  • Convergence: Slow"
    echo "  • Use case: Small networks"
    echo "  • Pros: Simple, easy to configure"
    echo "  • Cons: Limited scalability, slow convergence, routing loops"
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "OSPF (Open Shortest Path First):"
    echo "════════════════════════════════════════════════════════════"
    echo "  • Type: Link State"
    echo "  • Metric: Cost (based on bandwidth)"
    echo "  • Algorithm: Dijkstra's SPF (Shortest Path First)"
    echo "  • Updates: Triggered, only changes sent"
    echo "  • Hierarchy: Areas (Area 0 = backbone)"
    echo "  • Convergence: Fast"
    echo "  • Use case: Large enterprise networks"
    echo "  • Pros: Scalable, fast convergence, supports VLSM"
    echo "  • Cons: Complex, more CPU/memory intensive"
    
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "BGP (Border Gateway Protocol):"
    echo "════════════════════════════════════════════════════════════"
    echo "  • Type: Path Vector"
    echo "  • Metric: Path attributes (AS path, etc.)"
    echo "  • Purpose: Interdomain routing (between ISPs)"
    echo "  • Protocol: TCP port 179"
    echo "  • Types: eBGP (external), iBGP (internal)"
    echo "  • Use case: Internet backbone, ISP interconnection"
    echo "  • Pros: Highly scalable, policy-based routing"
    echo "  • Cons: Complex, slow convergence"
    echo "  • Note: Routes the entire Internet!"
    
    section "Protocol comparison table"
    
    cat << 'EOF'

┌─────────────┬─────────────┬─────────────┬─────────────┐
│  Feature    │     RIP     │    OSPF     │     BGP     │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ Type        │ Distance    │ Link State  │ Path Vector │
│             │ Vector      │             │             │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ Metric      │ Hop count   │ Cost        │ Path attrs  │
│             │ (max 15)    │ (bandwidth) │             │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ Convergence │ Slow        │ Fast        │ Slow        │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ Scalability │ Small       │ Medium-     │ Internet-   │
│             │ networks    │ Large       │ scale       │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ Use Case    │ Legacy/     │ Enterprise  │ ISP/        │
│             │ Small LANs  │ Networks    │ Internet    │
└─────────────┴─────────────┴─────────────┴─────────────┘

EOF
    
    section "Checking for routing protocol implementation"
    
    echo -e "${BLUE}Checking for routing software:${NC}"
    
    # Check for FRRouting
    if command -v vtysh &> /dev/null; then
        echo "  ✓ FRRouting (FRR) is installed"
        if systemctl is-active frr &>/dev/null; then
            echo "    Status: Running"
        fi
    fi
    
    # Check for Quagga
    if command -v vtysh &> /dev/null && ! command -v frr &> /dev/null; then
        echo "  ✓ Quagga is installed"
    fi
    
    # Check for BIRD
    if command -v birdc &> /dev/null; then
        echo "  ✓ BIRD (BIRD Internet Routing Daemon) is installed"
    fi
    
    # Check individual daemons
    echo ""
    echo "Routing protocol daemons:"
    for daemon in ripd ospfd bgpd; do
        if pgrep "$daemon" &>/dev/null; then
            echo "  ✓ $daemon is running"
        fi
    done
    
    if ! command -v vtysh &> /dev/null && ! pgrep -x "ripd\|ospfd\|bgpd" &>/dev/null; then
        echo "  ○ No routing protocol software detected"
        echo ""
        echo "To install routing protocols, you can use:"
        echo "  • FRRouting (modern): apt install frr"
        echo "  • BIRD: apt install bird"
    fi
}

###############################################################################
# MAIN EXECUTION
###############################################################################

echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║              SWITCHING & ROUTING CHECKER                         ║
║                                                                  ║
║  Exploring: Switches, Routers, VLANs, Routing Protocols         ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

check_switch_vs_router
check_mac_cam
check_vlans
check_routing_basics
check_static_dynamic_routing
check_routing_protocols

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ Switching & Routing Check Complete!                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"