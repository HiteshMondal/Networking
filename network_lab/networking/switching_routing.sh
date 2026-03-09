#!/bin/bash

# /network_lab/networking/switching_routing.sh
# Topic: Switching & Routing — Interactive Lab
# Covers: Switch vs Router, MAC/CAM, VLANs, Routing Basics, Static vs Dynamic, RIP/OSPF/BGP

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# SWITCH vs ROUTER
check_switch_vs_router() {
    header "Switch vs Router"

    printf "\n  ${BOLD}%-35s %-35s${NC}\n" "SWITCH (Layer 2)" "ROUTER (Layer 3)"
    printf "  ${DARK_GRAY}%-35s %-35s${NC}\n" "$(printf '─%.0s' {1..33})" "$(printf '─%.0s' {1..33})"
    while IFS='|' read -r sw rt; do
        printf "  ${GREEN}%-35s${NC} ${CYAN}%-35s${NC}\n" "$sw" "$rt"
    done << 'TABLE'
OSI Layer 2 (Data Link)|OSI Layer 3 (Network)
MAC address forwarding|IP address routing
Same network (LAN) only|Between different networks
Uses CAM/MAC table|Uses routing table
Reduces collision domains|Separates broadcast domains
No IP needed for basic op|Requires IP configuration
VLANs for segmentation|NAT, ACLs, QoS
Fast (ASIC hardware)|Slower (packet inspection)
Examples: Cisco Catalyst|Examples: Cisco ISR, pfSense
TABLE

    echo
    echo -e "${MUTED}  Layer 3 Switch = Switch + inter-VLAN routing (hardware accelerated)${NC}"

    section "This System's Network Role"

    echo -e "${INFO}Network interfaces:${NC}"
    ip link show 2>/dev/null | grep -E "^[0-9]+:" | while read -r _ iface _ flags; do
        local state
        state=$(echo "$flags" | grep -oP 'state \K\S+' || echo "UNKNOWN")
        local status_color
        [[ "$state" == "UP" ]] && status_color="$SUCCESS" || status_color="$MUTED"
        printf "  ${CYAN}%-14s${NC} ${status_color}%s${NC}\n" "${iface/:/}" "$state"
    done

    echo
    echo -e "${INFO}IP forwarding (routing capability):${NC}"
    local fwd
    fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$fwd" == "1" ]]; then
        status_line ok "IP forwarding ENABLED — acts as a router"
    else
        status_line neutral "IP forwarding DISABLED — acts as an endpoint"
    fi

    echo
    echo -e "${INFO}Bridge interfaces (software switch):${NC}"
    local found_bridge=0
    for iface in /sys/class/net/*; do
        if [[ -d "${iface}/bridge" ]]; then
            echo -e "  ${SUCCESS}$(basename "$iface")${NC} — bridge detected"
            found_bridge=1
        fi
    done
    [[ $found_bridge -eq 0 ]] && status_line neutral "No bridge (software switch) interfaces"

    echo
    echo -e "${INFO}Routing table:${NC}"
    ip route show 2>/dev/null | sed 's/^/  /'
}

# MAC ADDRESS & CAM TABLE
check_mac_cam() {
    header "MAC Addresses & CAM Table"

    cat << 'INFO'
  MAC (Media Access Control) Address
    48-bit hardware address assigned to every NIC
    Format: XX:XX:XX:XX:XX:XX  (hexadecimal, colon-separated)
    OUI (bytes 1-3): Manufacturer identifier (IEEE registered)
    NIC ID (bytes 4-6): Device-specific, assigned by vendor
    Bit 0 of byte 1: 0=Unicast, 1=Multicast
    Bit 1 of byte 1: 0=Globally unique, 1=Locally administered

  Special MACs:
    FF:FF:FF:FF:FF:FF — Broadcast (all devices)
    01:00:5E:xx:xx:xx — IPv4 Multicast range
    33:33:xx:xx:xx:xx — IPv6 Multicast range
    01:80:C2:00:00:00 — STP Bridge Protocol Data Units

  CAM Table (Content Addressable Memory):
    Switch maintains MAC-to-port mappings
    Learns by inspecting source MACs of incoming frames
    Entries timeout after inactivity (default ~300s)
    CAM flooding attack: overflow table → switch acts as hub
INFO

    section "System MAC Addresses"
    echo
    printf "  ${BOLD}%-14s %-20s %-10s %-20s${NC}\n" "Interface" "MAC Address" "Type" "State"
    printf "  ${DARK_GRAY}%-14s %-20s %-10s %-20s${NC}\n" \
        "──────────────" "────────────────────" "──────────" "────────────────────"

    ip link show 2>/dev/null | grep -E "^[0-9]+:" | awk '{print $2}' | tr -d ':' | while read -r iface; do
        local mac state
        mac=$(ip link show "$iface" 2>/dev/null | awk '/link\/ether/{print $2}')
        state=$(ip link show "$iface" 2>/dev/null | grep -oP 'state \K\S+')
        [[ -z "$mac" ]] && continue

        local first_byte
        first_byte=$(echo "$mac" | cut -d: -f1)
        local type="Unicast"
        (( 16#$first_byte & 1 )) && type="Multicast"

        local state_color="$MUTED"
        [[ "$state" == "UP" ]] && state_color="$SUCCESS"

        printf "  ${CYAN}%-14s${NC} ${WHITE}%-20s${NC} ${LABEL}%-10s${NC} ${state_color}%-20s${NC}\n" \
            "$iface" "$mac" "$type" "${state:-UNKNOWN}"
    done

    section "ARP Table (Simulated CAM Table for This Host)"
    echo
    printf "  ${BOLD}%-18s %-20s %-12s %-12s${NC}\n" "IP" "MAC" "Interface" "State"
    printf "  ${DARK_GRAY}%-18s %-20s %-12s %-12s${NC}\n" \
        "──────────────────" "────────────────────" "────────────" "────────────"

    ip neigh show 2>/dev/null | while read -r ip _ iface _ mac state; do
        [[ -z "$mac" || "$mac" == "lladdr" ]] && continue
        local sc="$MUTED"
        [[ "$state" == "REACHABLE" ]] && sc="$SUCCESS"
        [[ "$state" == "FAILED"    ]] && sc="$FAILURE"
        printf "  ${CYAN}%-18s${NC} ${WHITE}%-20s${NC} ${LABEL}%-12s${NC} ${sc}%-12s${NC}\n" \
            "$ip" "$mac" "$iface" "$state"
    done

    section "MAC Address Lookup"
    read -rp "$(echo -e "  ${PROMPT}Enter a MAC address to analyse [e.g. 00:1A:2B:3C:4D:5E]:${NC} ")" user_mac
    if [[ "$user_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        local first
        first=$(echo "$user_mac" | cut -d: -f1)
        local b1=$(( 16#$first ))
        local oui
        oui=$(echo "$user_mac" | tr '[:lower:]' '[:upper:]' | cut -d: -f1-3 | tr -d ':')
        echo
        kv "MAC Address"   "$user_mac"
        kv "OUI (vendor)"  "$oui (look up at https://macvendors.co)"
        [[ $(( b1 & 1 )) -eq 0 ]] && kv "Type" "Unicast" || kv "Type" "Multicast"
        [[ $(( b1 & 2 )) -eq 0 ]] && kv "Scope" "Globally unique (IEEE assigned)" || \
                                      kv "Scope" "Locally administered"
    else
        log_warning "Invalid MAC address format"
    fi
}

# VLANs
check_vlans() {
    header "VLANs — Virtual Local Area Networks"

    cat << 'INFO'
  VLANs logically segment a physical network without extra hardware.
  Each VLAN = separate broadcast domain = isolated Layer 2 segment.

  802.1Q VLAN Tagging:
    4-byte tag inserted between source MAC and EtherType
    [0x8100][PCP 3-bit][DEI 1-bit][VID 12-bit]
    VID range: 1–4094 (0=untagged, 4095=reserved)
    VLAN 1 = default/native (untagged)

  Port Types:
    Access port — single VLAN, untagged frames (end devices)
    Trunk port  — multiple VLANs, tagged frames (switch-to-switch)
    Hybrid port — mix of tagged and untagged

  Inter-VLAN Routing Options:
    1. Router-on-a-stick    — single trunk to router with sub-interfaces
    2. Layer 3 switch       — hardware SVI (Switch Virtual Interfaces)
    3. Separate router port — one physical port per VLAN (wasteful)
INFO

    section "VLAN Configuration on This System"

    echo -e "${INFO}Checking for VLAN interfaces:${NC}"
    local found_vlans=0

    ip link show 2>/dev/null | grep "@" | while read -r _ iface_at_parent _; do
        local token="${iface_at_parent%:}"
        local iface="${token%%@*}"
        local parent="${token##*@}"
        local vid
        vid=$(ip -d link show "$iface" 2>/dev/null | grep -oP 'id \K[0-9]+' | head -1)
        echo -e "  ${SUCCESS}${iface}${NC}  VLAN ID: ${GOLD}${vid:-?}${NC}  Parent: ${CYAN}${parent}${NC}"
        found_vlans=1
    done

    [[ $found_vlans -eq 0 ]] && status_line neutral "No 802.1Q VLAN interfaces detected"

    echo
    echo -e "${INFO}802.1Q kernel module:${NC}"
    if lsmod 2>/dev/null | grep -q "8021q"; then
        status_line ok "8021q module loaded (VLAN-capable)"
    else
        status_line neutral "8021q module not loaded  (load with: sudo modprobe 8021q)"
    fi

    section "VLAN Command Reference"
    cat << 'CMDS'
  Create a VLAN interface:
    sudo ip link add link eth0 name eth0.10 type vlan id 10
    sudo ip addr add 192.168.10.1/24 dev eth0.10
    sudo ip link set dev eth0.10 up

  Delete a VLAN interface:
    sudo ip link delete eth0.10

  List 802.1Q VLAN config (kernel):
    cat /proc/net/vlan/config

  Create a bridge (software switch):
    sudo ip link add name br0 type bridge
    sudo ip link set eth0 master br0
    sudo ip link set dev br0 up
CMDS
}

# ROUTING BASICS
check_routing_basics() {
    header "Routing Fundamentals"

    cat << 'INFO'
  Routing Decision Process (for each packet):
    1. Extract destination IP
    2. Find longest matching prefix in routing table
    3. If found: forward to next-hop or directly to destination
    4. If not found: forward to default gateway
    5. If no default: drop packet (ICMP Unreachable to sender)

  Administrative Distance (preference when multiple sources):
    Connected interface  — 0
    Static route         — 1
    eBGP                 — 20
    OSPF                 — 110
    RIP                  — 120
    External OSPF        — 170
    iBGP                 — 200
INFO

    section "Live Routing Table"
    echo -e "${INFO}IPv4 routing table:${NC}"
    ip route show 2>/dev/null | while read -r line; do
        if echo "$line" | grep -q "^default"; then
            echo -e "  ${GOLD}${line}${NC}"
        elif echo "$line" | grep -q "kernel"; then
            echo -e "  ${GREEN}${line}${NC}"
        else
            echo -e "  ${CYAN}${line}${NC}"
        fi
    done

    echo
    echo -e "${INFO}IPv6 routing table:${NC}"
    ip -6 route show 2>/dev/null | head -10 | sed 's/^/  /' \
        || echo -e "  ${MUTED}IPv6 routing not configured${NC}"

    section "Routing Path Finder"
    read -rp "$(echo -e "  ${PROMPT}Enter destination IP or hostname:${NC} ")" route_dest
    route_dest="${route_dest:-8.8.8.8}"
    if is_valid_ip "$route_dest" || is_valid_host "$route_dest"; then
        echo
        echo -e "${INFO}Route decision for ${route_dest}:${NC}"
        ip route get "$route_dest" 2>/dev/null | sed 's/^/  /' \
            || echo -e "  ${MUTED}Cannot determine route${NC}"

        echo
        echo -e "${INFO}MTR-style path analysis (7 hops):${NC}"
        if cmd_exists mtr; then
            mtr --report --report-cycles 3 -n "$route_dest" 2>/dev/null | head -20 | sed 's/^/  /'
        elif cmd_exists traceroute; then
            traceroute -m 10 -w 2 "$route_dest" 2>/dev/null | head -15 | sed 's/^/  /'
        else
            log_warning "traceroute/mtr not available"
        fi
    else
        log_warning "Invalid destination"
    fi

    section "Default Gateway Analysis"
    local gw
    gw=$(get_gateway)
    if [[ -n "$gw" ]]; then
        kv "Default gateway" "$gw"
        local gw_mac
        gw_mac=$(ip neigh show "$gw" 2>/dev/null | awk '{print $5}')
        kv "Gateway MAC" "${gw_mac:-unknown (ARP not resolved)}"
        ping -c 3 -W 2 -q "$gw" 2>/dev/null | tail -2 | sed 's/^/  /'
    else
        status_line neutral "No default gateway configured"
    fi
}

# STATIC vs DYNAMIC ROUTING
check_static_dynamic_routing() {
    header "Static vs Dynamic Routing"

    cat << 'INFO'
  Static Routing:
    Admin manually adds routes
    No protocol overhead
    Predictable, secure
    No automatic failover
    Best for: stub networks, simple topologies

  Dynamic Routing:
    Routers exchange topology information
    Automatically adapts to changes
    Protocol overhead (CPU, bandwidth)
    Convergence time varies by protocol
    Best for: large, redundant networks
INFO

    section "Route Source Analysis"
    echo -e "${INFO}Routes by protocol source:${NC}"
    echo
    ip route show 2>/dev/null | while read -r route; do
        local proto
        proto=$(echo "$route" | grep -oP 'proto \K\S+')
        local color label
        case "$proto" in
            kernel)  color="$MUTED"    label="[KERNEL]" ;;
            static)  color="$GREEN"    label="[STATIC]" ;;
            dhcp)    color="$YELLOW"   label="[DHCP]"   ;;
            bird|bgp|ospf|rip) color="$CYAN" label="[DYNAMIC:${proto^^}]" ;;
            "")      color="$WHITE"    label="[UNSPEC]" ;;
            *)       color="$ORANGE"   label="[${proto^^}]" ;;
        esac
        printf "  ${color}%-14s${NC} %s\n" "$label" "$route"
    done

    section "Dynamic Routing Daemon Detection"
    local any_daemon=0
    for daemon in zebra bgpd ospfd ripd frr bird; do
        if systemctl is-active "$daemon" &>/dev/null || pgrep -x "$daemon" &>/dev/null; then
            status_line ok "${daemon} is running"
            any_daemon=1
        fi
    done
    [[ $any_daemon -eq 0 ]] && status_line neutral "No dynamic routing daemons detected (using static/kernel routes)"

    section "Add/Delete Static Route Demo (dry-run)"
    cat << 'CMDS'
  Add a static route:
    sudo ip route add 10.10.10.0/24 via 192.168.1.1 dev eth0

  Add a blackhole route (drop traffic silently):
    sudo ip route add blackhole 10.10.10.0/24

  Add a default route:
    sudo ip route add default via 192.168.1.1

  Delete a route:
    sudo ip route del 10.10.10.0/24

  Make persistent (Ubuntu/Debian — netplan):
    Edit /etc/netplan/01-netcfg.yaml
    Add routes: section and run: sudo netplan apply
CMDS
}

# ROUTING PROTOCOLS
check_routing_protocols() {
    header "Routing Protocols — RIP, OSPF, BGP"

    cat << 'TABLE'
┌─────────────────┬──────────────┬────────────────┬────────────────────┐
│ Feature         │  RIP         │  OSPF          │  BGP               │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Type            │ Distance     │ Link State     │ Path Vector        │
│                 │ Vector       │                │                    │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Algorithm       │ Bellman-Ford │ Dijkstra SPF   │ Best Path Select   │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Metric          │ Hop count    │ Bandwidth cost │ Path attributes    │
│                 │ (max 15)     │                │ (AS path, MED...)  │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Convergence     │ Slow (~mins) │ Fast (secs)    │ Slow (minutes)     │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Scalability     │ Small (<15)  │ Large (areas)  │ Internet-scale     │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Transport       │ UDP 520      │ IP proto 89    │ TCP port 179       │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Updates         │ Full every   │ Triggered,     │ Incremental,       │
│                 │ 30 seconds   │ LSA flooding   │ triggered          │
├─────────────────┼──────────────┼────────────────┼────────────────────┤
│ Use Case        │ Legacy LANs  │ Enterprise     │ ISP / Internet     │
└─────────────────┴──────────────┴────────────────┴────────────────────┘
TABLE

    section "OSPF Concepts"
    cat << 'INFO'
  OSPF Areas:
    Area 0 (Backbone) — all other areas must connect here
    Area N            — regular areas (need ABR to reach backbone)
    ABR (Area Border Router) — connects an area to Area 0
    ASBR (AS Boundary Router) — connects OSPF to external routing

  OSPF Router Types:
    DR  (Designated Router)    — elected on multi-access segments
    BDR (Backup DR)            — takes over if DR fails
    DROTHER                    — all other routers

  OSPF LSA Types:
    1 = Router LSA, 2 = Network LSA, 3 = Summary, 5 = External
INFO

    section "BGP Concepts"
    cat << 'INFO'
  BGP AS (Autonomous System):
    A collection of IP prefixes under one administrative policy
    Identified by ASN (Autonomous System Number, 16 or 32-bit)
    Public ASNs: 1–64511 (IANA assigned)
    Private ASNs: 64512–65535

  eBGP vs iBGP:
    eBGP — between different ASes (Internet peering)
    iBGP — within the same AS (internal routing consistency)

  BGP path selection (simplified, in order):
    1. Highest LOCAL_PREF
    2. Shortest AS_PATH
    3. Lowest ORIGIN (IGP < EGP < Incomplete)
    4. Lowest MED
    5. eBGP over iBGP
    6. Lowest IGP metric to next-hop
    7. Lowest router ID
INFO

    section "Routing Software Available"
    for tool in vtysh birdc gobgpd; do
        if cmd_exists "$tool"; then
            status_line ok "$tool is available"
        fi
    done

    echo
    echo -e "${INFO}Install modern routing suite (FRRouting):${NC}"
    echo -e "  ${MUTED}sudo apt install frr${NC}"
    echo -e "  ${MUTED}Then enable protocols in /etc/frr/daemons${NC}"

    section "Live BGP Table (if FRR/BIRD running)"
    if cmd_exists vtysh && pgrep bgpd &>/dev/null; then
        echo -e "${INFO}BGP summary:${NC}"
        sudo vtysh -c "show ip bgp summary" 2>/dev/null | head -20 | sed 's/^/  /'
    elif cmd_exists birdc; then
        birdc show protocol all 2>/dev/null | head -20 | sed 's/^/  /'
    else
        status_line neutral "No BGP daemon running — install FRRouting to explore"
    fi
}

cam_flood_simulation() {
    header "CAM Table Flooding Simulation (Conceptual)"
    echo -e "${INFO}Simulating MAC flooding...${NC}"
    for i in {1..20}; do
        local mac
        mac=$(printf "02:00:%02x:%02x:%02x:%02x\n" $RANDOM $RANDOM $RANDOM $RANDOM)
        echo "Fake MAC injected: $mac"
        sleep 0.1
    done
    echo
    echo -e "${WARNING}Real attack uses tools like macof to overflow switch CAM table${NC}"
}

main() {
    check_switch_vs_router
    check_mac_cam
    check_vlans
    check_routing_basics
    check_static_dynamic_routing
    check_routing_protocols
    cam_flood_simulation
}

main