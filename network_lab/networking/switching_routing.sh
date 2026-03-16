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
    printf "  ${DARK_GRAY}%-35s %-35s${NC}\n" "$(printf '%.0s' {1..33})" "$(printf '%.0s' {1..33})"
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
    ├ 48-bit hardware address assigned to every NIC
    ├ Format: XX:XX:XX:XX:XX:XX  (hexadecimal, colon-separated)
    ├ OUI  (bytes 1–3) : Manufacturer identifier (IEEE registered)
    ├ NIC ID (bytes 4–6) : Device-specific, assigned by vendor
    ├ Bit 0 of byte 1  : 0 = Unicast      | 1 = Multicast
    └ Bit 1 of byte 1  : 0 = Globally unique (OUI enforced)
                          1 = Locally administered (VM / spoof / random)
 
  Special / Reserved MACs
    ├ FF:FF:FF:FF:FF:FF     — Layer-2 Broadcast (all devices on segment)
    ├ 01:00:5E:xx:xx:xx     — IPv4 Multicast  (RFC 1112)
    ├ 33:33:xx:xx:xx:xx     — IPv6 Multicast  (RFC 2464)
    ├ 01:80:C2:00:00:00     — STP BPDU  (802.1D)
    ├ 01:80:C2:00:00:02     — LACP / slow protocols  (802.3ad)
    └ 00:00:00:00:00:00     — Unset / placeholder
 
  CAM Table (Content Addressable Memory)
    ├ Maintained by the switch; maps  MAC → ingress port
    ├ Populated by inspecting the Source MAC of every received frame
    ├ Entries age out after inactivity (default ≈ 300 s on Cisco)
    ├ Lookup is O(1) — hardware TCAM; no CPU involvement at line rate
    └ CAM Flooding Attack
         └ Attacker sends frames with thousands of spoofed source MACs
            → table fills → switch falls back to flooding all ports
            → attacker receives traffic intended for other hosts (passive sniff)
            → mitigated with: port security, 802.1X, MAC limit per-port
INFO
 
    #  SECTION 1  System Interfaces 
    section "System Network Interfaces & MAC Addresses"
    echo
 
    printf "  ${BOLD}${LABEL}%-16s %-19s %-12s %-10s %-18s${NC}\n" \
        "Interface" "MAC Address" "Type" "Admin" "Link State"
    printf "  ${DARK_GRAY}%-16s %-19s %-12s %-10s %-18s${NC}\n" \
        "-" "-" "-" "-" "-"
 
    # ip -o link show: one line per interface — immune to multi-line output
    while IFS= read -r line; do
        local iface mac flags operstate itype admin_state
 
        iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
        mac=$(echo "$line" | grep -oP 'link/ether \K[0-9a-f:]+')
        flags=$(echo "$line" | grep -oP '<\K[^>]+')
        operstate=$(echo "$line" | grep -oP 'state \K\S+')
 
        # Skip interfaces with no Ethernet MAC (loopback, sit, gre, etc.)
        [[ -z "$mac" ]] && continue
 
        # Determine interface type from name patterns + flags
        itype="Physical"
        [[ "$iface" =~ ^(lo)$              ]] && itype="Loopback"
        [[ "$iface" =~ ^(docker|br-|virbr) ]] && itype="Bridge"
        [[ "$iface" =~ ^veth               ]] && itype="vEth"
        [[ "$iface" =~ ^(tun|tap)          ]] && itype="Tunnel"
        [[ "$iface" =~ \.[0-9]+$           ]] && itype="VLAN"
        [[ "$iface" =~ ^bond               ]] && itype="Bond"
        [[ "$iface" =~ ^dummy              ]] && itype="Dummy"
        [[ "$flags" =~ SLAVE               ]] && itype="Slave"
 
        # Admin state from flags
        admin_state="${FAILURE}DOWN${NC}"
        [[ "$flags" =~ UP ]] && admin_state="${SUCCESS}UP${NC}"
 
        # Operstate colour
        local op_color="$MUTED"
        case "$operstate" in
            UP)             op_color="$SUCCESS" ;;
            DOWN)           op_color="$FAILURE" ;;
            UNKNOWN|LOWERLAYERDOWN) op_color="$WARNING" ;;
        esac
 
        printf "  ${CYAN}%-16s${NC} ${WHITE}%-19s${NC} ${LABEL}%-12s${NC} %-10b ${op_color}%-18s${NC}\n" \
            "$iface" "$mac" "$itype" "$admin_state" "${operstate:-UNKNOWN}"
 
    done < <(ip -o link show 2>/dev/null)
 
    #  SECTION 2  ARP / IPv4 Neighbour Table 
    section "ARP Table — IPv4 Neighbours  (simulated CAM for this host)"
    echo
 
    local arp_count=0 reachable_count=0 stale_count=0 failed_count=0
 
    printf "  ${BOLD}${LABEL}%-18s %-19s %-14s %-12s${NC}\n" \
        "IPv4 Address" "MAC Address" "Interface" "NUD State"
    printf "  ${DARK_GRAY}%-18s %-19s %-14s %-12s${NC}\n" \
        "-" "-" "-" "-"
 
    # Parse ip neigh show with associative extraction — handles missing fields
    while IFS= read -r entry; do
        local n_ip n_iface n_mac n_state n_sc
 
        n_ip=$(echo    "$entry" | awk '{print $1}')
        n_iface=$(echo "$entry" | grep -oP 'dev \K\S+')
        n_mac=$(echo   "$entry" | grep -oP 'lladdr \K[0-9a-f:]+')
        n_state=$(echo "$entry" | awk '{print $NF}')
 
        # Skip IPv6 entries here (handled separately below)
        [[ "$n_ip" =~ : ]] && continue
        # Skip entries with no MAC (FAILED with no lladdr)
        [[ -z "$n_mac" ]] && n_mac="(none)"
 
        n_sc="$MUTED"
        case "$n_state" in
            REACHABLE) n_sc="$SUCCESS"; (( reachable_count++ )) ;;
            STALE)     n_sc="$WARNING"; (( stale_count++ ))     ;;
            FAILED)    n_sc="$FAILURE"; (( failed_count++ ))    ;;
            DELAY|PROBE|INCOMPLETE) n_sc="$AMBER"               ;;
        esac
        (( arp_count++ ))
 
        printf "  ${CYAN}%-18s${NC} ${WHITE}%-19s${NC} ${LABEL}%-14s${NC} ${n_sc}%-12s${NC}\n" \
            "$n_ip" "$n_mac" "$n_iface" "$n_state"
 
    done < <(ip neigh show 2>/dev/null)
 
    if [[ $arp_count -eq 0 ]]; then
        echo -e "  ${MUTED}No ARP entries found.${NC}"
    else
        echo
        printf "  ${MUTED}Summary — Total: ${WHITE}%d${NC}  " "$arp_count"
        printf "${SUCCESS}Reachable: %d${NC}  " "$reachable_count"
        printf "${WARNING}Stale: %d${NC}  "     "$stale_count"
        printf "${FAILURE}Failed: %d${NC}\n"    "$failed_count"
    fi
 
    #  SECTION 3  IPv6 Neighbour Table 
    section "NDP Table — IPv6 Neighbours"
    echo
 
    local ndp_count=0
    printf "  ${BOLD}${LABEL}%-40s %-19s %-14s %-12s${NC}\n" \
        "IPv6 Address" "MAC Address" "Interface" "NUD State"
    printf "  ${DARK_GRAY}%-40s %-19s %-14s %-12s${NC}\n" \
        "-" "-" "-" "-"
 
    while IFS= read -r entry; do
        local n_ip n_iface n_mac n_state n_sc
 
        n_ip=$(echo    "$entry" | awk '{print $1}')
        n_iface=$(echo "$entry" | grep -oP 'dev \K\S+')
        n_mac=$(echo   "$entry" | grep -oP 'lladdr \K[0-9a-f:]+')
        n_state=$(echo "$entry" | awk '{print $NF}')
 
        # IPv6 only
        [[ ! "$n_ip" =~ : ]] && continue
        [[ -z "$n_mac" ]] && n_mac="(none)"
 
        n_sc="$MUTED"
        case "$n_state" in
            REACHABLE) n_sc="$SUCCESS" ;;
            STALE)     n_sc="$WARNING" ;;
            FAILED)    n_sc="$FAILURE" ;;
            DELAY|PROBE|INCOMPLETE) n_sc="$AMBER" ;;
        esac
        (( ndp_count++ ))
 
        printf "  ${CYAN}%-40s${NC} ${WHITE}%-19s${NC} ${LABEL}%-14s${NC} ${n_sc}%-12s${NC}\n" \
            "$n_ip" "$n_mac" "$n_iface" "$n_state"
 
    done < <(ip neigh show 2>/dev/null)
 
    if [[ $ndp_count -eq 0 ]]; then
        echo -e "  ${MUTED}No IPv6 neighbour entries found.${NC}"
    fi
 
    #  SECTION 4  MAC Address Analyser 
    section "MAC Address Analyser"
    echo
    read -rp "$(echo -e "  ${PROMPT}Enter MAC address to analyse [e.g. 00:1A:2B:3C:4D:5E]:${NC} ")" user_mac
    echo
 
    if [[ ! "$user_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        log_warning "Invalid MAC format. Expected XX:XX:XX:XX:XX:XX"
        return 0
    fi
 
    # Normalise to uppercase
    local mac_upper
    mac_upper=$(echo "$user_mac" | tr '[:lower:]' '[:upper:]')
 
    local b1_hex b1_dec
    b1_hex=$(echo "$mac_upper" | cut -d: -f1)
    b1_dec=$(( 16#$b1_hex ))
 
    local oui_raw oui_fmt
    oui_raw=$(echo "$mac_upper" | cut -d: -f1-3 | tr -d ':')
    oui_fmt=$(echo "$mac_upper" | cut -d: -f1-3)
 
    # Bit flags
    local is_multicast is_local
    is_multicast=$(( b1_dec & 1 ))    # bit 0
    is_local=$(( b1_dec & 2 ))        # bit 1
 
    # Binary representation of first byte
    local bin=""
    for (( bit=7; bit>=0; bit-- )); do
        bin+=$(( (b1_dec >> bit) & 1 ))
    done
 
    kv "MAC Address (input)"    "$user_mac"
    kv "Normalised"             "$mac_upper"
    kv "OUI  (bytes 1–3)"       "$oui_fmt"
    kv "NIC ID  (bytes 4–6)"    "$(echo "$mac_upper" | cut -d: -f4-6)"
    echo
    kv "First byte  (hex)"      "0x${b1_hex}"
    kv "First byte  (binary)"   "${bin}  [bit7..bit0]"
    kv "Bit 0  (I/G)"           "$( [[ $is_multicast -eq 0 ]] && echo "0 → Unicast" || echo "1 → Multicast" )"
    kv "Bit 1  (U/L)"           "$( [[ $is_local -eq 0 ]] && echo "0 → Globally unique (OUI-enforced)" || echo "1 → Locally administered (VM / random / spoofed)" )"
    echo
 
    # Special MAC detection
    local mac_lower
    mac_lower=$(echo "$mac_upper" | tr '[:upper:]' '[:lower:]')
    if   [[ "$mac_lower" == "ff:ff:ff:ff:ff:ff" ]]; then
        kv "Special"  "Layer-2 Broadcast"
    elif [[ "$mac_lower" =~ ^01:00:5e ]]; then
        kv "Special"  "IPv4 Multicast (RFC 1112)"
    elif [[ "$mac_lower" =~ ^33:33 ]]; then
        kv "Special"  "IPv6 Multicast (RFC 2464)"
    elif [[ "$mac_lower" == "01:80:c2:00:00:00" ]]; then
        kv "Special"  "STP BPDU (IEEE 802.1D)"
    elif [[ "$mac_lower" == "00:00:00:00:00:00" ]]; then
        kv "Special"  "Unset / placeholder"
    fi
 
    # OUI vendor lookup — try curl, fall back gracefully
    echo
    echo -e "  ${AMBER}OUI Vendor Lookup${NC}"
    if command -v curl &>/dev/null; then
        local vendor response
        echo -e "  ${MUTED}Querying macvendors.com...${NC}"
        response=$(curl -sf --max-time 4 \
            "https://api.macvendors.com/${oui_fmt}" 2>/dev/null)
        if [[ -n "$response" && "$response" != *"errors"* ]]; then
            kv "Vendor" "$response"
        else
            kv "Vendor" "${MUTED}Not found or lookup failed${NC}"
            kv "Manual lookup" "https://macvendors.co  |  https://www.wireshark.org/tools/oui-lookup"
        fi
    else
        kv "Vendor lookup" "${MUTED}curl not available — cannot query online OUI database${NC}"
        kv "Manual lookup" "https://macvendors.co  |  https://www.wireshark.org/tools/oui-lookup"
    fi
 
    # Locally administered note
    if [[ $is_local -ne 0 ]]; then
        echo
        echo -e "  ${WARNING}[~] Locally administered bit is SET.${NC}"
        echo -e "  ${MUTED}    This MAC was not assigned by the manufacturer."
        echo -e "      Common causes: VMware/VirtualBox vNIC, Docker bridge,"
        echo -e "      macchanger spoof, OS privacy randomisation (macOS/iOS/Android/Win11).${NC}"
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

# CAM TABLE FLOODING
cam_flood_simulation() {
    header "CAM Table Flooding — Educational Simulation"
 
    # ── Theory block ──────────────────────────────────────────────────────────
    cat << 'THEORY'
  How a Switch Uses Its CAM Table
    ├─ Every frame received is inspected for its Source MAC
    ├─ The switch records:  Source MAC → ingress port → VLAN  (one entry)
    ├─ On forwarding, the Destination MAC is looked up in the table
    ├─ HIT  → frame is forwarded only to the correct egress port  (unicast)
    └─ MISS → frame is flooded to all ports in the VLAN  (unknown unicast flood)
 
  CAM Table Flooding Attack  (MAC Flood / CAM Overflow)
    ├─ Attacker rapidly injects frames with unique, spoofed Source MACs
    ├─ Each frame creates a new CAM entry until the table is exhausted
    ├─ Once full, the switch cannot learn new MACs
    ├─ All subsequent unknown-destination frames are flooded to every port
    └─ Attacker passively captures traffic intended for other hosts
 
  Real-World Tool:  macof  (part of dsniff suite)
    ├─ Generates ~155,000 spoofed-MAC frames per minute
    ├─ Most commodity switches have 4 K – 128 K CAM entries
    └─ A 16 K-entry table can be exhausted in under 1 second
 
  Defences
    ├─ Port Security       — limit learned MACs per port; violation = shutdown
    ├─ 802.1X              — authenticate before the port joins any VLAN
    ├─ Dynamic ARP Inspection (DAI) — drops ARP replies not in DHCP binding
    ├─ DHCP Snooping       — binding table used by DAI / IP Source Guard
    └─ Private VLANs       — isolate ports; flood blast radius is eliminated
THEORY
 
    echo
    log_info "This simulation is entirely local and passive."
    log_info "No frames are transmitted. No network interfaces are touched."
    echo
 
    # ── Parameters ────────────────────────────────────────────────────────────
    local CAM_SIZE=64          # simulated switch CAM table capacity
    local BATCH=8              # MACs generated per display tick
    local DELAY="0.12"         # seconds between ticks
    local FLOOD_ROUNDS=10      # ticks in flood phase
    local LEGITIMATE_HOSTS=6   # pre-existing legitimate entries
 
    # ── Phase 0 ─ Initial legitimate state ───────────────────────────────────
    section "Phase 0 — Baseline: Legitimate CAM State"
    echo
    log_info "Switch powers on. Legitimate hosts communicate; table builds normally."
    echo
 
    printf "  ${BOLD}${LABEL}%-5s %-19s %-8s %-10s${NC}\n" \
        "Port" "MAC Address" "VLAN" "Age (s)"
    printf "  ${DARK_GRAY}%-5s %-19s %-8s %-10s${NC}\n" \
        "─────" "───────────────────" "────────" "──────────"
 
    local -a legit_macs=()
    local -a legit_ports=(Gi0/1 Gi0/2 Gi0/3 Gi0/4 Gi0/5 Gi0/6)
    local vlan=10
 
    for (( h=0; h<LEGITIMATE_HOSTS; h++ )); do
        local lmac
        lmac=$(_gen_mac)
        legit_macs+=("$lmac")
        printf "  ${CYAN}%-5s${NC} ${WHITE}%-19s${NC} ${LABEL}%-8s${NC} ${SUCCESS}%-10s${NC}\n" \
            "${legit_ports[$h]}" "$lmac" "$vlan" "$(( RANDOM % 280 + 20 ))"
    done
 
    echo
    _cam_bar "$LEGITIMATE_HOSTS" "$CAM_SIZE"
    echo
    log_success "CAM table healthy.  $LEGITIMATE_HOSTS / $CAM_SIZE entries used."
 
    pause
 
    # ── Phase 1 ─ Attack begins ───────────────────────────────────────────────
    section "Phase 1 — Attack Begins: macof-Style MAC Flood"
    echo
    log_warning "Attacker connects to port Gi0/24 and launches MAC flood."
    log_info    "Spoofed frames arrive with unique Source MACs at line rate."
    echo
 
    printf "  ${BOLD}${LABEL}%-5s %-19s %-8s %-14s${NC}\n" \
        "Port" "Injected MAC" "VLAN" "Entry Type"
    printf "  ${DARK_GRAY}%-5s %-19s %-8s %-14s${NC}\n" \
        "─────" "───────────────────" "────────" "──────────────"
 
    local cam_used="$LEGITIMATE_HOSTS"
    local injected=0
    local attacker_port="Gi0/24"
 
    for (( round=0; round<FLOOD_ROUNDS; round++ )); do
        for (( b=0; b<BATCH; b++ )); do
            (( cam_used >= CAM_SIZE )) && break 2
 
            local fmac
            fmac=$(_gen_mac)
            (( cam_used++ ))
            (( injected++ ))
 
            # Colour shifts as table fills
            local entry_color="$SUCCESS"
            local fill_pct=$(( cam_used * 100 / CAM_SIZE ))
            (( fill_pct >= 60 )) && entry_color="$WARNING"
            (( fill_pct >= 85 )) && entry_color="$FAILURE"
 
            printf "  ${CORAL}%-5s${NC} ${entry_color}%-19s${NC} ${LABEL}%-8s${NC} ${AMBER}%-14s${NC}\n" \
                "$attacker_port" "$fmac" "$vlan" "SPOOFED"
        done
 
        sleep "$DELAY"
        echo
        _cam_bar "$cam_used" "$CAM_SIZE"
 
        # Milestone messages
        local pct=$(( cam_used * 100 / CAM_SIZE ))
        if   (( pct >= 50 && pct < 60 && round == 4 )); then
            echo -e "  ${WARNING}[~] 50% — Switch begins dropping new legitimate MACs.${NC}"
        elif (( pct >= 75 && pct < 85 )); then
            echo -e "  ${WARNING}[~] 75% — Port security violations would trigger here on hardened switches.${NC}"
        elif (( pct >= 90 )); then
            echo -e "  ${FAILURE}[!] 90%+ — Table nearly full. Flooding behaviour imminent.${NC}"
        fi
        echo
    done
 
    # ── Phase 2 ─ Table exhausted ─────────────────────────────────────────────
    section "Phase 2 — CAM Table Exhausted: Flooding Mode Active"
    echo
 
    _cam_bar "$CAM_SIZE" "$CAM_SIZE"
    echo
 
    log_error "CAM table is FULL  ($CAM_SIZE / $CAM_SIZE entries)."
    log_warning "Switch can no longer learn new Source MACs."
    echo
 
    cat << 'IMPACT'
  What happens now:
    ├─ Every frame with an unknown Destination MAC is flooded to ALL ports
    ├─ Legitimate host traffic (e.g. Host-A → Host-B) floods to attacker port
    ├─ Attacker runs Wireshark / tcpdump and passively captures all L2 traffic
    ├─ Credentials, session tokens, and plaintext data are exposed
    └─ Switch CPU may spike — flooding at line rate is expensive to process
 
  Traffic visible to attacker:
    ├─ Unencrypted HTTP sessions, FTP credentials, Telnet passwords
    ├─ SMB share traffic, NFS mounts, LDAP binds
    └─ Any protocol without transport-layer encryption (TLS/SSH)
IMPACT
 
    pause
 
    # ── Phase 3 ─ Recovery ────────────────────────────────────────────────────
    section "Phase 3 — Recovery: CAM Table Ages Out"
    echo
    log_info "Attacker disconnects.  CAM entries age out (default timeout ≈ 300 s)."
    log_info "Simulating accelerated ageing for demonstration."
    echo
 
    local recovery_steps=6
    local recovery_interval=$(( CAM_SIZE / recovery_steps ))
 
    for (( step=recovery_steps; step>=0; step-- )); do
        local remaining=$(( step * recovery_interval ))
        (( remaining > CAM_SIZE )) && remaining=$CAM_SIZE
        _cam_bar "$remaining" "$CAM_SIZE"
        sleep "$DELAY"
    done
 
    echo
    _cam_bar "$LEGITIMATE_HOSTS" "$CAM_SIZE"
    echo
    log_success "CAM table recovered.  Only $LEGITIMATE_HOSTS legitimate entries remain."
 
    # ── Summary ───────────────────────────────────────────────────────────────
    section "Simulation Summary"
    echo
    kv "Simulated CAM capacity"   "$CAM_SIZE entries"
    kv "Legitimate hosts"         "$LEGITIMATE_HOSTS"
    kv "Spoofed MACs injected"    "$injected"
    kv "Attack port"              "$attacker_port"
    kv "Flood phase duration"     "$(echo "$DELAY * $FLOOD_ROUNDS" | bc -l | xargs printf '%.1f') s (simulated)"
    kv "Real macof rate"          "~155,000 frames / min"
    kv "Time to flood 16K table"  "< 1 second (real hardware)"
    echo
 
    cat << 'MITIGATION'
  Recommended Mitigations (Cisco IOS syntax shown as reference)
    ├─ Port Security
    │     switchport port-security maximum 5
    │     switchport port-security violation restrict
    │     switchport port-security
    ├─ 802.1X  (strongest — requires RADIUS)
    │     dot1x port-control auto
    ├─ DHCP Snooping  (prerequisite for DAI)
    │     ip dhcp snooping vlan 10
    │     ip dhcp snooping
    └─ Dynamic ARP Inspection
          ip arp inspection vlan 10
MITIGATION
 
    echo
    log_info "No packets were sent. This was a fully local, educational simulation."
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