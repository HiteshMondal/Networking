#!/bin/bash

# /network_lab/diagnostics/ip_addressing.sh
# Work on all Linux computers independent of distro
# Topic: IP & Addressing — Interactive Lab
# Covers: IPv4/IPv6, Subnetting (CIDR/VLSM), Private/Public, NAT/PAT, ARP

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

#  HELPERS

# Convert an IP octet to 8-char zero-padded binary
octet_to_bin() {
    local n=$1
    local bits=""
    for (( i=7; i>=0; i-- )); do
        (( (n >> i) & 1 )) && bits+="1" || bits+="0"
    done
    echo "$bits"
}

# Convert full IPv4 to dotted binary
ip_to_binary() {
    local ip="$1"
    IFS='.' read -ra o <<< "$ip"
    local b=""
    for i in "${!o[@]}"; do
        b+="$(octet_to_bin "${o[$i]}")"
        [[ $i -lt 3 ]] && b+="."
    done
    echo "$b"
}

# Compute subnet details from CIDR
subnet_details() {
    local cidr="$1"
    local ip="${cidr%/*}" prefix="${cidr#*/}"
    local mask_int
    if (( prefix == 0 )); then
        mask_int=0
    else
        mask_int=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi
    local mask_a=$(( (mask_int >> 24) & 0xFF ))
    local mask_b=$(( (mask_int >> 16) & 0xFF ))
    local mask_c=$(( (mask_int >> 8)  & 0xFF ))
    local mask_d=$(( mask_int & 0xFF ))
    local mask="${mask_a}.${mask_b}.${mask_c}.${mask_d}"

    IFS='.' read -ra ipo <<< "$ip"
    local ip_int=$(( (ipo[0] << 24) | (ipo[1] << 16) | (ipo[2] << 8) | ipo[3] ))

    local net_int=$(( ip_int & mask_int ))
    local na=$(( (net_int >> 24) & 0xFF ))
    local nb=$(( (net_int >> 16) & 0xFF ))
    local nc=$(( (net_int >> 8)  & 0xFF ))
    local nd=$(( net_int & 0xFF ))
    local network="${na}.${nb}.${nc}.${nd}"

    local bc_int=$(( net_int | (0xFFFFFFFF >> prefix) ))
    local ba=$(( (bc_int >> 24) & 0xFF ))
    local bb=$(( (bc_int >> 16) & 0xFF ))
    local bc=$(( (bc_int >> 8)  & 0xFF ))
    local bd=$(( bc_int & 0xFF ))
    local broadcast="${ba}.${bb}.${bc}.${bd}"

    local fh_int=$(( net_int + 1 ))
    local lh_int=$(( bc_int - 1 ))
    local fha=$(( (fh_int >> 24) & 0xFF ))
    local fhb=$(( (fh_int >> 16) & 0xFF ))
    local fhc=$(( (fh_int >> 8)  & 0xFF ))
    local fhd=$(( fh_int & 0xFF ))
    local first_host="${fha}.${fhb}.${fhc}.${fhd}"

    local lha=$(( (lh_int >> 24) & 0xFF ))
    local lhb=$(( (lh_int >> 16) & 0xFF ))
    local lhc=$(( (lh_int >> 8)  & 0xFF ))
    local lhd=$(( lh_int & 0xFF ))
    local last_host="${lha}.${lhb}.${lhc}.${lhd}"

    local hosts
    if (( prefix >= 31 )); then
        hosts=$(( prefix == 31 ? 2 : 1 ))
    else
        hosts=$(( (1 << (32 - prefix)) - 2 ))
    fi

    echo "CIDR Notation:  ${cidr}"
    echo "IP Address:     ${ip}"
    echo "Subnet Mask:    ${mask}"
    echo "Prefix Length:  /${prefix}"
    echo "Network:        ${network}/${prefix}"
    echo "Broadcast:      ${broadcast}"
    echo "First Host:     ${first_host}"
    echo "Last Host:      ${last_host}"
    echo "Usable Hosts:   ${hosts}"
    echo "IP in Binary:   $(ip_to_binary "$ip")"
    echo "Mask in Binary: $(ip_to_binary "$mask")"
}

# Classify an IP
classify_ip() {
    local ip="$1"
    if   [[ "$ip" =~ ^10\.                   ]]; then echo "PRIVATE (RFC1918 10.0.0.0/8)"
    elif [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then echo "PRIVATE (RFC1918 172.16-31.x.x)"
    elif [[ "$ip" =~ ^192\.168\.             ]]; then echo "PRIVATE (RFC1918 192.168.0.0/16)"
    elif [[ "$ip" =~ ^127\.                  ]]; then echo "LOOPBACK"
    elif [[ "$ip" =~ ^169\.254\.             ]]; then echo "LINK-LOCAL (APIPA)"
    elif [[ "$ip" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then echo "SHARED (CGNAT RFC6598)"
    elif [[ "$ip" =~ ^(198\.51\.100\.|203\.0\.113\.|192\.0\.2\.) ]]; then echo "DOCUMENTATION (TEST)"
    elif [[ "$ip" =~ ^224\.                  ]]; then echo "MULTICAST"
    elif [[ "$ip" =~ ^240\.                  ]]; then echo "RESERVED (Class E)"
    elif [[ "$ip" == "255.255.255.255"       ]]; then echo "BROADCAST"
    elif [[ "$ip" == "0.0.0.0"              ]]; then echo "UNSPECIFIED"
    else echo "PUBLIC / GLOBAL UNICAST"
    fi
}

# IPv4 & IPv6
check_ip_versions() {
    header "IPv4 vs IPv6"

    printf "\n  ${BOLD}%-35s %-35s${NC}\n" "IPv4" "IPv6"
    printf "  ${DARK_GRAY}%-35s %-35s${NC}\n" "$(printf '─%.0s' {1..33})" "$(printf '─%.0s' {1..33})"
    while IFS='|' read -r f4 f6; do
        printf "  ${GREEN}%-35s${NC} ${CYAN}%-35s${NC}\n" "$f4" "$f6"
    done << 'TABLE'
32-bit address (4 bytes)|128-bit address (16 bytes)
Dotted decimal notation|Colon-hex notation
~4.3 billion addresses|340 undecillion addresses
Manual/DHCP configuration|SLAAC or DHCPv6
Broadcast supported|No broadcast (multicast)
Optional IPSec|Built-in IPSec
Header: 20 bytes min|Header: 40 bytes fixed
NAT widely required|NAT not needed
TABLE

    section "System IPv4 Addresses"
    ip -4 -o addr show | while read -r _ iface _ cidr _; do
        local ip="${cidr%/*}"
        printf "  ${LABEL}%-12s${NC} ${WHITE}%-18s${NC} ${MUTED}%s${NC}\n" \
            "$iface" "$cidr" "($(classify_ip "$ip"))"
    done

    section "System IPv6 Addresses"
    ip -6 -o addr show | while read -r _ iface _ addr _ scope _; do
        printf "  ${CYAN}%-40s${NC} ${MUTED}%s${NC}\n" "$addr" "$scope"
    done

    echo
    echo -e "${INFO}IPv6 global connectivity check:${NC}"
    if ping -6 -c 2 -W 2 2001:4860:4860::8888 &>/dev/null; then
        status_line ok "IPv6 Internet connectivity available"
    else
        status_line neutral "IPv6 Internet not reachable (or not configured)"
    fi

    header "IPv6 Security Analysis"
    echo -e "${INFO}Checking IPv6 exposure...${NC}"
    ip -6 route show | sed 's/^/  /'
    echo
    echo -e "${INFO}Listening IPv6 services:${NC}"
    if cmd_exists ss; then
        ss -ltn6
    else
        status_line neutral "ss not installed"
    fi
    echo
    echo -e "${WARNING}IPv6 often bypasses IPv4 firewall rules${NC}"
}

ip_fragmentation_analysis() {
    header "IP Fragmentation Analysis"

    echo -e "${INFO}Checking MTU and fragmentation behavior...${NC}"

    local target="8.8.8.8"

    for size in 1472 1500 2000; do
        echo -e "\n${CYAN}Testing packet size: $size${NC}"
        ping -c 1 -s "$size" -M do "$target" 2>&1 | \
            grep -E "frag needed|Message too long|bytes from" | sed 's/^/  /'
    done

    echo
    echo -e "${WARNING}If fragmentation occurs → possible MTU issues or filtering${NC}"
}

ip_geolocation() {
    header "IP Geolocation"

    read -rp "Enter IP: " ip

    if ! is_valid_ip "$ip"; then
        log_warning "Invalid IP"
        return
    fi

    curl -s --max-time 5 https://ip-api.com/json/$ip | \
        grep -E '"country"|"regionName"|"city"|"isp"' | sed 's/[",]//g' | sed 's/^/  /'
}

reverse_dns_check() {
    header "Reverse DNS (PTR) Consistency Check"

    read -rp "Enter IP: " ip

    if ! is_valid_ip "$ip"; then
        log_warning "Invalid IP"
        return
    fi

    local ptr

    if cmd_exists dig; then
        ptr=$(dig +short -x "$ip")
    elif cmd_exists host; then
        ptr=$(host "$ip" | awk '{print $5}' | sed 's/\.$//')
    else
        log_warning "No DNS lookup tool available"
        return
    fi

    if [[ -z "$ptr" ]]; then
        status_line neutral "No PTR record found"
    else
        kv "PTR Record" "$ptr"

        echo -e "${INFO}Forward resolving PTR...${NC}"
        if cmd_exists dig; then
            dig +short "$ptr"
        elif cmd_exists host; then
            host "$ptr"
        fi
    fi
}

# Subnetting Calculator
check_subnetting() {
    header "Subnetting Calculator (CIDR / VLSM)"

    cat << 'INFO'
  CIDR (Classless Inter-Domain Routing)
    Notation: network/prefix  e.g. 192.168.1.0/24
    The prefix specifies how many bits are the network portion.

  VLSM (Variable Length Subnet Masking)
    Different subnets can use different prefix lengths within
    the same address space — maximises IP efficiency.
INFO

    section "Interactive Subnet Calculator"
    read -rp "$(echo -e "  ${PROMPT}Enter a CIDR address [e.g. 10.0.0.0/22]:${NC} ")" user_cidr
    user_cidr="${user_cidr:-10.0.0.0/22}"
    if is_valid_cidr "$user_cidr"; then
        echo
        subnet_details "$user_cidr" | while IFS= read -r line; do
            local key="${line%%:*}"
            local val="${line#*: }"
            printf "  ${LABEL}%-20s${NC} ${WHITE}%s${NC}\n" "${key}:" "$val"
        done
    else
        log_warning "Invalid CIDR — showing built-in examples instead"
    fi

    section "VLSM Example — Dividing 192.168.0.0/24"
    local examples=("192.168.0.0/25" "192.168.0.128/26" "192.168.0.192/27" "192.168.0.224/28")
    for cidr in "${examples[@]}"; do
        echo -e "\n  ${GOLD}${BOLD}${cidr}${NC}"
        subnet_details "$cidr" | grep -E "Subnet Mask|First Host|Last Host|Usable" | \
            while IFS= read -r line; do
                echo "  $line"
            done
    done

    section "CIDR Quick Reference"
    echo
    printf "  ${BOLD}%-6s %-18s %-14s %-10s${NC}\n" "CIDR" "Subnet Mask" "Hosts" "Use Case"
    printf "  ${DARK_GRAY}%-6s %-18s %-14s %-10s${NC}\n" "──────" "──────────────────" "──────────────" "──────────"
    while IFS='|' read -r prefix mask hosts usecase; do
        printf "  ${CYAN}%-6s${NC} %-18s ${GOLD}%-14s${NC} ${MUTED}%s${NC}\n" \
            "/$prefix" "$mask" "$hosts" "$usecase"
    done << 'TABLE'
32|255.255.255.255|1 host|Single host route
31|255.255.255.254|2 hosts|Point-to-point link
30|255.255.255.252|2 hosts|P2P with broadcast
29|255.255.255.248|6 hosts|Small segment
28|255.255.255.240|14 hosts|Office subnet
27|255.255.255.224|30 hosts|Mid office
26|255.255.255.192|62 hosts|Department
25|255.255.255.128|126 hosts|Mid LAN
24|255.255.255.0|254 hosts|Standard LAN
23|255.255.254.0|510 hosts|Large LAN
22|255.255.252.0|1022 hosts|Campus segment
20|255.255.240.0|4094 hosts|Enterprise LAN
16|255.255.0.0|65534 hosts|Large enterprise
8|255.0.0.0|16.7M hosts|ISP / cloud
TABLE
}

subnet_overlap_check() {
    header "Subnet Overlap Detection"

    read -rp "Enter CIDR 1: " c1
    read -rp "Enter CIDR 2: " c2

    if ! is_valid_cidr "$c1" || ! is_valid_cidr "$c2"; then
        log_warning "Invalid CIDR(s)"
        return
    fi

    local n1
    n1=$(subnet_details "$c1" | awk -F': *' '/Network/ {print $2}')
    local n2
    n2=$(subnet_details "$c2" | grep Network | awk '{print $2}')

    echo -e "${INFO}Basic comparison:${NC}"
    echo "  $c1 vs $c2"

    if [[ "$n1" == "$n2" ]]; then
        status_line ok "Possible overlap (same network)"
    else
        status_line neutral "Different networks (manual validation needed)"
    fi
}

# Private vs Public IP
check_ip_types() {
    header "Private vs Public IP Addresses"

    cat << 'INFO'
  RFC 1918 Private Ranges (not Internet-routable):
    10.0.0.0/8       — Class A private (10.0.0.0 – 10.255.255.255)
    172.16.0.0/12    — Class B private (172.16.0.0 – 172.31.255.255)
    192.168.0.0/16   — Class C private (192.168.0.0 – 192.168.255.255)

  Other Special Ranges:
    127.0.0.0/8      — Loopback (localhost)
    169.254.0.0/16   — Link-local (APIPA — auto-assigned when DHCP fails)
    100.64.0.0/10    — CGNAT shared space (RFC 6598)
    224.0.0.0/4      — Multicast
    240.0.0.0/4      — Reserved (Class E)
    0.0.0.0/8        — This network (unspecified)
INFO

    section "Classify This System's Addresses"
    ip -4 -o addr show | while read -r _ iface _ cidr _; do
        local ip="${cidr%/*}"
        local class
        class=$(classify_ip "$ip")
        case "$class" in
            *PRIVATE*)  echo -e "  ${CYAN}${iface}${NC} ${ip} → ${GREEN}${class}${NC}" ;;
            *PUBLIC*)   echo -e "  ${CYAN}${iface}${NC} ${ip} → ${GOLD}${class}${NC}" ;;
            *LOOPBACK*) echo -e "  ${CYAN}${iface}${NC} ${ip} → ${MUTED}${class}${NC}" ;;
            *)          echo -e "  ${CYAN}${iface}${NC} ${ip} → ${YELLOW}${class}${NC}" ;;
        esac
    done

    section "Interactive IP Classifier"
    read -rp "$(echo -e "  ${PROMPT}Enter any IPv4 address to classify:${NC} ")" user_ip
    if is_valid_ip "$user_ip"; then
        echo -e "  ${WHITE}${user_ip}${NC} → ${GOLD}$(classify_ip "$user_ip")${NC}"
        ip_to_binary "$user_ip" | sed 's/^/  Binary: /'
    else
        log_warning "Invalid IP address entered"
    fi

    section "Public IP Detection"
    echo -e "  ${MUTED}Querying external IP services...${NC}"
    local pub
    pub=$(get_public_ip)
    if [[ "$pub" != "unavailable" ]]; then
        status_line ok "Your public IP: ${pub}"
    else
        status_line neutral "Unable to detect public IP (offline or blocked)"
    fi
}

# NAT & PAT
check_nat() {
    header "NAT & PAT — Network/Port Address Translation"

    cat << 'INFO'
  Static NAT   — 1-to-1 mapping (one private IP ↔ one public IP)
  Dynamic NAT  — pool of public IPs shared across private hosts
  PAT/NAPT     — many private IPs → ONE public IP, differentiated by port
                  (Also called "NAT overload" — used in all home routers)

  NAT Types (for P2P/gaming):
    Full Cone     — most permissive, any external can reach
    Restricted    — external can reach if we sent first
    Port Restricted — external must match IP + port
    Symmetric     — strictest, maps each connection uniquely
INFO

    section "NAT/iptables Status"
    if cmd_exists iptables; then
        if sudo -n iptables -t nat -L -n 2>/dev/null | grep -qE "MASQUERADE|SNAT|DNAT"; then
            status_line ok "NAT/masquerade rules detected"
            echo
            echo -e "${INFO}NAT rules:${NC}"
            sudo -n iptables -t nat -L -n -v 2>/dev/null | grep -v "^Chain\|^target\|^$" | head -20 | sed 's/^/  /'
        elif cmd_exists nft; then
            nft list ruleset | grep -E "snat|dnat|masquerade"
        else
            status_line neutral "No NAT rules in iptables (this host is not a NAT router)"
        fi
    fi

    echo
    echo -e "${INFO}IP forwarding (required for NAT routing):${NC}"
    local fwd
    fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$fwd" == "1" ]]; then
        status_line ok "IP forwarding ENABLED — this host can forward/route packets"
    else
        status_line neutral "IP forwarding DISABLED — endpoint mode (normal workstation)"
    fi

    section "Connection Tracking"
    if [[ -f /proc/net/nf_conntrack ]]; then
        local total
        total=$(wc -l < /proc/net/nf_conntrack 2>/dev/null)
        kv "Tracked connections" "$total"
        kv "conntrack max" "$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 'N/A')"
        echo
        echo -e "${INFO}Active NAT translations (first 10):${NC}"
        grep "dnat\|snat" /proc/net/nf_conntrack 2>/dev/null | head -10 | sed 's/^/  /' \
            || echo -e "  ${MUTED}No NAT translations found${NC}"
    else
        status_line neutral "Connection tracking not available (nf_conntrack module not loaded)"
    fi
}

# ARP
check_arp() {
    header "ARP — Address Resolution Protocol"

    cat << 'INFO'
  ARP resolves a Layer-3 IP address to a Layer-2 MAC address
  so Ethernet frames can be delivered on the local segment.

  ARP Cache Entry States:
    REACHABLE — recently verified, actively used
    STALE     — timed out but not yet purged
    DELAY     — awaiting confirmation
    PROBE     — actively checking
    FAILED    — unreachable
    PERMANENT — manually added (static ARP)

  Gratuitous ARP — host announces its own IP/MAC mapping
  ARP Spoofing — attacker sends fake ARP replies to poison caches
    Defence: dynamic ARP inspection, static ARP entries
INFO

    section "Current ARP Cache"
    echo -e "${INFO}ARP/Neighbor table:${NC}"
    echo
    printf "  ${BOLD}%-18s %-20s %-12s %-10s${NC}\n" "IP" "MAC" "Interface" "State"
    printf "  ${DARK_GRAY}%-18s %-20s %-12s %-10s${NC}\n" "──────────────────" "────────────────────" "────────────" "──────────"

    ip neigh show 2>/dev/null | while read -r n_ip _ n_iface _ n_mac n_state; do
        [[ -z "$n_mac" || "$n_mac" == "FAILED" || "$n_mac" == "INCOMPLETE" ]] && continue
        local color
        case "$n_state" in
            REACHABLE) color="$SUCCESS" ;;
            STALE)     color="$MUTED"   ;;
            FAILED)    color="$FAILURE" ;;
            *)         color="$YELLOW"  ;;
        esac
        printf "  ${CYAN}%-18s${NC} ${WHITE}%-20s${NC} ${LABEL}%-12s${NC} ${color}%-10s${NC}\n" \
            "$n_ip" "$n_mac" "$n_iface" "$n_state"
    done

    section "ARP Statistics"
    kv "Total ARP entries" "$(ip neigh show 2>/dev/null | wc -l)"
    kv "REACHABLE" "$(ip neigh show 2>/dev/null | grep -c REACHABLE 2>/dev/null || echo 0)"
    kv "STALE"     "$(ip neigh show 2>/dev/null | grep -c STALE     2>/dev/null || echo 0)"
    kv "FAILED"    "$(ip neigh show 2>/dev/null | grep -c FAILED    2>/dev/null || echo 0)"

    section "ARP Lookup for Gateway"
    local gw
    gw=$(get_gateway)
    if [[ -n "$gw" ]]; then
        echo -e "  ${INFO}Pinging gateway ${gw} to refresh ARP...${NC}"
        ping -c 2 -W 1 "$gw" > /dev/null 2>&1
        echo
        ip neigh show "$gw" 2>/dev/null | while read -r n_ip _ n_iface _ n_mac n_state; do
            kv "Gateway IP" "$n_ip"
            kv "MAC Address" "$n_mac"
            kv "Interface"  "$n_iface"
            kv "State"      "$n_state"
        done
    fi

    section "OUI Lookup on Local MACs"
    echo -e "  ${MUTED}First 3 bytes of MAC = OUI (Organizationally Unique Identifier)${NC}"
    echo
    ip link show 2>/dev/null | grep "link/ether" | awk '{print $2}' | while read -r mac; do
        local oui
        oui=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
        echo -e "  MAC ${WHITE}${mac}${NC}  OUI ${GOLD}${oui}${NC}"
    done

    section "ARP Watch (5 seconds)"
    if cmd_exists tcpdump; then
        echo -e "  ${MUTED}Capturing ARP packets for 5 seconds (requires sudo)...${NC}"
        sudo -n timeout 5 tcpdump -ql -e arp 2>/dev/null \
            | grep -v "^tcpdump" | head -20 | sed 's/^/  /' \
            || echo -e "  ${MUTED}ARP capture not available (no sudo or tcpdump)${NC}"
    else
        status_line neutral "tcpdump not available — install for ARP watch"
    fi

    header "ARP Spoof Detection"
    echo -e "${INFO}Checking duplicate MAC entries...${NC}"

    ip neigh show | awk '{print $5}' | sort | uniq -d | while read -r mac; do
        echo -e "${FAILURE}Duplicate MAC detected: $mac${NC}"
    done
    echo
    echo -e "${WARNING}Duplicate MACs may indicate ARP spoofing${NC}"
}

main() {
    check_ip_versions
    ip_fragmentation_analysis
    ip_geolocation
    reverse_dns_check
    check_subnetting
    subnet_overlap_check
    check_ip_types
    check_nat
    check_arp
}

main