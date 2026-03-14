#!/bin/bash

# /network_lab/diagnostics/ip_addressing.sh
# Work on all Linux computers independent of distro
# Topic: IP & Addressing -- Interactive Lab
# Covers: IPv4/IPv6, Subnetting (CIDR/VLSM), Private/Public, NAT/PAT, ARP

# Bootstrap -- script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

#  HELPERS (unchanged)

octet_to_bin() {
    local n=$1
    local bits=""
    for (( i=7; i>=0; i-- )); do
        (( (n >> i) & 1 )) && bits+="1" || bits+="0"
    done
    echo "$bits"
}

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
    local fha=$(( (fh_int >> 24) & 0xFF )); local fhb=$(( (fh_int >> 16) & 0xFF ))
    local fhc=$(( (fh_int >> 8)  & 0xFF )); local fhd=$(( fh_int & 0xFF ))
    local first_host="${fha}.${fhb}.${fhc}.${fhd}"

    local lha=$(( (lh_int >> 24) & 0xFF )); local lhb=$(( (lh_int >> 16) & 0xFF ))
    local lhc=$(( (lh_int >> 8)  & 0xFF )); local lhd=$(( lh_int & 0xFF ))
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

classify_ip() {
    local ip="$1"
    if   [[ "$ip" =~ ^10\.                                              ]]; then echo "PRIVATE (RFC1918 10.0.0.0/8)"
    elif [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\.                   ]]; then echo "PRIVATE (RFC1918 172.16-31.x.x)"
    elif [[ "$ip" =~ ^192\.168\.                                        ]]; then echo "PRIVATE (RFC1918 192.168.0.0/16)"
    elif [[ "$ip" =~ ^127\.                                             ]]; then echo "LOOPBACK"
    elif [[ "$ip" =~ ^169\.254\.                                        ]]; then echo "LINK-LOCAL (APIPA)"
    elif [[ "$ip" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then echo "SHARED (CGNAT RFC6598)"
    elif [[ "$ip" =~ ^(198\.51\.100\.|203\.0\.113\.|192\.0\.2\.)       ]]; then echo "DOCUMENTATION (TEST)"
    elif [[ "$ip" =~ ^224\.                                             ]]; then echo "MULTICAST"
    elif [[ "$ip" =~ ^240\.                                             ]]; then echo "RESERVED (Class E)"
    elif [[ "$ip" == "255.255.255.255"                                  ]]; then echo "BROADCAST"
    elif [[ "$ip" == "0.0.0.0"                                          ]]; then echo "UNSPECIFIED"
    else echo "PUBLIC / GLOBAL UNICAST"
    fi
}

#  check_ip_versions
check_ip_versions() {

    #  SECTION 1 -- OVERVIEW
    header "IPv4 vs IPv6 -- IP Addressing"

    echo -e "  ${INFO}An IP address is a logical identifier assigned to every network interface.${NC}"
    echo -e "  ${MUTED}It operates at Layer 3 (Network) of the OSI model and serves two purposes:${NC}"
    echo -e "  ${MUTED}  1. Host identification  -- who is this device?${NC}"
    echo -e "  ${MUTED}  2. Location addressing  -- how do we route packets to it?${NC}"
    echo
    echo -e "  ${MUTED}IPv4 (1981) and IPv6 (1998) are the two versions in active use today.${NC}"
    echo -e "  ${MUTED}IPv4 exhaustion drove IPv6 adoption, but both coexist via dual-stack.${NC}"
    echo

    #  SECTION 2 -- IPv4 ADDRESS CLASSES
    section "IPv4 Address Classes (Classful Addressing)"

    echo -e "  ${MUTED}  Before CIDR (1993), IPv4 used fixed class boundaries. Understanding${NC}"
    echo -e "  ${MUTED}  classes explains why private ranges and multicast are where they are.${NC}"
    echo -e "  ${MUTED}  Classful addressing is obsolete for routing but still appears in${NC}"
    echo -e "  ${MUTED}  documentation, firewall rules, and legacy equipment.${NC}"
    echo
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..78})"
    printf "  ${BOLD}${TITLE}%-7s  %-6s  %-18s  %-14s  %-18s  %s${NC}\n" \
        "Class" "1st oct" "Range" "Default Mask" "Hosts/network" "Purpose"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..78})"
    printf "  ${GREEN}%-7s${NC}  ${LABEL}%-6s${NC}  ${VALUE}%-18s${NC}  ${MUTED}%-14s${NC}  ${GOLD}%-18s${NC}  ${MUTED}%s${NC}\n" \
        "Class A" "0-127"   "0.0.0.0 - 127.255.255.255"   "255.0.0.0 /8"   "16,777,214"  "Govts, large corps, ISPs"
    printf "  ${GREEN}%-7s${NC}  ${LABEL}%-6s${NC}  ${VALUE}%-18s${NC}  ${MUTED}%-14s${NC}  ${GOLD}%-18s${NC}  ${MUTED}%s${NC}\n" \
        "Class B" "128-191" "128.0.0.0 - 191.255.255.255" "255.255.0.0 /16" "65,534"      "Universities, mid corps"
    printf "  ${GREEN}%-7s${NC}  ${LABEL}%-6s${NC}  ${VALUE}%-18s${NC}  ${MUTED}%-14s${NC}  ${GOLD}%-18s${NC}  ${MUTED}%s${NC}\n" \
        "Class C" "192-223" "192.0.0.0 - 223.255.255.255" "255.255.255.0 /24" "254"        "Small orgs, LANs"
    printf "  ${GREEN}%-7s${NC}  ${LABEL}%-6s${NC}  ${VALUE}%-18s${NC}  ${MUTED}%-14s${NC}  ${GOLD}%-18s${NC}  ${MUTED}%s${NC}\n" \
        "Class D" "224-239" "224.0.0.0 - 239.255.255.255" "N/A"             "N/A"          "Multicast groups"
    printf "  ${GREEN}%-7s${NC}  ${LABEL}%-6s${NC}  ${VALUE}%-18s${NC}  ${MUTED}%-14s${NC}  ${GOLD}%-18s${NC}  ${MUTED}%s${NC}\n" \
        "Class E" "240-255" "240.0.0.0 - 255.255.255.255" "N/A"             "N/A"          "Reserved / experimental"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..78})"
    echo
    echo -e "  ${AMBER}${BOLD}How class is determined -- read the leading bits:${NC}"
    echo -e "  ${MUTED}  Class A:  first bit = 0          (0xxxxxxx)${NC}"
    echo -e "  ${MUTED}  Class B:  first two bits = 10    (10xxxxxx)${NC}"
    echo -e "  ${MUTED}  Class C:  first three bits = 110 (110xxxxx)${NC}"
    echo -e "  ${MUTED}  Class D:  first four bits = 1110 (1110xxxx)${NC}"
    echo -e "  ${MUTED}  Class E:  first four bits = 1111 (1111xxxx)${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Why classful addressing was abandoned:${NC}"
    echo -e "  ${MUTED}  Class A gave 16M hosts to a single org -- hugely wasteful.${NC}"
    echo -e "  ${MUTED}  Class C only gave 254 hosts -- too small for most organisations.${NC}"
    echo -e "  ${MUTED}  CIDR (1993) replaced it with variable-length prefixes so any${NC}"
    echo -e "  ${MUTED}  block size can be allocated, dramatically slowing exhaustion.${NC}"
    echo

    #  SECTION 3 -- IPv4 HEADER ANATOMY
    section "IPv4 Header Anatomy  (20 bytes minimum)"

    echo -e "  ${MUTED}  Every IPv4 packet begins with this header. Routers read it to${NC}"
    echo -e "  ${MUTED}  forward the packet; they never touch the payload above Layer 3.${NC}"
    echo
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${LABEL}  %-10s${NC}  ${LABEL}%-10s${NC}  ${LABEL}%-14s${NC}  ${LABEL}%s${NC}\n" \
        "Version(4)" "IHL(4)" "DSCP/ECN(8)" "Total Length(16)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${LABEL}  %-26s${NC}  ${LABEL}%-10s${NC}  ${LABEL}%s${NC}\n" \
        "Identification(16)" "Flags(3)" "Fragment Offset(13)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${LABEL}  %-16s${NC}  ${LABEL}%-16s${NC}  ${LABEL}%s${NC}\n" \
        "TTL(8)" "Protocol(8)" "Header Checksum(16)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${SUCCESS}  %-62s${NC}\n" "Source IP Address                                (32 bits)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${SUCCESS}  %-62s${NC}\n" "Destination IP Address                           (32 bits)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${MUTED}  %-62s${NC}\n" "Options  (0-40 bytes, present if IHL > 5)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${VALUE}  %-62s${NC}\n" "Payload  (TCP segment / UDP datagram / ICMP message)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo
    echo -e "  ${AMBER}${BOLD}Key fields explained:${NC}"
    kv "  Version"        "Always 4 for IPv4; tells stack which header format to expect"
    kv "  IHL"            "Internet Header Length in 32-bit words; min=5 (20 bytes), max=15 (60 bytes)"
    kv "  DSCP/ECN"       "Quality of Service marking (DSCP) + congestion notification (ECN)"
    kv "  Total Length"   "Entire packet size including header; max 65,535 bytes"
    kv "  Identification" "Unique ID for reassembling fragmented packets"
    kv "  Flags"          "Bit 0: reserved. Bit 1: DF (Don't Fragment). Bit 2: MF (More Fragments)"
    kv "  Frag Offset"    "Position of this fragment in the original datagram (units of 8 bytes)"
    kv "  TTL"            "Decremented by 1 at each router hop; packet dropped at 0 (prevents loops)"
    kv "  Protocol"       "Layer 4 type: 6=TCP  17=UDP  1=ICMP  89=OSPF  50=ESP  51=AH"
    kv "  Checksum"       "CRC over header only (not payload); recalculated at every hop (TTL change)"
    kv "  Src/Dst IP"     "32-bit logical addresses; dst used by every router to make forwarding decision"
    echo

    #  SECTION 4 -- IPv4 vs IPv6 COMPARISON
    section "IPv4 vs IPv6 -- Feature Comparison"

    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    printf "  ${BOLD}${TITLE}%-22s  %-22s  %-22s${NC}\n" "Feature" "IPv4" "IPv6"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Address size"       "32 bits"               "128 bits"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Total addresses"    "~4.3 billion"          "340 undecillion"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Notation"           "Dotted decimal"        "Colon-hex groups"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Header size"        "20-60 bytes (variable)" "40 bytes (fixed)"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Header checksum"    "Yes (recalc per hop)"  "Removed (L4 covers it)"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Fragmentation"      "Routers can fragment"  "Source only (PMTUD)"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Broadcast"          "Yes"                   "No (multicast instead)"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "Config"             "Manual / DHCP"         "SLAAC / DHCPv6"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "NAT required"       "Yes (address scarcity)" "No (global unicast)"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "IPsec"              "Optional (add-on)"     "Mandatory support"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "ARP"                "Yes (broadcast)"       "NDP replaces ARP"
    printf "  ${LABEL}%-22s${NC}  ${MUTED}%-22s${NC}  ${SUCCESS}%-22s${NC}\n" \
        "QoS"                "DSCP/ECN in header"    "Traffic Class + Flow Label"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    echo

    #  SECTION 5 -- IPv6 ADDRESS TYPES
    section "IPv6 Address Types"

    echo -e "  ${MUTED}  IPv6 addresses are 128 bits written as 8 groups of 4 hex digits.${NC}"
    echo -e "  ${MUTED}  Consecutive all-zero groups are compressed with :: (once per address).${NC}"
    echo -e "  ${MUTED}  Example: 2001:0db8:0000:0000:0000:0000:0000:0001 = 2001:db8::1${NC}"
    echo
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    printf "  ${BOLD}${TITLE}%-20s  %-24s  %s${NC}\n" "Type" "Prefix / Example" "Scope & Purpose"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Loopback"           "::1"                          "Equivalent to 127.0.0.1; localhost only"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Unspecified"        "::"                           "Equivalent to 0.0.0.0; means 'any address'"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Link-Local"         "fe80::/10"                    "Auto-configured; same link only; never routed"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Unique Local"       "fc00::/7  (fd00::/8 common)"  "Private LAN; like RFC1918; not routed globally"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Global Unicast"     "2000::/3  (e.g. 2001:db8::1)" "Public Internet address; globally routable"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Multicast"          "ff00::/8"                     "One-to-many; replaces broadcast"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Solicited-Node MC"  "ff02::1:ffXX:XXXX"           "NDP target lookup; derived from unicast addr"
    printf "  ${GREEN}%-20s${NC}  ${LABEL}%-24s${NC}  ${VALUE}%s${NC}\n" \
        "Anycast"            "Same as unicast; routed to nearest" "Load balancing; CDN, DNS root servers"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    echo
    echo -e "  ${AMBER}${BOLD}Link-local deep dive:${NC}"
    echo -e "  ${MUTED}  Every IPv6 interface auto-generates a link-local address from its MAC${NC}"
    echo -e "  ${MUTED}  using EUI-64: insert ff:fe in the middle of the MAC and flip bit 6.${NC}"
    echo -e "  ${MUTED}  Example: MAC aa:bb:cc:dd:ee:ff -> link-local fe80::a8bb:ccff:fedd:eeff${NC}"
    echo -e "  ${MUTED}  Link-locals are used by NDP, routing protocol hellos, and DHCPv6.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Common multicast groups:${NC}"
    kv "  ff02::1"   "All nodes on the link (equivalent of 255.255.255.255)"
    kv "  ff02::2"   "All routers on the link"
    kv "  ff02::5"   "All OSPFv3 routers"
    kv "  ff02::1:2" "All DHCPv6 servers/relays"
    echo

    #  SECTION 6 -- EXHAUSTION + TRANSITION
    section "IPv4 Exhaustion Story and Transition Mechanisms"

    echo -e "  ${AMBER}${BOLD}The exhaustion timeline:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "1981"  "IPv4 defined (RFC 791) -- 4.3B addresses seemed infinite"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "1993"  "CIDR introduced -- slows exhaustion with variable-length prefixes"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "1994"  "NAT invented -- hides many private hosts behind one public IP"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "1998"  "IPv6 standardised (RFC 2460) -- 128-bit addresses"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "2011"  "IANA free pool exhausted -- all /8 blocks allocated to RIRs"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "2011"  "APNIC (Asia-Pacific) exhausted its pool"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "2015"  "ARIN (North America) exhausted -- waitlist only"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "2019"  "RIPE NCC (Europe) exhausted -- last /22 allocated"
    printf "  ${LABEL}%-6s${NC}  ${VALUE}%s${NC}\n" "Today" "IPv4 addresses traded on secondary market; IPv6 deployment ~45%"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Transition mechanisms -- bridging IPv4 and IPv6:${NC}"
    echo
    echo -e "  ${AMBER}Dual-Stack  (most common, recommended)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Every interface has BOTH an IPv4 and an IPv6 address.${NC}"
    echo -e "  ${MUTED}  OS prefers IPv6 when available (RFC 6724 address selection).${NC}"
    echo -e "  ${MUTED}  No tunnelling overhead; both stacks run natively.${NC}"
    echo -e "  ${MUTED}  Requires dual-stack support throughout: hosts, routers, DNS.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}6to4  (RFC 3056, largely deprecated)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Embeds IPv4 address into IPv6 prefix: 2002::/16 + 32-bit IPv4.${NC}"
    echo -e "  ${MUTED}  IPv6 packets tunnelled inside IPv4 (protocol 41).${NC}"
    echo -e "  ${MUTED}  Relies on anycast relay routers -- unreliable, deprecated.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}Teredo  (RFC 4380, mostly obsolete)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Tunnels IPv6 inside UDP/IPv4 -- works through NAT devices.${NC}"
    echo -e "  ${MUTED}  Used by Windows for IPv6 behind NAT; disabled by default now.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}NAT64 + DNS64  (RFC 6146 / 6147)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  IPv6-only hosts communicate with IPv4-only servers.${NC}"
    echo -e "  ${MUTED}  DNS64 synthesises AAAA records from A records.${NC}"
    echo -e "  ${MUTED}  NAT64 gateway translates IPv6 packets to IPv4 and back.${NC}"
    echo -e "  ${MUTED}  Used in mobile networks (iOS requires NAT64 compatibility).${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    #  SECTION 7 -- LIVE SYSTEM (unchanged)
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
    echo -e "  ${INFO}IPv6 global connectivity check:${NC}"
    if ping -6 -c 2 -W 2 2001:4860:4860::8888 &>/dev/null; then
        status_line ok "IPv6 Internet connectivity available"
    else
        status_line neutral "IPv6 Internet not reachable (or not configured)"
    fi

    header "IPv6 Security Analysis"
    echo -e "  ${INFO}Checking IPv6 exposure...${NC}"
    ip -6 route show | sed 's/^/  /'
    echo
    echo -e "  ${INFO}Listening IPv6 services:${NC}"
    if cmd_exists ss; then
        ss -ltn6
    else
        status_line neutral "ss not installed"
    fi
    echo
    echo -e "  ${WARNING}IPv6 often bypasses IPv4 firewall rules -- audit both stacks${NC}"
}

#  ip_fragmentation_analysis  (unchanged)
ip_fragmentation_analysis() {
    header "IP Fragmentation Analysis"
    echo -e "  ${INFO}Checking MTU and fragmentation behavior...${NC}"
    local target="8.8.8.8"
    for size in 1472 1500 2000; do
        echo -e "\n  ${CYAN}Testing packet size: $size${NC}"
        ping -c 1 -s "$size" -M do "$target" 2>&1 | \
            grep -E "frag needed|Message too long|bytes from" | sed 's/^/  /'
    done
    echo
    echo -e "  ${WARNING}If fragmentation occurs -> possible MTU issues or filtering${NC}"
}

#  ip_geolocation  (unchanged)
ip_geolocation() {
    header "IP Geolocation"
    read -rp "Enter IP: " ip
    if ! is_valid_ip "$ip"; then
        log_warning "Invalid IP"
        return
    fi
    curl -s --max-time 5 "https://ip-api.com/json/$ip" | \
        grep -E '"country"|"regionName"|"city"|"isp"' | \
        sed 's/[",]//g' | sed 's/^/  /'
}

#  reverse_dns_check  (unchanged)
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
        echo -e "  ${INFO}Forward resolving PTR...${NC}"
        if cmd_exists dig; then dig +short "$ptr"
        elif cmd_exists host; then host "$ptr"
        fi
    fi
}

#  check_subnetting
check_subnetting() {

    #  SECTION 1 -- OVERVIEW
    header "Subnetting -- CIDR / VLSM"

    echo -e "  ${INFO}Subnetting is the practice of dividing a large IP address block into${NC}"
    echo -e "  ${MUTED}smaller sub-blocks (subnets). Each subnet is a contiguous range of IPs${NC}"
    echo -e "  ${MUTED}that share a common network prefix. Devices on the same subnet can reach${NC}"
    echo -e "  ${MUTED}each other directly via Layer 2; traffic to other subnets must go via a router.${NC}"
    echo

    #  SECTION 2 -- CIDR NOTATION DEEP EXPLANATION
    section "CIDR Notation -- How the Prefix Works in Binary"

    echo -e "  ${MUTED}  CIDR (Classless Inter-Domain Routing, RFC 4632) replaced classful${NC}"
    echo -e "  ${MUTED}  addressing in 1993. A CIDR block is written as x.x.x.x/n where${NC}"
    echo -e "  ${MUTED}  /n means the first n bits identify the network and the remaining${NC}"
    echo -e "  ${MUTED}  (32-n) bits identify the host within that network.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Example: 192.168.10.0/24${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo -e "  ${MUTED}  IP in binary:${NC}"
    echo -e "  ${LABEL}  192      .  168      .  10       .  0${NC}"
    echo -e "  ${VALUE}  11000000   10101000   00001010   00000000${NC}"
    echo -e "  ${SUCCESS}  |------ 24 network bits --------|${NC}${MUTED}  |host|${NC}"
    echo
    echo -e "  ${MUTED}  Subnet mask: the /24 becomes 24 ones followed by 8 zeros${NC}"
    echo -e "  ${VALUE}  11111111   11111111   11111111   00000000${NC}"
    echo -e "  ${LABEL}  255      .  255      .  255      .  0${NC}"
    echo
    echo -e "  ${MUTED}  To find the network address: bitwise AND the IP with the mask${NC}"
    echo -e "  ${VALUE}  11000000   10101000   00001010   01001101  (192.168.10.77)${NC}"
    echo -e "  ${LABEL}  AND${NC}"
    echo -e "  ${VALUE}  11111111   11111111   11111111   00000000  (255.255.255.0)${NC}"
    echo -e "  ${LABEL}  =${NC}"
    echo -e "  ${SUCCESS}  11000000   10101000   00001010   00000000  (192.168.10.0) <- network${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo
    echo -e "  ${AMBER}${BOLD}Key derived values for /24:${NC}"
    kv "  Network addr"   "192.168.10.0   -- all host bits = 0; identifies the subnet"
    kv "  Broadcast addr" "192.168.10.255 -- all host bits = 1; packet to all hosts on subnet"
    kv "  First host"     "192.168.10.1   -- network + 1"
    kv "  Last host"      "192.168.10.254 -- broadcast - 1"
    kv "  Usable hosts"   "2^8 - 2 = 254  -- subtract network and broadcast"
    echo

    echo -e "  ${AMBER}${BOLD}How to calculate hosts from prefix:${NC}"
    echo -e "  ${MUTED}  Host bits = 32 - prefix${NC}"
    echo -e "  ${MUTED}  Total addresses = 2^(host bits)${NC}"
    echo -e "  ${MUTED}  Usable hosts    = 2^(host bits) - 2  (subtract network + broadcast)${NC}"
    echo -e "  ${MUTED}  Exception: /31 has 2 usable (RFC 3021, point-to-point links)${NC}"
    echo -e "  ${MUTED}  Exception: /32 has 1 (host route -- identifies a single host)${NC}"
    echo

    #  SECTION 3 -- SUBNETTING WORKED EXAMPLE
    section "Subnetting Worked Example -- Splitting 192.168.1.0/24"

    echo -e "  ${MUTED}  Goal: split 192.168.1.0/24 into 4 equal subnets for 4 departments.${NC}"
    echo -e "  ${MUTED}  Each subnet needs to accommodate at least 50 hosts.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Step 1 -- How many bits do we need to steal from the host portion?${NC}"
    echo -e "  ${MUTED}  We need 4 subnets. 2^n >= 4 -> n=2. Steal 2 bits.${NC}"
    echo -e "  ${MUTED}  New prefix = /24 + 2 = /26${NC}"
    echo -e "  ${MUTED}  Host bits remaining = 32 - 26 = 6${NC}"
    echo -e "  ${MUTED}  Hosts per subnet = 2^6 - 2 = 62  (satisfies the 50-host requirement)${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Step 2 -- Calculate the block size (subnet increment):${NC}"
    echo -e "  ${MUTED}  Block size = 2^(host bits) = 2^6 = 64${NC}"
    echo -e "  ${MUTED}  Each subnet starts 64 addresses after the previous one.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Step 3 -- List the 4 subnets:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    printf "  ${BOLD}${TITLE}%-6s  %-18s  %-16s  %-16s  %-8s${NC}\n" \
        "Subnet" "Network" "First Host" "Last Host" "Broadcast"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-18s${NC}  ${VALUE}%-16s${NC}  ${VALUE}%-16s${NC}  ${MUTED}%s${NC}\n" \
        "1" "192.168.1.0/26"   "192.168.1.1"   "192.168.1.62"  "192.168.1.63"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-18s${NC}  ${VALUE}%-16s${NC}  ${VALUE}%-16s${NC}  ${MUTED}%s${NC}\n" \
        "2" "192.168.1.64/26"  "192.168.1.65"  "192.168.1.126" "192.168.1.127"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-18s${NC}  ${VALUE}%-16s${NC}  ${VALUE}%-16s${NC}  ${MUTED}%s${NC}\n" \
        "3" "192.168.1.128/26" "192.168.1.129" "192.168.1.190" "192.168.1.191"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-18s${NC}  ${VALUE}%-16s${NC}  ${VALUE}%-16s${NC}  ${MUTED}%s${NC}\n" \
        "4" "192.168.1.192/26" "192.168.1.193" "192.168.1.254" "192.168.1.255"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..72})"
    echo
    echo -e "  ${AMBER}${BOLD}Binary view of the subnet boundary -- the 2 stolen bits:${NC}"
    echo -e "  ${MUTED}  192.168.1.  [ss hhhhhh]  where ss=subnet bits, hhhhhh=host bits${NC}"
    echo -e "  ${VALUE}  Subnet 1:   00 000000  = .0   network,  00 111111 = .63  broadcast${NC}"
    echo -e "  ${VALUE}  Subnet 2:   01 000000  = .64  network,  01 111111 = .127 broadcast${NC}"
    echo -e "  ${VALUE}  Subnet 3:   10 000000  = .128 network,  10 111111 = .191 broadcast${NC}"
    echo -e "  ${VALUE}  Subnet 4:   11 000000  = .192 network,  11 111111 = .255 broadcast${NC}"
    echo

    #  SECTION 4 -- SUPERNETTING / ROUTE SUMMARISATION
    section "Supernetting and Route Summarisation"

    echo -e "  ${MUTED}  Supernetting is the opposite of subnetting -- combining multiple${NC}"
    echo -e "  ${MUTED}  smaller networks into a single larger block. In routing, this is${NC}"
    echo -e "  ${MUTED}  called route summarisation (or aggregation).${NC}"
    echo
    echo -e "  ${MUTED}  Benefits:${NC}"
    echo -e "  ${MUTED}    - Smaller routing tables (fewer prefixes to store and advertise)${NC}"
    echo -e "  ${MUTED}    - Faster convergence (fewer updates when topology changes)${NC}"
    echo -e "  ${MUTED}    - Hides internal topology from external routers${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Worked example -- summarise these 4 routes into one:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${LABEL}  192.168.4.0/24${NC}"
    echo -e "  ${LABEL}  192.168.5.0/24${NC}"
    echo -e "  ${LABEL}  192.168.6.0/24${NC}"
    echo -e "  ${LABEL}  192.168.7.0/24${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Step 1 -- convert the third octets to binary:${NC}"
    echo -e "  ${MUTED}  192.168.4.0  -> third octet 4  = 00000${SUCCESS}100${NC}"
    echo -e "  ${MUTED}  192.168.5.0  -> third octet 5  = 00000${SUCCESS}101${NC}"
    echo -e "  ${MUTED}  192.168.6.0  -> third octet 6  = 00000${SUCCESS}110${NC}"
    echo -e "  ${MUTED}  192.168.7.0  -> third octet 7  = 00000${SUCCESS}111${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Step 2 -- find the common prefix bits:${NC}"
    echo -e "  ${MUTED}  All four share: 192.168. + 00000 1xx  -- the first 22 bits match${NC}"
    echo -e "  ${MUTED}  The last 2 bits of the third octet differ (00,01,10,11)${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Step 3 -- the summary route:${NC}"
    echo -e "  ${SUCCESS}  192.168.4.0/22${NC}  ${MUTED}-- covers .4.0 through .7.255 (1022 usable hosts)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Rule of thumb -- a block is summarisable if:${NC}"
    echo -e "  ${MUTED}  1. The network addresses share a common prefix${NC}"
    echo -e "  ${MUTED}  2. The number of networks is a power of 2${NC}"
    echo -e "  ${MUTED}  3. The first network address is divisible by the block size${NC}"
    echo

    #  SECTION 5 -- INTERACTIVE CALCULATOR (unchanged)
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
        log_warning "Invalid CIDR -- showing built-in examples instead"
    fi

    section "VLSM Example -- Dividing 192.168.0.0/24"
    local examples=("192.168.0.0/25" "192.168.0.128/26" "192.168.0.192/27" "192.168.0.224/28")
    for cidr in "${examples[@]}"; do
        echo -e "\n  ${GOLD}${BOLD}${cidr}${NC}"
        subnet_details "$cidr" | grep -E "Subnet Mask|First Host|Last Host|Usable" | \
            while IFS= read -r line; do echo "  $line"; done
    done

    section "CIDR Quick Reference"
    echo
    printf "  ${BOLD}%-6s %-18s %-14s %-10s${NC}\n" "CIDR" "Subnet Mask" "Hosts" "Use Case"
    printf "  ${DARK_GRAY}%-6s %-18s %-14s %-10s${NC}\n" \
        "------" "------------------" "--------------" "----------"
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

#  subnet_overlap_check  (unchanged)
subnet_overlap_check() {
    header "Subnet Overlap Detection"
    read -rp "Enter CIDR 1: " c1
    read -rp "Enter CIDR 2: " c2
    if ! is_valid_cidr "$c1" || ! is_valid_cidr "$c2"; then
        log_warning "Invalid CIDR(s)"
        return
    fi
    local n1; n1=$(subnet_details "$c1" | awk -F': *' '/Network/ {print $2}')
    local n2; n2=$(subnet_details "$c2" | grep Network | awk '{print $2}')
    echo -e "  ${INFO}Basic comparison: ${c1} vs ${c2}${NC}"
    if [[ "$n1" == "$n2" ]]; then
        status_line ok "Possible overlap (same network)"
    else
        status_line neutral "Different networks (manual validation needed)"
    fi
}

#  check_ip_types  (unchanged)
check_ip_types() {
    header "Private vs Public IP Addresses"
    cat << 'INFO'
  RFC 1918 Private Ranges (not Internet-routable):
    10.0.0.0/8       -- Class A private (10.0.0.0 - 10.255.255.255)
    172.16.0.0/12    -- Class B private (172.16.0.0 - 172.31.255.255)
    192.168.0.0/16   -- Class C private (192.168.0.0 - 192.168.255.255)

  Other Special Ranges:
    127.0.0.0/8      -- Loopback (localhost)
    169.254.0.0/16   -- Link-local (APIPA -- auto-assigned when DHCP fails)
    100.64.0.0/10    -- CGNAT shared space (RFC 6598)
    224.0.0.0/4      -- Multicast
    240.0.0.0/4      -- Reserved (Class E)
    0.0.0.0/8        -- This network (unspecified)
INFO
    section "Classify This System's Addresses"
    ip -4 -o addr show | while read -r _ iface _ cidr _; do
        local ip="${cidr%/*}"
        local class; class=$(classify_ip "$ip")
        case "$class" in
            *PRIVATE*)  echo -e "  ${CYAN}${iface}${NC} ${ip} -> ${GREEN}${class}${NC}" ;;
            *PUBLIC*)   echo -e "  ${CYAN}${iface}${NC} ${ip} -> ${GOLD}${class}${NC}" ;;
            *LOOPBACK*) echo -e "  ${CYAN}${iface}${NC} ${ip} -> ${MUTED}${class}${NC}" ;;
            *)          echo -e "  ${CYAN}${iface}${NC} ${ip} -> ${YELLOW}${class}${NC}" ;;
        esac
    done
    section "Interactive IP Classifier"
    read -rp "$(echo -e "  ${PROMPT}Enter any IPv4 address to classify:${NC} ")" user_ip
    if is_valid_ip "$user_ip"; then
        echo -e "  ${WHITE}${user_ip}${NC} -> ${GOLD}$(classify_ip "$user_ip")${NC}"
        ip_to_binary "$user_ip" | sed 's/^/  Binary: /'
    else
        log_warning "Invalid IP address entered"
    fi
    section "Public IP Detection"
    echo -e "  ${MUTED}Querying external IP services...${NC}"
    local pub; pub=$(get_public_ip)
    if [[ "$pub" != "unavailable" ]]; then
        status_line ok "Your public IP: ${pub}"
    else
        status_line neutral "Unable to detect public IP (offline or blocked)"
    fi
}

#  check_nat
check_nat() {

    #  SECTION 1 -- OVERVIEW
    header "NAT and PAT -- Network/Port Address Translation"

    echo -e "  ${INFO}NAT (Network Address Translation) modifies IP address fields in packet${NC}"
    echo -e "  ${MUTED}headers as they pass through a router or firewall. It was invented in${NC}"
    echo -e "  ${MUTED}1994 as a short-term fix for IPv4 exhaustion and became universally${NC}"
    echo -e "  ${MUTED}deployed in home routers, enterprise firewalls, and cloud gateways.${NC}"
    echo

    #  SECTION 2 -- NAT TYPES
    section "NAT Types and How They Work"

    echo -e "  ${AMBER}${BOLD}Static NAT  (1-to-1 mapping)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  One private IP permanently maps to one public IP.${NC}"
    echo -e "  ${MUTED}  Used for servers that must be reachable from the Internet.${NC}"
    echo -e "  ${MUTED}  Does NOT conserve addresses -- one public IP per host.${NC}"
    echo -e "  ${LABEL}  Inside:${NC} ${VALUE}192.168.1.10${NC}  ${MUTED}<->  ${NC}${LABEL}Outside:${NC} ${VALUE}203.0.113.10${NC}  ${MUTED}(always)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}Dynamic NAT  (pool mapping)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  A pool of public IPs is shared across private hosts on first-come basis.${NC}"
    echo -e "  ${MUTED}  If pool is exhausted, new connections are dropped.${NC}"
    echo -e "  ${MUTED}  Still requires one public IP per simultaneous outbound connection.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    echo -e "  ${AMBER}${BOLD}PAT / NAPT / NAT Overload  (many-to-one, the common case)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Thousands of private hosts share ONE public IP, differentiated by${NC}"
    echo -e "  ${MUTED}  source port number. This is what your home router does.${NC}"
    echo -e "  ${MUTED}  The NAT table tracks: private IP:port <-> public IP:translated-port${NC}"
    echo
    printf "  ${GREEN}%-24s${NC}            ${BLUE}%s${NC}\n" "Inside (private)" "Outside (public)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${LABEL}  192.168.1.10:54321${NC}  ${SUCCESS}-->${NC}  ${VALUE}203.0.113.1:40001${NC}  ${MUTED}-> 8.8.8.8:53${NC}"
    echo -e "  ${LABEL}  192.168.1.11:54322${NC}  ${SUCCESS}-->${NC}  ${VALUE}203.0.113.1:40002${NC}  ${MUTED}-> 8.8.8.8:53${NC}"
    echo -e "  ${LABEL}  192.168.1.12:80${NC}     ${SUCCESS}-->${NC}  ${VALUE}203.0.113.1:40003${NC}  ${MUTED}-> 1.1.1.1:443${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Reply packets are matched back to the original host using the port.${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}NAT Types for P2P / Gaming (cone vs symmetric):${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${BOLD}${TITLE}%-20s  %-12s  %s${NC}\n" "Type" "Permissive" "Behaviour"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${GREEN}%-20s${NC}  ${SUCCESS}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "Full Cone"       "Most open"   "Any external host can send to the mapped port"
    printf "  ${GREEN}%-20s${NC}  ${WARNING}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "Restricted Cone" "Medium"      "External can send if inside host sent to their IP first"
    printf "  ${GREEN}%-20s${NC}  ${WARNING}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "Port Restricted" "Medium"      "External must match both IP and port of prior contact"
    printf "  ${GREEN}%-20s${NC}  ${FAILURE}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "Symmetric"       "Strictest"   "New port mapped per destination -- breaks most P2P"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    echo

    #  SECTION 3 -- CGNAT AND DOUBLE-NAT
    section "CGNAT and Double-NAT"

    echo -e "  ${AMBER}${BOLD}CGNAT -- Carrier-Grade NAT  (RFC 6598)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  ISPs facing IPv4 exhaustion apply a second layer of NAT between${NC}"
    echo -e "  ${MUTED}  the customer and the Internet. The customer's router gets an address${NC}"
    echo -e "  ${MUTED}  in the 100.64.0.0/10 range (RFC 6598 shared space) instead of a${NC}"
    echo -e "  ${MUTED}  real public IP. The ISP's CGNAT box then translates that to a true${NC}"
    echo -e "  ${MUTED}  public IP shared across hundreds of customers.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}CGNAT traffic flow:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${GREEN}%-14s${NC}    ${LABEL}%-18s${NC}    ${AMBER}%-14s${NC}    ${BLUE}%s${NC}\n" \
        "Your Device" "Home Router (PAT)" "ISP CGNAT" "Internet"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo -e "  ${VALUE}  192.168.1.5${NC}  ${SUCCESS}-->${NC}  ${VALUE}100.64.10.1${NC}  ${SUCCESS}-->${NC}  ${VALUE}203.0.113.50${NC}  ${SUCCESS}-->${NC}  ${BLUE}Server${NC}"
    echo -e "  ${MUTED}  Private          RFC6598 shared      True public${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo
    echo -e "  ${AMBER}${BOLD}Problems caused by CGNAT:${NC}"
    kv "  Port forwarding"   "Impossible -- you don't own the public IP"
    kv "  IP reputation"     "Your public IP is shared; one user's abuse affects all"
    kv "  Geo-IP accuracy"   "Your 'location' reflects ISP CGNAT PoP, not your home"
    kv "  P2P/VoIP"          "Symmetric NAT breaks ICE/STUN-based hole punching"
    kv "  Log correlation"   "Law enforcement can't trace IP to a subscriber without port logs"
    echo
    echo -e "  ${AMBER}${BOLD}How to detect if you're behind CGNAT:${NC}"
    echo -e "  ${MUTED}  Your router's WAN IP is in 100.64.0.0/10, or${NC}"
    echo -e "  ${MUTED}  your router's WAN IP differs from your public IP (check ip-api.com).${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}Double-NAT${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Occurs when a second NAT device sits behind the ISP's gateway --${NC}"
    echo -e "  ${MUTED}  e.g. your own router behind a modem/router combo that also NATSs.${NC}"
    echo -e "  ${MUTED}  Results in three NAT layers total with CGNAT.${NC}"
    echo -e "  ${MUTED}  Fix: put the ISP device in bridge mode (passthrough) so your${NC}"
    echo -e "  ${MUTED}  router gets the real WAN IP.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    #  SECTION 4 -- NAT TRAVERSAL PROBLEMS
    section "NAT Traversal Problems"

    echo -e "  ${MUTED}  NAT breaks the end-to-end principle of IP: any host should be able${NC}"
    echo -e "  ${MUTED}  to initiate a connection to any other host. Behind NAT, external hosts${NC}"
    echo -e "  ${MUTED}  cannot reach you unless you initiated the connection or set up forwarding.${NC}"
    echo

    echo -e "  ${FAILURE}${BOLD}[!] SIP / VoIP${NC}"
    echo -e "  ${MUTED}  SIP embeds IP:port inside the payload body (not just headers).${NC}"
    echo -e "  ${MUTED}  When NAT rewrites the outer IP, the embedded address stays private.${NC}"
    echo -e "  ${MUTED}  The remote end tries to send RTP audio to your private IP -- fails.${NC}"
    echo -e "  ${AMBER}  Fix: SIP ALG on router (rewrites payload), or STUN/TURN server${NC}"
    echo

    echo -e "  ${FAILURE}${BOLD}[!] FTP Active Mode${NC}"
    echo -e "  ${MUTED}  Active FTP: client tells server 'connect back to me on port X'.${NC}"
    echo -e "  ${MUTED}  Client sends its private IP in the PORT command -- server can't reach it.${NC}"
    echo -e "  ${MUTED}  Passive FTP: server tells client which port to connect to -- NAT-friendly.${NC}"
    echo -e "  ${AMBER}  Fix: always use Passive (PASV) mode behind NAT; FTP ALG also helps${NC}"
    echo

    echo -e "  ${FAILURE}${BOLD}[!] P2P / WebRTC / Gaming${NC}"
    echo -e "  ${MUTED}  Peer-to-peer requires both sides to initiate -- one is behind NAT.${NC}"
    echo -e "  ${MUTED}  Solution stack: STUN -> TURN -> relay${NC}"
    kv "  STUN (RFC 5389)"  "Discover your public IP:port by asking a STUN server"
    kv "  TURN (RFC 5766)"  "Relay server forwards packets when direct path fails"
    kv "  ICE (RFC 8445)"   "Framework that tries STUN first, falls back to TURN"
    echo -e "  ${MUTED}  WebRTC, Zoom, Discord, gaming all use ICE under the hood.${NC}"
    echo

    #  SECTION 5 -- iptables NAT RULE ANATOMY
    section "iptables NAT Rule Anatomy"

    echo -e "  ${MUTED}  Linux implements NAT via Netfilter hooks. The nat table has three chains:${NC}"
    echo
    kv "  PREROUTING"   "Packets arriving on interface -- DNAT applied here (port forwarding)"
    kv "  POSTROUTING"  "Packets leaving interface -- SNAT/MASQUERADE applied here"
    kv "  OUTPUT"       "Locally generated packets -- rarely used for NAT"
    echo
    echo -e "  ${AMBER}${BOLD}Masquerade (dynamic SNAT -- home router style):${NC}"
    echo -e "  ${VALUE}  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE${NC}"
    echo -e "  ${MUTED}  All outbound traffic on eth0 gets src IP replaced with eth0's IP.${NC}"
    echo -e "  ${MUTED}  MASQUERADE re-reads the interface IP each time -- suits DHCP WAN.${NC}"
    echo -e "  ${MUTED}  SNAT with --to-source is faster when the public IP is static.${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}Static SNAT (fixed public IP):${NC}"
    echo -e "  ${VALUE}  iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source 203.0.113.1${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}DNAT / Port forwarding (expose internal server):${NC}"
    echo -e "  ${VALUE}  iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 \\${NC}"
    echo -e "  ${VALUE}             -j DNAT --to-destination 192.168.1.10:80${NC}"
    echo -e "  ${MUTED}  Incoming TCP port 80 on the public interface is forwarded to the${NC}"
    echo -e "  ${MUTED}  internal web server at 192.168.1.10:80.${NC}"
    echo -e "  ${MUTED}  Also requires: iptables -A FORWARD -d 192.168.1.10 -j ACCEPT${NC}"
    echo

    echo -e "  ${AMBER}${BOLD}Full packet flow with DNAT:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo -e "  ${MUTED}  Internet client sends:  dst=203.0.113.1:80${NC}"
    echo -e "  ${SUCCESS}  PREROUTING DNAT:${NC}       ${MUTED}dst rewritten to 192.168.1.10:80${NC}"
    echo -e "  ${MUTED}  Kernel routes to:       192.168.1.10 (via internal interface)${NC}"
    echo -e "  ${MUTED}  Server replies:         src=192.168.1.10:80 dst=client${NC}"
    echo -e "  ${SUCCESS}  POSTROUTING SNAT:${NC}      ${MUTED}src rewritten back to 203.0.113.1:80${NC}"
    echo -e "  ${MUTED}  Client receives:        src=203.0.113.1:80 (transparent)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo

    #  SECTION 6 -- NAT vs NPTv6
    section "NAT vs NPTv6"

    echo -e "  ${MUTED}  IPv6 was designed to eliminate NAT by giving every device a globally${NC}"
    echo -e "  ${MUTED}  unique address. But some organisations still want prefix translation${NC}"
    echo -e "  ${MUTED}  for policy reasons -- this is where NPTv6 comes in.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}NPTv6 -- Network Prefix Translation for IPv6  (RFC 6296)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    kv "  What it does"   "Translates one IPv6 prefix to another -- no port mangling"
    kv "  Preserves"      "End-to-end address transparency within each side"
    kv "  Stateless"      "No connection tracking table -- 1:1 prefix mapping only"
    kv "  Use case"       "Multi-homing: same internal ULA behind multiple ISP prefixes"
    kv "  Use case"       "Provider independence: change ISP without renumbering internally"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}NAT44 vs NPTv6 -- key differences:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${BOLD}${TITLE}%-26s  %-18s  %-18s${NC}\n" "Property" "NAT44 (IPv4)" "NPTv6 (IPv6)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${LABEL}%-26s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Port translation"     "Yes"                "No"
    printf "  ${LABEL}%-26s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Stateful"             "Yes (conn track)"   "No (prefix map)"
    printf "  ${LABEL}%-26s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Hides topology"       "Yes"                "Partially"
    printf "  ${LABEL}%-26s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Breaks end-to-end"    "Yes"                "No (within prefix)"
    printf "  ${LABEL}%-26s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Inbound connections"  "Needs DNAT rules"   "Allowed by default"
    printf "  ${LABEL}%-26s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Address conservation" "Yes (main purpose)" "No (not needed)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo
    echo -e "  ${AMBER}${BOLD}Recommendation:${NC}"
    echo -e "  ${MUTED}  Prefer dual-stack with real IPv6 global addresses over NPTv6.${NC}"
    echo -e "  ${MUTED}  NPTv6 is a last resort for specific multi-homing/policy scenarios.${NC}"
    echo -e "  ${MUTED}  If you need inbound filtering, use a stateful IPv6 firewall -- not NAT.${NC}"
    echo

    #  SECTION 7 -- LIVE SYSTEM (unchanged)
    section "NAT/iptables Status"
    if cmd_exists iptables; then
        if sudo -n iptables -t nat -L -n 2>/dev/null | grep -qE "MASQUERADE|SNAT|DNAT"; then
            status_line ok "NAT/masquerade rules detected"
            echo
            echo -e "  ${INFO}NAT rules:${NC}"
            sudo -n iptables -t nat -L -n -v 2>/dev/null | \
                grep -v "^Chain\|^target\|^$" | head -20 | sed 's/^/  /'
        elif cmd_exists nft; then
            nft list ruleset | grep -E "snat|dnat|masquerade"
        else
            status_line neutral "No NAT rules in iptables (this host is not a NAT router)"
        fi
    fi
    echo
    echo -e "  ${INFO}IP forwarding (required for NAT routing):${NC}"
    local fwd; fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$fwd" == "1" ]]; then
        status_line ok "IP forwarding ENABLED -- this host can forward/route packets"
    else
        status_line neutral "IP forwarding DISABLED -- endpoint mode (normal workstation)"
    fi
    section "Connection Tracking"
    if [[ -f /proc/net/nf_conntrack ]]; then
        local total; total=$(wc -l < /proc/net/nf_conntrack 2>/dev/null)
        kv "Tracked connections" "$total"
        kv "conntrack max" "$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 'N/A')"
        echo
        echo -e "  ${INFO}Active NAT translations (first 10):${NC}"
        grep "dnat\|snat" /proc/net/nf_conntrack 2>/dev/null | head -10 | sed 's/^/  /' \
            || echo -e "  ${MUTED}No NAT translations found${NC}"
    else
        status_line neutral "Connection tracking not available (nf_conntrack not loaded)"
    fi
}

#  check_arp
check_arp() {

    #  SECTION 1 -- OVERVIEW
    header "ARP -- Address Resolution Protocol"

    echo -e "  ${INFO}ARP (RFC 826, 1982) solves a fundamental problem: IP works at Layer 3${NC}"
    echo -e "  ${MUTED}using logical addresses, but Ethernet works at Layer 2 using MAC addresses.${NC}"
    echo -e "  ${MUTED}Before sending a frame, a host must know the destination MAC. ARP is the${NC}"
    echo -e "  ${MUTED}protocol that maps a known IP address to its MAC address.${NC}"
    echo
    echo -e "  ${MUTED}ARP is link-local -- it uses Ethernet broadcast and never crosses a router.${NC}"
    echo -e "  ${MUTED}Cross-subnet traffic always goes to the gateway MAC, not the remote host MAC.${NC}"
    echo

    #  SECTION 2 -- ARP IN DIFFERENT SCENARIOS
    section "ARP in Different Scenarios"

    echo -e "  ${AMBER}${BOLD}Scenario 1 -- Same-subnet communication${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo -e "  ${MUTED}  Host A (192.168.1.5) wants to reach Host B (192.168.1.20).${NC}"
    echo -e "  ${MUTED}  Both are on 192.168.1.0/24 -- same subnet.${NC}"
    echo
    echo -e "  ${MUTED}  Step 1: A checks ARP cache -- no entry for 192.168.1.20${NC}"
    echo -e "  ${SUCCESS}  Step 2: A broadcasts ARP Request:${NC}"
    echo -e "  ${VALUE}          src MAC=aa:bb:cc:11:22:33  src IP=192.168.1.5${NC}"
    echo -e "  ${VALUE}          dst MAC=ff:ff:ff:ff:ff:ff  dst IP=192.168.1.20${NC}"
    echo -e "  ${MUTED}          'Who has 192.168.1.20? Tell 192.168.1.5'${NC}"
    echo -e "  ${SUCCESS}  Step 3: B receives broadcast, sends unicast ARP Reply:${NC}"
    echo -e "  ${VALUE}          src MAC=dd:ee:ff:44:55:66  src IP=192.168.1.20${NC}"
    echo -e "  ${VALUE}          dst MAC=aa:bb:cc:11:22:33  dst IP=192.168.1.5${NC}"
    echo -e "  ${MUTED}          'I am 192.168.1.20 -- my MAC is dd:ee:ff:44:55:66'${NC}"
    echo -e "  ${SUCCESS}  Step 4: A caches the mapping, builds Ethernet frame to B's MAC${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo

    echo -e "  ${AMBER}${BOLD}Scenario 2 -- Cross-subnet communication (the key insight)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo -e "  ${MUTED}  Host A (192.168.1.5) wants to reach Server (10.0.0.50).${NC}"
    echo -e "  ${MUTED}  Different subnets -- A cannot ARP for 10.0.0.50 directly.${NC}"
    echo
    echo -e "  ${MUTED}  Step 1: A sees dst IP is not on local subnet -> send to gateway${NC}"
    echo -e "  ${SUCCESS}  Step 2: A ARPs for the GATEWAY (192.168.1.1), not for 10.0.0.50${NC}"
    echo -e "  ${VALUE}          'Who has 192.168.1.1?'${NC}"
    echo -e "  ${SUCCESS}  Step 3: Gateway replies with its MAC (e.g. 00:11:22:33:44:55)${NC}"
    echo -e "  ${SUCCESS}  Step 4: A sends frame with dst MAC = GATEWAY MAC, dst IP = 10.0.0.50${NC}"
    echo -e "  ${MUTED}          The IP header carries the final destination; the MAC only goes${NC}"
    echo -e "  ${MUTED}          to the next hop. The router strips the L2 frame and re-ARPs.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo

    echo -e "  ${AMBER}${BOLD}Scenario 3 -- Proxy ARP${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo -e "  ${MUTED}  A router or gateway answers ARP requests on behalf of another host.${NC}"
    echo -e "  ${MUTED}  The querying host thinks the gateway IS the target -- traffic is${NC}"
    echo -e "  ${MUTED}  intercepted and forwarded. Useful when hosts lack a default gateway.${NC}"
    echo
    echo -e "  ${MUTED}  Common uses:${NC}"
    kv "    VPN gateways"    "Answer ARP for VPN client IPs on the LAN segment"
    kv "    Cloud instances" "Hypervisor answers ARP for VM IPs; VM never sees raw broadcast"
    kv "    Legacy networks" "Routers with ip proxy-arp can bridge misconfigured subnets"
    echo -e "  ${WARNING}  Risk: misconfigured proxy ARP causes routing loops and black holes${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo

    echo -e "  ${AMBER}${BOLD}Gratuitous ARP -- announcing yourself${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo -e "  ${MUTED}  A Gratuitous ARP is an ARP Request where src IP = target IP.${NC}"
    echo -e "  ${MUTED}  The host is not asking -- it is broadcasting its own mapping.${NC}"
    echo
    echo -e "  ${AMBER}  Sent when:${NC}"
    kv "    Interface comes up"  "Populate neighbours' caches immediately"
    kv "    IP address changes"  "Flush stale caches across the LAN"
    kv "    HSRP/VRRP failover"  "New active router announces its IP->MAC mapping"
    kv "    Live VM migration"   "VM moved to new host announces new MAC for same IP"
    echo
    echo -e "  ${FAILURE}  Security risk:${NC}  ${MUTED}An attacker can send gratuitous ARP to poison caches.${NC}"
    echo -e "  ${MUTED}  All hosts accept it -- no authentication in ARP.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo

    #  SECTION 3 -- ARP CACHE ENTRY STATES
    section "ARP Cache Entry States"

    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${BOLD}${TITLE}%-12s  %s${NC}\n" "State" "Meaning"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${SUCCESS}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "REACHABLE" "Recently confirmed -- MAC is valid; used for forwarding"
    printf "  ${MUTED}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "STALE"     "Timed out but cached; will be re-verified on next use"
    printf "  ${WARNING}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "DELAY"     "Stale entry used; waiting for confirmation before probing"
    printf "  ${AMBER}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "PROBE"     "Actively sending unicast ARP to re-verify the mapping"
    printf "  ${FAILURE}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "FAILED"    "Probe got no reply -- host presumed unreachable"
    printf "  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "PERMANENT"  "Manually added static entry -- never expires, never re-verified"
    printf "  ${LABEL}%-12s${NC}  ${VALUE}%s${NC}\n" \
        "INCOMPLETE" "ARP request sent; waiting for reply (transient)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo

    #  SECTION 4 -- NDP COMPARISON
    section "NDP -- IPv6 Replaces ARP"

    echo -e "  ${INFO}IPv6 does not use ARP. Instead it uses NDP (Neighbour Discovery Protocol,${NC}"
    echo -e "  ${MUTED}RFC 4861), which is part of ICMPv6. NDP does everything ARP does plus more.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}NDP vs ARP -- comparison:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${BOLD}${TITLE}%-28s  %-18s  %-18s${NC}\n" "Function" "ARP (IPv4)" "NDP (IPv6)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Address resolution"      "ARP Request/Reply"     "NS / NA messages"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Transport"               "Ethernet broadcast"    "IPv6 multicast (ICMPv6)"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Router discovery"        "Manual / DHCP"         "RS / RA messages"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Prefix/route info"       "DHCP only"             "RA carries prefix + route"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Auto-configuration"      "APIPA (169.254/16)"    "SLAAC from RA prefix"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Duplicate addr detect"   "Gratuitous ARP"        "DAD via NS to own address"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Security extension"      "None"                  "SEND (RFC 3971)"
    printf "  ${LABEL}%-28s${NC}  ${MUTED}%-18s${NC}  ${SUCCESS}%-18s${NC}\n" \
        "Cache poisoning risk"    "High (no auth)"        "Lower (multicast scope)"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    echo
    echo -e "  ${AMBER}${BOLD}NDP message types (ICMPv6):${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${GREEN}%-6s  %-22s${NC}  ${VALUE}%s${NC}\n" \
        "Type" "Name" "Purpose"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-22s${NC}  ${VALUE}%s${NC}\n" \
        "133"  "Router Solicitation"    "Host asks 'is there a router here?'"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-22s${NC}  ${VALUE}%s${NC}\n" \
        "134"  "Router Advertisement"   "Router announces prefix, MTU, default gateway"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-22s${NC}  ${VALUE}%s${NC}\n" \
        "135"  "Neighbour Solicitation" "ARP Request equivalent -- 'who has this IPv6?'"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-22s${NC}  ${VALUE}%s${NC}\n" \
        "136"  "Neighbour Advertisement" "ARP Reply equivalent -- 'I have this IPv6'"
    printf "  ${GREEN}%-6s${NC}  ${LABEL}%-22s${NC}  ${VALUE}%s${NC}\n" \
        "137"  "Redirect"               "Router tells host of a better next hop"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
    echo -e "  ${AMBER}${BOLD}Why NDP is better than ARP:${NC}"
    kv "  Multicast not broadcast" "NS sent to solicited-node multicast -- only the target wakes up"
    kv "  Integrated with routing" "RA replaces DHCP for default gateway and prefix discovery"
    kv "  DAD built-in"            "Duplicate Address Detection before using an address"
    kv "  SEND optional"           "Cryptographically signed NDP messages (rarely deployed)"
    echo

    #  SECTION 5 -- LIVE SYSTEM (unchanged)
    section "Current ARP Cache"
    echo -e "  ${INFO}ARP/Neighbour table:${NC}"
    echo
    printf "  ${BOLD}%-18s %-20s %-12s %-10s${NC}\n" "IP" "MAC" "Interface" "State"
    printf "  ${DARK_GRAY}%-18s %-20s %-12s %-10s${NC}\n" \
        "------------------" "--------------------" "------------" "----------"
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
    local gw; gw=$(get_gateway)
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
    echo -e "  ${MUTED}  First 3 bytes of MAC = OUI (Organizationally Unique Identifier)${NC}"
    echo
    ip link show 2>/dev/null | grep "link/ether" | awk '{print $2}' | while read -r mac; do
        local oui; oui=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
        echo -e "  MAC ${WHITE}${mac}${NC}  OUI ${GOLD}${oui}${NC}"
    done

    section "ARP Watch (5 seconds)"
    if cmd_exists tcpdump; then
        echo -e "  ${MUTED}Capturing ARP packets for 5 seconds (requires sudo)...${NC}"
        sudo -n timeout 5 tcpdump -ql -e arp 2>/dev/null \
            | grep -v "^tcpdump" | head -20 | sed 's/^/  /' \
            || echo -e "  ${MUTED}ARP capture not available (no sudo or tcpdump)${NC}"
    else
        status_line neutral "tcpdump not available -- install for ARP watch"
    fi

    header "ARP Spoof Detection"
    echo -e "  ${INFO}Checking duplicate MAC entries...${NC}"
    ip neigh show | awk '{print $5}' | sort | uniq -d | while read -r mac; do
        echo -e "  ${FAILURE}Duplicate MAC detected: $mac${NC}"
    done
    echo
    echo -e "  ${WARNING}Duplicate MACs may indicate ARP spoofing${NC}"
}

#  MAIN
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