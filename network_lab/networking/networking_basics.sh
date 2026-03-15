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
 
    #  SECTION 1 -- OVERVIEW
    header "OSI Model -- 7 Layers"
 
    echo -e "  ${INFO}The OSI (Open Systems Interconnection) model is a conceptual framework${NC}"
    echo -e "  ${MUTED}published by ISO in 1984. It divides network communication into 7 discrete${NC}"
    echo -e "  ${MUTED}layers so that hardware vendors, OS developers, and application programmers${NC}"
    echo -e "  ${MUTED}can build interoperable products without depending on each other's internals.${NC}"
    echo
    echo -e "  ${MUTED}Each layer has one job. It provides a service to the layer above it and${NC}"
    echo -e "  ${MUTED}consumes a service from the layer below it. Layers only communicate${NC}"
    echo -e "  ${MUTED}directly with their immediate neighbours -- never across layers.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Memory aid (top to bottom):${NC}"
    echo -e "  ${MUTED}  All People Seem To Need Data Processing${NC}"
    echo -e "  ${MUTED}  Application - Presentation - Session - Transport - Network - Data Link - Physical${NC}"
    echo
 
    #  SECTION 2 -- LAYER REFERENCE TABLE
    section "Layer Reference Table"
 
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..78})"
    printf "  ${BOLD}${TITLE}%-4s  %-14s  %-10s  %-18s  %s${NC}\n" \
        "No." "Name" "Data Unit" "Key Protocols" "Responsibility"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..78})"
 
    printf "  ${AMBER}%-4s${NC}  ${BOLD}${WHITE}%-14s${NC}  ${LABEL}%-10s${NC}  ${GREEN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L7" "APPLICATION"  "Data"     "HTTP FTP SMTP DNS"   "User-facing services and APIs"
    printf "  ${AMBER}%-4s${NC}  ${BOLD}${WHITE}%-14s${NC}  ${LABEL}%-10s${NC}  ${GREEN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L6" "PRESENTATION" "Data"     "TLS SSL JPEG GZIP"   "Encoding, encryption, compression"
    printf "  ${AMBER}%-4s${NC}  ${BOLD}${WHITE}%-14s${NC}  ${LABEL}%-10s${NC}  ${GREEN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L5" "SESSION"      "Data"     "RPC NetBIOS SIP"     "Open, manage, close sessions"
    printf "  ${AMBER}%-4s${NC}  ${BOLD}${WHITE}%-14s${NC}  ${LABEL}%-10s${NC}  ${GREEN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L4" "TRANSPORT"    "Segment"  "TCP UDP SCTP"        "End-to-end delivery, ports, flow"
    printf "  ${AMBER}%-4s${NC}  ${BOLD}${WHITE}%-14s${NC}  ${LABEL}%-10s${NC}  ${GREEN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L3" "NETWORK"      "Packet"   "IP ICMP OSPF BGP"    "Logical addressing and routing"
    printf "  ${AMBER}%-4s${NC}  ${BOLD}${WHITE}%-14s${NC}  ${LABEL}%-10s${NC}  ${GREEN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L2" "DATA LINK"    "Frame"    "Ethernet WiFi ARP"   "MAC addressing, error detection"
    printf "  ${AMBER}%-4s${NC}  ${BOLD}${WHITE}%-14s${NC}  ${LABEL}%-10s${NC}  ${GREEN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L1" "PHYSICAL"     "Bit"      "RJ45 Fiber DSL"      "Electrical/optical signal tx"
 
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..78})"
    echo
 
    #  SECTION 3 -- LAYER-BY-LAYER DEEP DIVE
    section "Layer-by-Layer Detail"
 
    # L7
    echo -e "  ${AMBER}${BOLD}Layer 7 -- Application${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  The only layer the end user ever interacts with directly.${NC}"
    echo -e "  ${MUTED}  It is NOT the application itself (e.g. Firefox) but the protocol${NC}"
    echo -e "  ${MUTED}  the application uses to communicate (e.g. HTTP).${NC}"
    echo -e "  ${MUTED}  Responsible for identifying communication partners, checking resource${NC}"
    echo -e "  ${MUTED}  availability, and synchronising communication.${NC}"
    echo
    kv "  Data unit"    "Data (application payload)"
    kv "  Protocols"    "HTTP  HTTPS  FTP  SFTP  SMTP  POP3  IMAP  DNS  SSH  SNMP  DHCP  LDAP  RDP"
    kv "  Devices"      "Servers, PCs, phones -- anything running application software"
    kv "  Real example" "Browser sends 'GET /index.html HTTP/1.1' to a web server"
    echo
 
    # L6
    echo -e "  ${AMBER}${BOLD}Layer 6 -- Presentation${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  The translator of the OSI model. Converts data between the format${NC}"
    echo -e "  ${MUTED}  the application uses and the format the network uses.${NC}"
    echo -e "  ${MUTED}  Handles three concerns: syntax translation, encryption/decryption,${NC}"
    echo -e "  ${MUTED}  and compression/decompression.${NC}"
    echo -e "  ${MUTED}  In practice, TLS/SSL lives here -- it wraps application data before${NC}"
    echo -e "  ${MUTED}  handing it to the Session layer.${NC}"
    echo
    kv "  Data unit"    "Data"
    kv "  Protocols"    "TLS  SSL  JPEG  PNG  MPEG  ASCII  EBCDIC  GZIP  MIME"
    kv "  Devices"      "No dedicated hardware -- handled by OS/library (e.g. OpenSSL)"
    kv "  Real example" "OpenSSL encrypts HTTP payload into TLS record before sending"
    echo
 
    # L5
    echo -e "  ${AMBER}${BOLD}Layer 5 -- Session${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Establishes, maintains, and terminates sessions between applications.${NC}"
    echo -e "  ${MUTED}  A session is a logical persistent connection -- it can survive brief${NC}"
    echo -e "  ${MUTED}  transport interruptions by re-establishing the underlying connection.${NC}"
    echo -e "  ${MUTED}  Also handles checkpointing: large file transfers can resume from a${NC}"
    echo -e "  ${MUTED}  checkpoint rather than restarting from zero.${NC}"
    echo
    kv "  Data unit"    "Data"
    kv "  Protocols"    "RPC  NFS  SMB  NetBIOS  SIP  H.245  PPTP"
    kv "  Devices"      "No dedicated hardware -- handled by OS/middleware"
    kv "  Real example" "Video call app maintains session state across brief network drops"
    echo
 
    # L4
    echo -e "  ${AMBER}${BOLD}Layer 4 -- Transport${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  The first layer that provides end-to-end communication between${NC}"
    echo -e "  ${MUTED}  two hosts (not just the next hop). It introduces port numbers,${NC}"
    echo -e "  ${MUTED}  which allow multiple simultaneous conversations on the same IP.${NC}"
    echo -e "  ${MUTED}  TCP (connection-oriented) adds reliability: sequencing, ACKs,${NC}"
    echo -e "  ${MUTED}  retransmission, flow control, and congestion control.${NC}"
    echo -e "  ${MUTED}  UDP (connectionless) skips all of that for speed.${NC}"
    echo
    kv "  Data unit"    "Segment (TCP) / Datagram (UDP)"
    kv "  Protocols"    "TCP  UDP  SCTP  DCCP  QUIC"
    kv "  Devices"      "Firewalls (L4), load balancers, host OS network stack"
    kv "  Real example" "TCP splits 1 MB file into ~700 segments; reassembles at the other end"
    echo
 
    # L3
    echo -e "  ${AMBER}${BOLD}Layer 3 -- Network${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Responsible for moving packets across multiple networks from source${NC}"
    echo -e "  ${MUTED}  to destination. Introduces logical (IP) addressing -- unlike MAC${NC}"
    echo -e "  ${MUTED}  addresses, IP addresses are hierarchical and routable.${NC}"
    echo -e "  ${MUTED}  Routers operate here: they read the destination IP, consult their${NC}"
    echo -e "  ${MUTED}  routing table, and forward the packet to the next-hop router.${NC}"
    echo -e "  ${MUTED}  This layer does NOT guarantee delivery or ordering.${NC}"
    echo
    kv "  Data unit"    "Packet"
    kv "  Protocols"    "IPv4  IPv6  ICMP  ICMPv6  OSPF  BGP  RIP  EIGRP  IPsec"
    kv "  Devices"      "Routers, L3 switches, firewalls"
    kv "  Real example" "Router reads dst IP 8.8.8.8, matches /0 default route, forwards to ISP"
    echo
 
    # L2
    echo -e "  ${AMBER}${BOLD}Layer 2 -- Data Link${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Governs how data is framed and transmitted between two nodes on the${NC}"
    echo -e "  ${MUTED}  SAME physical network. Introduces MAC (Media Access Control) addresses${NC}"
    echo -e "  ${MUTED}  -- 48-bit hardware identifiers burned into NICs.${NC}"
    echo -e "  ${MUTED}  Split into two sublayers: LLC (logical link control, flow/error) and${NC}"
    echo -e "  ${MUTED}  MAC (medium access, addressing, frame delimiting).${NC}"
    echo -e "  ${MUTED}  Switches operate here: they build MAC address tables and forward${NC}"
    echo -e "  ${MUTED}  frames only to the correct port.${NC}"
    echo
    kv "  Data unit"    "Frame"
    kv "  Protocols"    "Ethernet (802.3)  WiFi (802.11)  PPP  HDLC  ARP  STP  VLAN (802.1Q)"
    kv "  Devices"      "Switches, bridges, NICs, access points"
    kv "  Real example" "Switch learns src MAC aa:bb:cc:dd:ee:ff on port 3; forwards future frames there"
    echo
 
    # L1
    echo -e "  ${AMBER}${BOLD}Layer 1 -- Physical${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  The raw bit pipe. Defines the electrical, optical, or radio signals${NC}"
    echo -e "  ${MUTED}  that represent 0s and 1s. No addressing -- just signal transmission.${NC}"
    echo -e "  ${MUTED}  Specifies: voltage levels, cable types, connector pinouts, bit timing,${NC}"
    echo -e "  ${MUTED}  modulation schemes, duplex mode (half/full), and physical topology.${NC}"
    echo
    kv "  Data unit"    "Bit"
    kv "  Standards"    "Ethernet (IEEE 802.3)  USB  DSL  SONET  RS-232  Bluetooth  802.11"
    kv "  Media"        "Copper (Cat5e/6/6a)  Fibre optic (SMF/MMF)  Radio (WiFi/LTE)"
    kv "  Devices"      "Hubs, repeaters, cables, modems, transceivers, antennas"
    kv "  Real example" "Cat6 cable transmits 10 Gbps using 4 twisted pairs at 250 MHz"
    echo
 
    #  SECTION 4 -- ENCAPSULATION / DECAPSULATION
    section "Encapsulation -- How Data Travels Down the Stack (Sender)"
 
    echo -e "  ${MUTED}  Each layer wraps the data from the layer above with its own header${NC}"
    echo -e "  ${MUTED}  (and sometimes a trailer). This is called encapsulation.${NC}"
    echo -e "  ${MUTED}  At the receiver, each layer strips its own header -- decapsulation.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Sender (top to bottom):${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${AMBER}L7-L5${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n" \
        "[ DATA        ]" "Application generates payload (e.g. HTTP request)"
    echo -e "  ${MUTED}          add L4 header${NC}  ${MUTED}(TCP/UDP src+dst port, seq/ack)${NC}"
    printf "  ${AMBER}L4   ${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n" \
        "[ L4 | DATA   ]" "Segment -- adds port numbers, sequence info"
    echo -e "  ${MUTED}          add L3 header${NC}  ${MUTED}(IP src+dst address, TTL, protocol)${NC}"
    printf "  ${AMBER}L3   ${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n" \
        "[L3|L4|DATA   ]" "Packet -- adds IP addresses"
    echo -e "  ${MUTED}          add L2 header + trailer${NC}  ${MUTED}(MAC src+dst, EtherType, FCS checksum)${NC}"
    printf "  ${AMBER}L2   ${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n" \
        "[L2|L3|L4|DATA|FCS]" "Frame -- adds MAC addresses and error-check"
    echo -e "  ${MUTED}          encode as electrical/optical/radio signal${NC}"
    printf "  ${AMBER}L1   ${NC}  ${LABEL}%-14s${NC}  ${VALUE}%s${NC}\n" \
        "1010110010...   " "Bits on the wire"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo
    echo -e "  ${AMBER}${BOLD}Receiver (bottom to top) -- decapsulation:${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    printf "  ${AMBER}L1   ${NC}  ${MUTED}Receives bits, reconstructs frame${NC}\n"
    printf "  ${AMBER}L2   ${NC}  ${MUTED}Checks FCS, strips L2 header, passes packet up${NC}\n"
    printf "  ${AMBER}L3   ${NC}  ${MUTED}Checks dst IP, strips L3 header, passes segment up${NC}\n"
    printf "  ${AMBER}L4   ${NC}  ${MUTED}Checks port, reassembles stream, strips L4 header${NC}\n"
    printf "  ${AMBER}L5-7 ${NC}  ${MUTED}Decrypts (L6), manages session (L5), delivers to app (L7)${NC}\n"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..66})"
    echo
    echo -e "  ${AMBER}${BOLD}Concrete example -- browser fetching https://example.com:${NC}"
    echo -e "  ${MUTED}  L7  HTTP GET /index.html${NC}"
    echo -e "  ${MUTED}  L6  TLS encrypts the GET request${NC}"
    echo -e "  ${MUTED}  L5  TLS session maintained${NC}"
    echo -e "  ${MUTED}  L4  TCP segment: src=54321 dst=443 seq=1${NC}"
    echo -e "  ${MUTED}  L3  IP packet:   src=192.168.1.5 dst=93.184.216.34${NC}"
    echo -e "  ${MUTED}  L2  Ethernet frame: src=aa:bb:cc dst=gateway-MAC${NC}"
    echo -e "  ${MUTED}  L1  Electrical pulses on Cat6 cable${NC}"
    echo
 
    #  SECTION 5 -- REAL-WORLD DEVICE MAPPING
    section "Real-World Device and Protocol Mapping"
 
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..76})"
    printf "  ${BOLD}${TITLE}%-6s  %-14s  %-22s  %s${NC}\n" \
        "Layer" "Name" "Devices" "Common Protocols"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..76})"
    printf "  ${AMBER}%-6s${NC}  ${WHITE}%-14s${NC}  ${LABEL}%-22s${NC}  ${GREEN}%s${NC}\n" \
        "L7" "Application"  "PC  Phone  Server"           "HTTP HTTPS FTP SSH DNS SMTP SNMP"
    printf "  ${AMBER}%-6s${NC}  ${WHITE}%-14s${NC}  ${LABEL}%-22s${NC}  ${GREEN}%s${NC}\n" \
        "L6" "Presentation" "PC  Phone  Server"           "TLS SSL JPEG GZIP ASCII MIME"
    printf "  ${AMBER}%-6s${NC}  ${WHITE}%-14s${NC}  ${LABEL}%-22s${NC}  ${GREEN}%s${NC}\n" \
        "L5" "Session"      "PC  Phone  Server"           "RPC SMB NFS SIP NetBIOS"
    printf "  ${AMBER}%-6s${NC}  ${WHITE}%-14s${NC}  ${LABEL}%-22s${NC}  ${GREEN}%s${NC}\n" \
        "L4" "Transport"    "Firewall  Load Balancer"     "TCP UDP SCTP QUIC DCCP"
    printf "  ${AMBER}%-6s${NC}  ${WHITE}%-14s${NC}  ${LABEL}%-22s${NC}  ${GREEN}%s${NC}\n" \
        "L3" "Network"      "Router  L3 Switch  Firewall" "IPv4 IPv6 ICMP OSPF BGP RIP"
    printf "  ${AMBER}%-6s${NC}  ${WHITE}%-14s${NC}  ${LABEL}%-22s${NC}  ${GREEN}%s${NC}\n" \
        "L2" "Data Link"    "Switch  Bridge  NIC  AP"     "Ethernet 802.11 ARP STP PPP"
    printf "  ${AMBER}%-6s${NC}  ${WHITE}%-14s${NC}  ${LABEL}%-22s${NC}  ${GREEN}%s${NC}\n" \
        "L1" "Physical"     "Hub  Repeater  Cable  Modem" "802.3 DSL SONET RS-232 USB"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..76})"
    echo
    echo -e "  ${AMBER}${BOLD}Key distinction -- switches vs routers vs hubs:${NC}"
    kv "  Hub (L1)"       "Broadcasts every bit to all ports -- no intelligence whatsoever"
    kv "  Switch (L2)"    "Reads dst MAC, forwards frame only to correct port -- learns table"
    kv "  Router (L3)"    "Reads dst IP, consults route table, forwards to next hop"
    kv "  L3 Switch"      "Switch with routing capability -- common in enterprise LANs"
    kv "  Firewall (L3/4)" "Filters by IP + port -- stateful firewalls track TCP connections"
    echo
 
    #  SECTION 6 -- ATTACK SURFACE PER LAYER
    section "Attack Surface by OSI Layer"
 
    echo -e "  ${MUTED}  Every layer introduces its own set of vulnerabilities.${NC}"
    echo -e "  ${MUTED}  Understanding which layer an attack targets helps choose the right defence.${NC}"
    echo
 
    echo -e "  ${FAILURE}${BOLD}L1 -- Physical Attacks${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Wiretapping"        "Physical tap on copper cable; passive, hard to detect"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Cable cutting"      "Physical DoS -- sever the link; takes down entire segment"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Rogue hardware"     "Plug in a malicious device to an unused port"
    echo -e "  ${AMBER}  Defence: physical security, locked comms rooms, fibre (harder to tap)${NC}"
    echo
 
    echo -e "  ${FAILURE}${BOLD}L2 -- Data Link Attacks${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "ARP Spoofing"       "Send fake ARP replies mapping attacker MAC to victim IP"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "MAC Flooding"       "Overflow switch CAM table; switch degrades to hub mode"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "VLAN Hopping"       "Double-tagging or switch spoofing to reach other VLANs"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "STP Manipulation"   "Become root bridge; redirect all switch traffic through attacker"
    echo -e "  ${AMBER}  Defence: Dynamic ARP Inspection, port security, BPDU guard, private VLANs${NC}"
    echo
 
    echo -e "  ${FAILURE}${BOLD}L3 -- Network Attacks${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "IP Spoofing"        "Forge src IP to impersonate another host or bypass ACLs"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "ICMP Redirect"      "Send fake ICMP redirect to reroute victim traffic"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Route Injection"    "Inject malicious routes via BGP/OSPF to hijack traffic"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Smurf Attack"       "ICMP broadcast amplification DDoS using spoofed src IP"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Fragmentation"      "Overlapping IP fragments evade IDS reassembly checks"
    echo -e "  ${AMBER}  Defence: BCP38 (ingress filtering), route authentication, TTL inspection${NC}"
    echo
 
    echo -e "  ${FAILURE}${BOLD}L4 -- Transport Attacks${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "SYN Flood"          "Exhaust server half-open connection queue (see TCP module)"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "RST Injection"      "Forge RST to kill established TCP sessions"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Port Scanning"      "Probe open ports to map services before exploitation"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "UDP Amplification"  "Abuse stateless UDP for reflection/amplification DDoS"
    echo -e "  ${AMBER}  Defence: SYN cookies, rate limiting, stateful firewall, TCP-AO${NC}"
    echo
 
    echo -e "  ${FAILURE}${BOLD}L5-L6 -- Session / Presentation Attacks${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Session Hijacking"  "Steal session token to impersonate authenticated user"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "SSL Stripping"      "Downgrade HTTPS to HTTP -- user sends creds in plaintext"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "BEAST / POODLE"     "Cipher-mode attacks against TLS 1.0 / SSL 3.0"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Heartbleed"         "OpenSSL buffer overread -- leaks private key material"
    echo -e "  ${AMBER}  Defence: TLS 1.3 only, HSTS, secure+HttpOnly cookies, token rotation${NC}"
    echo
 
    echo -e "  ${FAILURE}${BOLD}L7 -- Application Attacks${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "SQL Injection"      "Inject SQL into app queries to dump/modify the database"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "XSS"                "Inject JS into pages -- steal cookies, hijack sessions"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "DNS Spoofing"       "Poison resolver cache to redirect users to fake servers"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "HTTP Request Smugg" "Desync frontend/backend parsing to bypass security controls"
    printf "  ${LABEL}%-26s${NC}  ${VALUE}%s${NC}\n" "Slowloris"          "Hold open many partial HTTP connections to exhaust threads"
    echo -e "  ${AMBER}  Defence: WAF, input validation, parameterised queries, rate limiting${NC}"
    echo
 
    #  SECTION 7 -- LIVE SYSTEM (unchanged)
    section "System Components by OSI Layer"
 
    echo -e "\n  ${BLUE}[Layer 7 -- Application]${NC}"
    echo -e "  ${INFO}Active network services:${NC}"
    if cmd_exists ss; then
        ss -tulpn 2>/dev/null | head -10
    else
        netstat -tulpn 2>/dev/null | head -10
    fi
 
    echo -e "\n  ${BLUE}[Layer 4 -- Transport]${NC}"
    echo -e "  ${INFO}TCP/UDP socket summary:${NC}"
    ss -s 2>/dev/null || netstat -s 2>/dev/null | grep -E "(TCP|UDP)" | head -10
 
    echo -e "\n  ${BLUE}[Layer 3 -- Network]${NC}"
    echo -e "  ${INFO}IP routing table:${NC}"
    ip route 2>/dev/null | sed 's/^/  /' || route -n 2>/dev/null | sed 's/^/  /'
 
    echo -e "\n  ${BLUE}[Layer 2 -- Data Link]${NC}"
    echo -e "  ${INFO}Network interfaces with MAC addresses:${NC}"
    ip link show 2>/dev/null | sed 's/^/  /' || ifconfig -a 2>/dev/null | sed 's/^/  /'
 
    echo -e "\n  ${BLUE}[Layer 1 -- Physical]${NC}"
    echo -e "  ${INFO}Physical interface status:${NC}"
    ip -s link 2>/dev/null | grep -E "(state|RX:|TX:)" | sed 's/^/  /' \
        || ifconfig 2>/dev/null | grep -E "(UP|DOWN|RX|TX)" | sed 's/^/  /'
 
    pause
}

#  TCP/IP MODEL
check_tcpip_model() {
 
    #  SECTION 1 -- OVERVIEW
    header "TCP/IP Model -- 4 Layers"
 
    echo -e "  ${INFO}The TCP/IP model (also called the Internet model or DoD model) was${NC}"
    echo -e "  ${MUTED}developed by DARPA in the 1970s as the practical implementation model${NC}"
    echo -e "  ${MUTED}for ARPANET -- the precursor to the modern Internet.${NC}"
    echo
    echo -e "  ${MUTED}Unlike the OSI model which is a theoretical reference framework, TCP/IP${NC}"
    echo -e "  ${MUTED}is the model that the Internet actually runs on. It collapses OSI's${NC}"
    echo -e "  ${MUTED}7 layers into 4 by merging the upper layers and lower layers.${NC}"
    echo
    echo -e "  ${MUTED}Every device connected to the Internet -- phones, routers, servers --${NC}"
    echo -e "  ${MUTED}implements this stack. Understanding it is understanding the Internet.${NC}"
    echo
 
    #  SECTION 2 -- OSI vs TCP/IP COMPARISON
    section "OSI vs TCP/IP -- Side-by-Side Mapping"
 
    echo -e "  ${MUTED}  The two models describe the same reality; OSI is more granular.${NC}"
    echo -e "  ${MUTED}  TCP/IP maps directly to real implementations; OSI is a teaching tool.${NC}"
    echo
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${BOLD}${TITLE}%-6s  %-16s  %-6s  %-18s  %s${NC}\n" \
        "OSI#" "OSI Name" "TCP#" "TCP/IP Name" "Key Protocols"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${AMBER}%-6s${NC}  ${MUTED}%-16s${NC}  ${GREEN}%-6s${NC}  ${CYAN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L7" "Application"  "L4" "Application" "HTTP HTTPS FTP SSH SMTP DNS DHCP"
    printf "  ${AMBER}%-6s${NC}  ${MUTED}%-16s${NC}  ${GREEN}%-6s${NC}  ${CYAN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L6" "Presentation" "L4" "Application" "TLS SSL MIME JPEG GZIP"
    printf "  ${AMBER}%-6s${NC}  ${MUTED}%-16s${NC}  ${GREEN}%-6s${NC}  ${CYAN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L5" "Session"      "L4" "Application" "RPC SMB NFS SIP NetBIOS"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${AMBER}%-6s${NC}  ${MUTED}%-16s${NC}  ${GREEN}%-6s${NC}  ${CYAN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L4" "Transport"    "L3" "Transport"   "TCP UDP SCTP QUIC DCCP"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${AMBER}%-6s${NC}  ${MUTED}%-16s${NC}  ${GREEN}%-6s${NC}  ${CYAN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L3" "Network"      "L2" "Internet"    "IPv4 IPv6 ICMP ICMPv6 OSPF BGP"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    printf "  ${AMBER}%-6s${NC}  ${MUTED}%-16s${NC}  ${GREEN}%-6s${NC}  ${CYAN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L2" "Data Link"    "L1" "Net Access"  "Ethernet 802.11 ARP PPP HDLC"
    printf "  ${AMBER}%-6s${NC}  ${MUTED}%-16s${NC}  ${GREEN}%-6s${NC}  ${CYAN}%-18s${NC}  ${VALUE}%s${NC}\n" \
        "L1" "Physical"     "L1" "Net Access"  "RJ45 Fibre DSL Radio 802.3"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..70})"
    echo
    echo -e "  ${AMBER}${BOLD}Why does TCP/IP merge OSI L5/L6/L7 into one Application layer?${NC}"
    echo -e "  ${MUTED}  In practice, most application protocols handle their own session${NC}"
    echo -e "  ${MUTED}  management and data formatting internally. HTTP manages sessions${NC}"
    echo -e "  ${MUTED}  via cookies; TLS handles encryption at the library level. There was${NC}"
    echo -e "  ${MUTED}  no value in forcing these into separate protocol layers.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Why does TCP/IP merge OSI L1/L2 into one Network Access layer?${NC}"
    echo -e "  ${MUTED}  TCP/IP was designed to run over ANY link layer -- Ethernet, WiFi,${NC}"
    echo -e "  ${MUTED}  satellite, serial lines. It deliberately treats the underlying${NC}"
    echo -e "  ${MUTED}  physical medium as a black box it doesn't need to understand.${NC}"
    echo
 
    #  SECTION 3 -- LAYER DEEP DIVES
    section "TCP/IP Layer Deep Dives"
 
    # L4 Application
    echo -e "  ${AMBER}${BOLD}Layer 4 -- Application  (OSI L5 + L6 + L7)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Everything the user or application directly interacts with.${NC}"
    echo -e "  ${MUTED}  Application protocols define the message format, the request/response${NC}"
    echo -e "  ${MUTED}  semantics, error handling, and connection lifecycle.${NC}"
    echo -e "  ${MUTED}  This layer also includes encryption (TLS) and data formatting (MIME).${NC}"
    echo
    printf "  ${BOLD}${TITLE}%-8s  %-6s  %-6s  %s${NC}\n" "Protocol" "Port" "Trans" "Purpose"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "HTTP"   "80"   "TCP"  "Web page transfer -- plain text"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "HTTPS"  "443"  "TCP"  "HTTP over TLS -- encrypted web"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "DNS"    "53"   "UDP"  "Hostname to IP resolution"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "DHCP"   "67"   "UDP"  "Automatic IP address assignment"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "SSH"    "22"   "TCP"  "Encrypted remote shell access"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "FTP"    "21"   "TCP"  "File transfer (control channel)"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "SMTP"   "25"   "TCP"  "Send email between mail servers"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "IMAP"   "143"  "TCP"  "Retrieve email, server-stored"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "SNMP"   "161"  "UDP"  "Network device monitoring"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "NTP"    "123"  "UDP"  "Time synchronisation"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "LDAP"   "389"  "TCP"  "Directory services (AD, OpenLDAP)"
    printf "  ${GREEN}%-8s${NC}  ${LABEL}%-6s${NC}  ${MUTED}%-6s${NC}  ${VALUE}%s${NC}\n" \
        "RDP"    "3389" "TCP"  "Remote Desktop Protocol (Windows)"
    echo
 
    # L3 Transport
    echo -e "  ${AMBER}${BOLD}Layer 3 -- Transport  (OSI L4)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Provides end-to-end communication between application processes.${NC}"
    echo -e "  ${MUTED}  Port numbers (0-65535) identify specific processes on a host:${NC}"
    echo -e "  ${MUTED}    0-1023     = Well-known ports (require root to bind)${NC}"
    echo -e "  ${MUTED}    1024-49151 = Registered ports (assigned by IANA)${NC}"
    echo -e "  ${MUTED}    49152-65535= Ephemeral ports (OS assigns to clients)${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}TCP -- Transmission Control Protocol:${NC}"
    kv "  Connection"     "3-way handshake before data; 4-way teardown after"
    kv "  Reliability"    "Sequence numbers + ACKs + retransmission on timeout"
    kv "  Flow control"   "Sliding window -- receiver advertises how much it can accept"
    kv "  Congestion ctrl" "Slow start, congestion avoidance, fast retransmit (CUBIC/BBR)"
    kv "  Use cases"      "HTTP, SSH, FTP, email -- anywhere data integrity matters"
    echo
    echo -e "  ${AMBER}${BOLD}UDP -- User Datagram Protocol:${NC}"
    kv "  Connection"     "None -- fire and forget"
    kv "  Reliability"    "None -- lost datagrams stay lost"
    kv "  Speed"          "No handshake overhead; lower latency"
    kv "  Use cases"      "DNS, DHCP, VoIP, streaming, gaming, QUIC"
    echo
    echo -e "  ${AMBER}${BOLD}QUIC -- Quick UDP Internet Connections (HTTP/3):${NC}"
    kv "  Built on"       "UDP -- bypasses TCP limitations in the kernel"
    kv "  Features"       "Multiplexed streams, built-in TLS 1.3, 0-RTT reconnect"
    kv "  Advantage"      "No TCP HOL blocking; packet loss only affects one stream"
    kv "  Use cases"      "HTTP/3, Google services, WebRTC"
    echo
 
    # L2 Internet
    echo -e "  ${AMBER}${BOLD}Layer 2 -- Internet  (OSI L3)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  The glue of the Internet. Routes packets across networks using${NC}"
    echo -e "  ${MUTED}  logical IP addresses. Every router on the Internet operates here.${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}IPv4:${NC}"
    kv "  Address size"   "32 bits -- 4 octets (e.g. 192.168.1.1)"
    kv "  Total space"    "~4.3 billion addresses (exhausted in 2011)"
    kv "  Header"         "20 bytes minimum; includes TTL, protocol, src/dst IP"
    kv "  TTL"            "Decremented by each router; packet dropped at 0 (prevents loops)"
    kv "  Fragmentation"  "Routers can split oversized packets (Path MTU Discovery preferred)"
    echo
    echo -e "  ${AMBER}${BOLD}IPv6:${NC}"
    kv "  Address size"   "128 bits -- 8 groups of 4 hex digits (e.g. 2001:db8::1)"
    kv "  Total space"    "340 undecillion addresses -- effectively inexhaustible"
    kv "  Header"         "Fixed 40 bytes; simpler than IPv4; no checksum"
    kv "  No NAT needed"  "Every device gets a globally unique address"
    kv "  New features"   "Stateless autoconfiguration (SLAAC), mandatory IPsec support"
    echo
    echo -e "  ${AMBER}${BOLD}ICMP -- Internet Control Message Protocol:${NC}"
    kv "  Purpose"        "Diagnostic and error reporting for IP (not application data)"
    kv "  ping"           "ICMP Echo Request / Echo Reply -- tests reachability and RTT"
    kv "  traceroute"     "Sends packets with TTL=1,2,3... each router sends ICMP TTL exceeded"
    kv "  MTU discovery"  "ICMP Fragmentation Needed tells sender to reduce packet size"
    echo
 
    # L1 Network Access
    echo -e "  ${AMBER}${BOLD}Layer 1 -- Network Access  (OSI L1 + L2)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  How data moves between directly connected nodes on the same network.${NC}"
    echo -e "  ${MUTED}  TCP/IP intentionally abstracts this: IP doesn't care whether the link${NC}"
    echo -e "  ${MUTED}  is Ethernet, WiFi, 4G, or a carrier pigeon (RFC 1149).${NC}"
    echo
    echo -e "  ${AMBER}${BOLD}Ethernet (IEEE 802.3):${NC}"
    kv "  Addressing"     "48-bit MAC addresses (OUI:device -- first 24 bits = vendor)"
    kv "  Frame size"     "64-1518 bytes standard; jumbo frames up to 9000 bytes"
    kv "  Speeds"         "10 Mbps -> 100 Mbps -> 1 Gbps -> 10/25/40/100 Gbps"
    kv "  FCS"            "4-byte CRC trailer -- detects (not corrects) transmission errors"
    echo
    echo -e "  ${AMBER}${BOLD}ARP -- Address Resolution Protocol:${NC}"
    kv "  Problem"        "IP knows dst IP but needs dst MAC to build the L2 frame"
    kv "  How"            "Broadcast: 'Who has 192.168.1.1? Tell 192.168.1.5'"
    kv "  Reply"          "Target unicasts its MAC back; both sides cache the mapping"
    kv "  Cache"          "ARP table stores IP->MAC; expires after ~20 min"
    kv "  Vulnerability"  "ARP has no authentication -- ARP spoofing is trivial on LAN"
    echo
    echo -e "  ${AMBER}${BOLD}WiFi (IEEE 802.11):${NC}"
    kv "  802.11a/b/g"    "Legacy -- 2.4/5 GHz, up to 54 Mbps"
    kv "  802.11n (WiFi4)" "2.4/5 GHz, MIMO, up to 600 Mbps"
    kv "  802.11ac (WiFi5)" "5 GHz only, MU-MIMO, up to 3.5 Gbps"
    kv "  802.11ax (WiFi6)" "2.4/5/6 GHz, OFDMA, up to 9.6 Gbps"
    echo
 
    #  SECTION 4 -- PACKET JOURNEY THROUGH THE STACK
    section "Packet Journey -- Browser to Web Server"
 
    echo -e "  ${MUTED}  Tracing a single HTTP GET request from your laptop to a web server.${NC}"
    echo -e "  ${MUTED}  Laptop IP: 192.168.1.100  Gateway: 192.168.1.1  Server: 93.184.216.34${NC}"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 1 -- Application layer builds the request${NC}"
    echo -e "  ${MUTED}  Browser calls: GET /index.html HTTP/1.1  Host: example.com${NC}"
    echo -e "  ${MUTED}  TLS encrypts the request into a TLS record${NC}"
    echo -e "  ${MUTED}  Result: [ TLS-encrypted HTTP payload ]${NC}"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 2 -- Transport layer wraps in TCP segment${NC}"
    echo -e "  ${MUTED}  OS picks ephemeral src port: 54321  dst port: 443${NC}"
    echo -e "  ${MUTED}  Adds sequence number, ACK, window size${NC}"
    echo -e "  ${MUTED}  Result: [ TCP hdr | TLS payload ]${NC}"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 3 -- Internet layer wraps in IP packet${NC}"
    echo -e "  ${MUTED}  src IP: 192.168.1.100  dst IP: 93.184.216.34  TTL: 64${NC}"
    echo -e "  ${MUTED}  Consults routing table: dst not local -> send to gateway 192.168.1.1${NC}"
    echo -e "  ${MUTED}  Result: [ IP hdr | TCP hdr | TLS payload ]${NC}"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 4 -- Network Access layer wraps in Ethernet frame${NC}"
    echo -e "  ${MUTED}  Need gateway MAC -- check ARP cache or send ARP request${NC}"
    echo -e "  ${MUTED}  src MAC: aa:bb:cc:11:22:33  dst MAC: gateway MAC${NC}"
    echo -e "  ${MUTED}  Appends FCS (CRC checksum) as trailer${NC}"
    echo -e "  ${MUTED}  Result: [ Eth hdr | IP hdr | TCP hdr | TLS payload | FCS ]${NC}"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 5 -- Physical: bits on the wire${NC}"
    echo -e "  ${MUTED}  NIC encodes frame as electrical pulses on Cat6 (or radio waves on WiFi)${NC}"
    echo -e "  ${MUTED}  Gateway switch receives bits, reconstructs frame${NC}"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 6 -- Gateway router receives frame${NC}"
    echo -e "  ${MUTED}  L2: checks dst MAC matches its own -> accept${NC}"
    echo -e "  ${MUTED}  L3: strips Ethernet, reads IP dst 93.184.216.34${NC}"
    echo -e "  ${MUTED}  L3: looks up route -> matches default route -> next hop = ISP router${NC}"
    echo -e "  ${MUTED}  L3: decrements TTL (64->63), updates IP checksum${NC}"
    echo -e "  ${MUTED}  L2: builds NEW Ethernet frame with ISP router MAC as dst${NC}"
    echo -e "  ${MUTED}  This L2 re-framing happens at EVERY router hop${NC}"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 7 -- Packet crosses the Internet (many hops)${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo -e "  ${MUTED}  Laptop${NC}  ${SUCCESS}---->${NC}  ${MUTED}Home router${NC}  ${SUCCESS}---->${NC}  ${MUTED}ISP edge${NC}  ${SUCCESS}---->${NC}  ${MUTED}...${NC}  ${SUCCESS}---->${NC}  ${MUTED}example.com${NC}"
    echo -e "  ${MUTED}  At each hop: L2 frame stripped and rebuilt. L3 packet: TTL-- only.${NC}"
    echo -e "  ${MUTED}  L4 and above: untouched until the destination host.${NC}"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf -- '-%.0s' {1..62})"
    echo
 
    echo -e "  ${AMBER}${BOLD}Step 8 -- Server receives and decapsulates${NC}"
    echo -e "  ${MUTED}  L1: bits arrive on NIC${NC}"
    echo -e "  ${MUTED}  L2: frame accepted (dst MAC matches server NIC)${NC}"
    echo -e "  ${MUTED}  L3: IP packet dst=93.184.216.34 matches -- strip IP header${NC}"
    echo -e "  ${MUTED}  L4: TCP dst port 443 -> hand to HTTPS listener process${NC}"
    echo -e "  ${MUTED}  L4: TCP reassembles any out-of-order segments${NC}"
    echo -e "  ${MUTED}  L6: TLS decrypts the payload${NC}"
    echo -e "  ${MUTED}  L7: HTTP server parses GET /index.html -> builds 200 OK response${NC}"
    echo
 
    #  SECTION 5 -- LIVE SYSTEM (unchanged)
    section "Examining the TCP/IP Stack"
 
    echo -e "\n  ${BLUE}[Application Layer]${NC}"
    echo -e "  ${INFO}DNS servers configured:${NC}"
    grep nameserver /etc/resolv.conf 2>/dev/null | sed 's/^/  /' \
        || echo -e "  ${MUTED}(not available)${NC}"
 
    echo -e "\n  ${BLUE}[Transport Layer]${NC}"
    echo -e "  ${INFO}TCP statistics:${NC}"
    grep "^Tcp:" /proc/net/snmp 2>/dev/null | paste - - \
        | awk '{for(i=2;i<=NF/2+1;i++) printf "  %-30s %s\n", $i":", $(i+NF/2-1)}' \
        | head -8
 
    echo -e "\n  ${BLUE}[Internet Layer]${NC}"
    echo -e "  ${INFO}IP addresses on this system:${NC}"
    ip addr show 2>/dev/null | grep "inet " | sed 's/^/  /' \
        || ifconfig 2>/dev/null | grep "inet " | sed 's/^/  /'
 
    echo -e "\n  ${BLUE}[Network Access Layer]${NC}"
    echo -e "  ${INFO}ARP cache (IP->MAC mappings):${NC}"
    ip neigh show 2>/dev/null | sed 's/^/  /' \
        || arp -n 2>/dev/null | sed 's/^/  /'
 
    pause
}
 
#  BANDWIDTH vs LATENCY vs THROUGHPUT
check_bandwidth_concepts() {
    header "Bandwidth vs Latency vs Throughput"
 
    #  1. CONCEPT REFERENCE 
    section "Core Concepts"
    cat << 'INFO'
  These three terms are often used interchangeably but measure fundamentally
  different things. Confusing them leads to misdiagnosed performance problems.
 
  Bandwidth — the pipe width
    The maximum theoretical data capacity of a link.
    Unit: bits per second (Mbps, Gbps).
    Analogy: number of lanes on a highway.
    Determined by: physical medium, hardware NIC/AP, ISP subscription tier.
    Measurement: ethtool (wired), iw (wireless), speedtest-cli (end-to-end).
    Key fact: bandwidth is a ceiling — actual transfer rarely reaches it.
 
  Latency — the travel time
    Time for a single packet to travel from source to destination (one-way),
    or source → destination → source (round-trip, RTT).
    Unit: milliseconds (ms).
    Analogy: the time a car takes to drive from A to B, regardless of traffic.
    Sources: propagation delay (speed of light), serialisation delay,
             queuing delay, processing delay at each hop.
    Key fact: high bandwidth does NOT reduce latency. A satellite link may
              have 1 Gbps bandwidth but 600 ms RTT.
 
  Throughput — what actually arrived
    The actual data successfully transferred per unit time, measured end-to-end.
    Unit: bits per second (Mbps, Gbps) — same as bandwidth but always ≤ bandwidth.
    Analogy: the number of cars that actually completed the journey per hour.
    Factors: packet loss (triggers TCP retransmit, halves cwnd), RTT (limits
             TCP window), CPU/NIC overhead, protocol overhead (headers, ACKs).
    Measurement: iperf3 (controlled), speedtest-cli (real-world ISP).
 
  Jitter — latency variance
    The variation in RTT between successive packets.
    Unit: milliseconds (ms). Ideal: < 5 ms for VoIP/video.
    High jitter causes choppy audio, video stuttering, and VoIP degradation
    even when average latency is acceptable.
 
  Bandwidth–Delay Product (BDP)
    BDP = Bandwidth × RTT  (bytes in flight needed to saturate a link)
    Example: 1 Gbps × 100 ms RTT = 12.5 MB of in-flight data needed.
    TCP window size must equal BDP to fully utilise a high-BDP path.
    Relevant for: long-fat networks (LFN), satellite, WAN optimisation.
 
  Relationship summary:
    Throughput ≤ Bandwidth  (always — overhead and loss reduce it)
    Throughput ↓  when Latency ↑  (TCP slow-start, window limits)
    Throughput ↓  when Packet Loss ↑  (TCP congestion control)
    Jitter is independent of average latency — measure separately
INFO
 
    #  2. INTERFACE LINK SPEED (BANDWIDTH CEILING) 
    section "Interface Link Speed (Bandwidth Ceiling)"
 
    echo -e "  ${LABEL}Wired interfaces (ethtool):${NC}"
    echo
 
    local found_any=0
    while IFS= read -r iface; do
        [[ "$iface" == "lo" ]] && continue
 
        # ethtool for wired; iw for wireless
        if [[ -d "/sys/class/net/${iface}/wireless" ]]; then
            # Wireless: get bitrate from iw
            if command -v iw &>/dev/null; then
                local bitrate channel freq
                bitrate=$(iw dev "$iface" link 2>/dev/null \
                    | grep -oP 'tx bitrate: \K[^\n]+' | head -1)
                channel=$(iw dev "$iface" info 2>/dev/null \
                    | grep -oP 'channel \K[0-9]+')
                freq=$(iw dev "$iface" info 2>/dev/null \
                    | grep -oP '\(\K[0-9.]+ MHz')
 
                if [[ -n "$bitrate" ]]; then
                    (( found_any++ ))
                    printf "  ${LABEL}%-14s${NC}  ${GOLD}%-20s${NC}  ${MUTED}ch:%-4s %s${NC}\n" \
                        "${iface} (wifi)" "$bitrate" "$channel" "$freq"
                fi
            fi
            continue
        fi
 
        if ! command -v ethtool &>/dev/null; then
            continue
        fi
 
        local speed duplex link_state
        speed=$(ethtool "$iface" 2>/dev/null | grep -i '^\s*speed:' | awk '{print $2}')
        duplex=$(ethtool "$iface" 2>/dev/null | grep -i '^\s*duplex:' | awk '{print $2}')
        link_state=$(ethtool "$iface" 2>/dev/null \
            | grep -i '^\s*link detected:' | awk '{print $3}')
 
        [[ -z "$speed" ]] && continue
        (( found_any++ ))
 
        local link_col speed_col
        [[ "$link_state" == "yes" ]] && link_col="$SUCCESS" || link_col="$MUTED"
 
        # Colour by speed tier
        case "$speed" in
            10000Mb/s|25000Mb/s|40000Mb/s|100000Mb/s) speed_col="$SUCCESS" ;;
            1000Mb/s)  speed_col="$SUCCESS" ;;
            100Mb/s)   speed_col="$WARNING" ;;
            10Mb/s)    speed_col="$FAILURE" ;;
            *)         speed_col="$MUTED"   ;;
        esac
 
        printf "  ${LABEL}%-14s${NC}  ${speed_col}%-14s${NC}  duplex: ${MUTED}%-8s${NC}  link: ${link_col}%s${NC}\n" \
            "$iface" "$speed" "${duplex:---}" "${link_state:---}"
 
    done < <(ls /sys/class/net/ 2>/dev/null)
 
    if [[ $found_any -eq 0 ]]; then
        echo -e "  ${MUTED}  No link speed data available${NC}"
        echo -e "  ${MUTED}  (virtual/container interfaces, or ethtool/iw not installed)${NC}"
    fi
 
    #  3. LATENCY MEASUREMENT 
    section "Latency Measurement"
 
    # Targets: local gateway, public DNS, a remote host
    local gateway
    gateway=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1)
 
    declare -A ping_targets=(
        ["Local gateway"]="${gateway:-skip}"
        ["Google DNS (8.8.8.8)"]="8.8.8.8"
        ["Cloudflare DNS (1.1.1.1)"]="1.1.1.1"
        ["Google (google.com)"]="google.com"
    )
 
    local target_order=(
        "Local gateway"
        "Google DNS (8.8.8.8)"
        "Cloudflare DNS (1.1.1.1)"
        "Google (google.com)"
    )
 
    printf "  ${BOLD}${TITLE}%-28s %-10s %-10s %-10s %-10s %s${NC}\n" \
        "Target" "Min ms" "Avg ms" "Max ms" "Loss %" "Jitter"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '%*s' 80 '' | tr ' ' '-')"
 
    for label in "${target_order[@]}"; do
        local host="${ping_targets[$label]}"
        [[ "$host" == "skip" || -z "$host" ]] && continue
 
        local ping_out
        ping_out=$(ping -c 5 -W 2 "$host" 2>/dev/null)
 
        if [[ -z "$ping_out" ]]; then
            printf "  ${LABEL}%-28s${NC}  ${FAILURE}unreachable${NC}\n" "$label"
            continue
        fi
 
        # Parse rtt min/avg/max/mdev line
        local min avg max mdev loss
        min=$(echo  "$ping_out" | grep -oP 'rtt min.*= \K[0-9.]+')
        avg=$(echo  "$ping_out" | grep -oP 'rtt min.*= [0-9.]+/\K[0-9.]+')
        max=$(echo  "$ping_out" | grep -oP 'rtt min.*= [0-9.]+/[0-9.]+/\K[0-9.]+')
        mdev=$(echo "$ping_out" | grep -oP 'rtt min.*= [0-9.]+/[0-9.]+/[0-9.]+/\K[0-9.]+')
        loss=$(echo "$ping_out" | grep -oP '[0-9.]+(?=% packet loss)')
 
        # Colour by average latency
        local lat_col
        if   (( $(echo "$avg < 20"  | bc -l 2>/dev/null) )); then lat_col="$SUCCESS"
        elif (( $(echo "$avg < 80"  | bc -l 2>/dev/null) )); then lat_col="$WARNING"
        else                                                        lat_col="$FAILURE"
        fi 2>/dev/null
        [[ -z "$avg" ]] && lat_col="$MUTED"
 
        # Colour by loss
        local loss_col
        [[ "${loss:-0}" == "0" ]] && loss_col="$SUCCESS" || loss_col="$FAILURE"
 
        printf "  ${LABEL}%-28s${NC}  ${MUTED}%-10s${NC} ${lat_col}%-10s${NC} ${MUTED}%-10s${NC} ${loss_col}%-10s${NC} ${MUTED}%s ms${NC}\n" \
            "$label" \
            "${min:---}" "${avg:---}" "${max:---}" \
            "${loss:-?}%" "${mdev:---}"
    done
 
    echo
    echo -e "  ${MUTED}  Interpretation:${NC}"
    echo -e "  ${SUCCESS}  < 20 ms${NC}   ${MUTED}excellent (local/regional)${NC}"
    echo -e "  ${WARNING}  20–80 ms${NC}  ${MUTED}acceptable (cross-country)${NC}"
    echo -e "  ${FAILURE}  > 80 ms${NC}   ${MUTED}high (satellite/congestion) — investigate${NC}"
    echo -e "  ${MUTED}  Jitter (mdev) > 5 ms may cause VoIP/video degradation${NC}"
 
    #  4. THROUGHPUT SNAPSHOT 
    section "Throughput Snapshot — Interface Byte Counters"
 
    echo -e "  ${MUTED}  These are cumulative counters since last interface reset, not current rate.${NC}"
    echo -e "  ${MUTED}  For current rate: watch -n1 cat /proc/net/dev  or  vnstat -l${NC}"
    echo
 
    printf "  ${BOLD}${TITLE}%-14s %16s %16s %10s %10s${NC}\n" \
        "Interface" "RX bytes" "TX bytes" "RX pkts" "TX pkts"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '%*s' 72 '' | tr ' ' '-')"
 
    # /proc/net/dev is universally available — no tool dependency
    while IFS= read -r line; do
        # Format: iface: rx_bytes rx_pkts rx_errs ... tx_bytes tx_pkts ...
        [[ "$line" =~ ^[[:space:]]*([^:]+):[[:space:]]*([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+([0-9]+)[[:space:]]+([0-9]+) ]] || continue
 
        local iface="${BASH_REMATCH[1]}"
        local rx_bytes="${BASH_REMATCH[2]}"
        local rx_pkts="${BASH_REMATCH[3]}"
        local tx_bytes="${BASH_REMATCH[4]}"
        local tx_pkts="${BASH_REMATCH[5]}"
 
        [[ "$iface" == "lo" ]] && continue
        [[ "$rx_bytes" == "0" && "$tx_bytes" == "0" ]] && continue
 
        # Human-readable byte conversion
        _human_bytes() {
            local b=$1
            if   (( b >= 1073741824 )); then printf "%.2f GB" "$(echo "scale=2; $b/1073741824" | bc -l 2>/dev/null)"
            elif (( b >= 1048576 ));    then printf "%.2f MB" "$(echo "scale=2; $b/1048576"    | bc -l 2>/dev/null)"
            elif (( b >= 1024 ));       then printf "%.2f KB" "$(echo "scale=2; $b/1024"       | bc -l 2>/dev/null)"
            else printf "%d B" "$b"
            fi
        }
 
        printf "  ${LABEL}%-14s${NC} ${VALUE}%16s${NC} ${VALUE}%16s${NC} ${MUTED}%10s${NC} ${MUTED}%10s${NC}\n" \
            "$iface" \
            "$(_human_bytes "$rx_bytes")" "$(_human_bytes "$tx_bytes")" \
            "$rx_pkts" "$tx_pkts"
 
    done < /proc/net/dev
 
    echo
    echo -e "  ${AMBER}Throughput measurement tools:${NC}"
    for tool_entry in \
        "iperf3:iperf3 -c <server>:Controlled TCP/UDP throughput between two hosts" \
        "speedtest-cli:speedtest-cli:ISP download/upload speed to nearest server" \
        "nload:nload <iface>:Real-time RX/TX rate graph per interface" \
        "vnstat:vnstat -l:Live traffic rate + hourly/daily/monthly totals" \
        "nethogs:nethogs <iface>:Per-process bandwidth usage (like top for bandwidth)"
    do
        local tool cmd desc
        IFS=':' read -r tool cmd desc <<< "$tool_entry"
        local avail_col avail_label
        if command -v "$tool" &>/dev/null; then
            avail_col="$SUCCESS"; avail_label="installed"
        else
            avail_col="$MUTED";   avail_label="not found "
        fi
        printf "  ${avail_col}%-10s${NC}  ${MUTED}cmd: ${VALUE}%-30s${NC}  ${MUTED}%s${NC}\n" \
            "$avail_label" "$cmd" "$desc"
    done
 
    echo
    pause
}

#  PACKET SWITCHING vs CIRCUIT SWITCHING
check_switching_types() {
    header "Packet Switching vs Circuit Switching"
 
    #  1. CONCEPT REFERENCE 
    section "Core Concepts"
    cat << 'INFO'
  Two fundamental paradigms for carrying data across a network. Every network
  you use daily is built on one of these — or a hybrid.
 
  ┌┐
  │  Circuit Switching                                                       │
  └┘
  How it works:
    A dedicated end-to-end physical (or logical) path is established before
    any data is sent, and held exclusively for the duration of the session.
    Resources at every node along the path are reserved in advance.
 
  Phases:  1. Circuit establishment  2. Data transfer  3. Circuit teardown
 
  Examples:
    • PSTN — traditional telephone network (analogue and ISDN)
    • SONET/SDH — synchronous optical carrier (still used in telco backbones)
    • ATM (Asynchronous Transfer Mode) — fixed 53-byte cells, virtual circuits
 
  Advantages:
    ✔ Guaranteed, constant bandwidth for the session
    ✔ Predictable, bounded latency (no queuing delay mid-session)
    ✔ In-order delivery — no reassembly needed
    ✔ Simple at the data level — no headers per segment once established
 
  Disadvantages:
    ✘ Inefficient — reserved capacity is wasted during silence (phone calls
      are silent ~50% of the time)
    ✘ Rigid — adding capacity requires provisioning new circuits
    ✘ Poor utilisation for bursty data traffic (web browsing, file transfers)
    ✘ Single point of failure — circuit breaks = entire session drops
    ✘ Long setup latency for short communications
 
  ┌┐
  │  Packet Switching                                                        │
  └┘
  How it works:
    Data is divided into packets. Each packet carries a header with source,
    destination, and sequencing information. Packets traverse the network
    independently — potentially via different paths — and are reassembled
    at the destination.
 
  Two modes:
    Datagram (connectionless) — IP. No setup phase. Each packet routed
      independently. No delivery guarantee. Out-of-order arrival possible.
 
    Virtual Circuit (connection-oriented) — ATM, MPLS, Frame Relay.
      A logical path is pre-computed; packets follow it in order. Still
      packet-switched underneath but behaves more like circuit switching.
 
  Examples:
    • The Internet — IP (IPv4/IPv6), the dominant global example
    • MPLS — label-switched paths in ISP/enterprise WAN cores
    • Ethernet LANs — frames switched between hosts
    • WiFi — 802.11 frames over shared radio medium
 
  Advantages:
    ✔ High link utilisation — idle bandwidth is used by other flows
    ✔ Resilient — packets rerouted around failures automatically (IP)
    ✔ Scales efficiently to millions of simultaneous flows
    ✔ Cost-effective — shared infrastructure, no per-call provisioning
    ✔ Supports bursty traffic patterns naturally
 
  Disadvantages:
    ✘ Variable latency — queuing at congested routers adds delay (jitter)
    ✘ No delivery guarantee (UDP) — application must handle loss
    ✘ Out-of-order packets require reassembly (TCP handles this)
    ✘ Header overhead per packet (IPv4: 20 B min, IPv6: 40 B min)
    ✘ QoS requires explicit configuration (DSCP, traffic shaping)
 
  ┌┐
  │  Side-by-Side Comparison                                                 │
  └┘
  Property           Circuit Switching      Packet Switching (IP)
      
  Path               Dedicated, fixed       Dynamic per-packet (or MPLS LSP)
  Setup phase        Required               No (connectionless) / SYN (TCP)
  Bandwidth          Reserved (guaranteed)  Shared (best-effort)
  Latency            Constant (bounded)     Variable (jitter possible)
  Loss handling      N/A (CBR circuit)      TCP retransmit / UDP drop
  Efficiency         Low (idle waste)       High (statistical multiplex)
  Resilience         Low (path failure)     High (rerouting)
  Use case           Voice, real-time CBR   Data, web, video, most traffic
  Modern examples    PSTN, SONET, ATM       Internet, Ethernet, WiFi, MPLS
INFO
 
    #  2. IP FORWARDING STATE 
    section "IP Forwarding State"
 
    echo -e "  ${MUTED}  IP forwarding determines whether this host routes packets between interfaces.${NC}"
    echo -e "  ${MUTED}  Routers/gateways: ON.  Normal workstations: OFF.${NC}"
    echo
 
    local ipv4_fwd ipv6_fwd
    ipv4_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    ipv6_fwd=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)
 
    if [[ "$ipv4_fwd" == "1" ]]; then
        status_line ok    "IPv4 forwarding: ENABLED  — this host forwards/routes IPv4 packets"
    else
        status_line neutral "IPv4 forwarding: DISABLED — normal endpoint / workstation mode"
    fi
 
    if [[ "$ipv6_fwd" == "1" ]]; then
        status_line ok    "IPv6 forwarding: ENABLED  — this host forwards/routes IPv6 packets"
    else
        status_line neutral "IPv6 forwarding: DISABLED — normal endpoint / workstation mode"
    fi
 
    echo
    kv "  /proc/sys/net/ipv4/ip_forward" "${ipv4_fwd:-unavailable}"
    kv "  /proc/sys/net/ipv6/conf/all/forwarding" "${ipv6_fwd:-unavailable}"
 
    # Routing table summary
    echo
    echo -e "  ${LABEL}Routing table (packet forwarding decisions):${NC}"
    ip route show 2>/dev/null | head -12 | while IFS= read -r route_line; do
        # Colour default route distinctly
        if [[ "$route_line" == default* ]]; then
            printf "  ${SUCCESS}%-70s${NC}\n" "$route_line"
        else
            printf "  ${VALUE}%-70s${NC}\n" "$route_line"
        fi
    done
 
    #  3. TRACEROUTE — PACKET SWITCHING HOPS 
    section "Traceroute — Packet Path Through the Network"
 
    echo -e "  ${MUTED}  Each hop is a packet-switching router making an independent forwarding decision.${NC}"
    echo -e "  ${MUTED}  * = no ICMP TTL-exceeded reply (firewall / rate limiting)${NC}"
    echo
 
    local trace_target="8.8.8.8"
    local trace_label="Google DNS (8.8.8.8)"
 
    if command -v traceroute &>/dev/null; then
        echo -e "  ${LABEL}traceroute to ${trace_label}:${NC}"
        traceroute -n -m 10 -w 2 "$trace_target" 2>/dev/null \
            | head -12 \
            | while IFS= read -r hop_line; do
                # Colour the header line differently
                if [[ "$hop_line" == traceroute* ]]; then
                    printf "  ${MUTED}%s${NC}\n" "$hop_line"
                elif [[ "$hop_line" =~ ^[[:space:]]*[0-9]+ ]]; then
                    local hop_num
                    hop_num=$(echo "$hop_line" | awk '{print $1}')
                    # Colour unreachable hops (all *) differently
                    if [[ "$hop_line" =~ \*[[:space:]]+\*[[:space:]]+\* ]]; then
                        printf "  ${MUTED}%s${NC}\n" "$hop_line"
                    else
                        printf "  ${ACCENT}[%2s]${NC}  ${VALUE}%s${NC}\n" \
                            "$hop_num" "${hop_line#*$hop_num}"
                    fi
                else
                    printf "  %s\n" "$hop_line"
                fi
            done
    elif command -v tracepath &>/dev/null; then
        echo -e "  ${LABEL}tracepath to ${trace_label}:${NC}"
        tracepath -n "$trace_target" 2>/dev/null | head -12 | sed 's/^/  /'
    else
        echo -e "  ${MUTED}  traceroute and tracepath not available${NC}"
        echo -e "  ${MUTED}  Install: sudo apt install traceroute${NC}"
    fi
 
    #  4. ACTIVE CONNECTIONS 
    section "Active Packet-Switched Connections"
 
    echo -e "  ${MUTED}  Each row is an independent packet stream — no dedicated circuit.${NC}"
    echo
 
    printf "  ${BOLD}${TITLE}%-8s %-22s %-22s %-12s %s${NC}\n" \
        "Proto" "Local Address" "Remote Address" "State" "Process"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '%*s' 80 '' | tr ' ' '-')"
 
    if command -v ss &>/dev/null; then
        ss -tnp 2>/dev/null | tail -n +2 | head -15 \
            | while IFS= read -r ss_line; do
                local proto local_addr remote_addr state proc
                read -r state _ _ local_addr remote_addr proc <<< "$ss_line"
                proto="TCP"
 
                # State colour
                local state_col
                case "$state" in
                    ESTAB*)     state_col="$SUCCESS" ;;
                    TIME-WAIT)  state_col="$MUTED"   ;;
                    CLOSE-WAIT) state_col="$WARNING" ;;
                    LISTEN)     state_col="$INFO"     ;;
                    *)          state_col="$MUTED"    ;;
                esac
 
                # Clean up process field
                proc=$(echo "$proc" | grep -oP 'users:\(\("\K[^"]+' | head -1)
                proc="${proc:---}"
 
                printf "  ${MUTED}%-8s${NC} ${VALUE}%-22.22s${NC} ${VALUE}%-22.22s${NC} ${state_col}%-12s${NC} ${MUTED}%s${NC}\n" \
                    "$proto" "$local_addr" "$remote_addr" "$state" "$proc"
            done
    elif command -v netstat &>/dev/null; then
        netstat -tnp 2>/dev/null | tail -n +3 | head -15 \
            | awk '{printf "  TCP      %-22.22s %-22.22s %-12s %s\n", $4, $5, $6, $7}'
    else
        echo -e "  ${MUTED}  ss and netstat not available${NC}"
    fi
 
    # Connection count summary
    echo
    if command -v ss &>/dev/null; then
        local estab_count timewait_count listen_count
        estab_count=$(ss -tn 2>/dev/null | grep -c ESTAB || echo 0)
        timewait_count=$(ss -tn 2>/dev/null | grep -c TIME-WAIT || echo 0)
        listen_count=$(ss -tln 2>/dev/null | tail -n +2 | wc -l)
 
        printf "  ${LABEL}Established:${NC} ${SUCCESS}%-6s${NC}  " "$estab_count"
        printf "${LABEL}TIME-WAIT:${NC} ${MUTED}%-6s${NC}  " "$timewait_count"
        printf "${LABEL}Listening:${NC} ${INFO}%s${NC}\n" "$listen_count"
    fi
 
    echo
    pause
}
 
main() {
    check_osi_model
    check_tcpip_model
    check_bandwidth_concepts
    check_switching_types
}

main