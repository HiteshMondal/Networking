#!/bin/bash

# /network_lab/security/firewall_ids.sh
# Topic: Firewalls, IDS/IPS, WAF, fail2ban & Hardening
# Covers: Firewall types, iptables, nftables, UFW, Snort/Suricata/Zeek, WAF, fail2ban

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# FIREWALL TYPES
check_firewall_types() {
    header "Firewall Types — Architecture & Live Audit"
 
    #  1. ARCHITECTURE REFERENCE 
    section "Firewall Generations & Architecture"
    cat << 'INFO'
  ┌
  │  Generation 1 — Packet Filtering (Layer 3/4)                            │
  └
  OSI layers inspected:  3 (IP) and 4 (TCP/UDP/ICMP)
  State awareness:       Stateless — each packet evaluated in isolation
  Match criteria:        Source/destination IP, port, protocol, interface
  Performance:           Very fast; minimal memory (no state tables)
 
  Limitations:
    • Cannot distinguish return traffic from new connections
    • Spoofed packets pass if header fields match rules
    • No payload inspection — cannot block malicious HTTP inside allowed port 80
    • TCP fragmentation attacks can bypass naive rules
 
  Examples:  iptables (raw filter table), BSD ipf, classic ACLs on Cisco IOS
  Use today: Edge rate-limiting, coarse pre-filtering before stateful engine
 
  ┌
  │  Generation 2 — Stateful Inspection (Layer 3/4)                         │
  └
  OSI layers inspected:  3 and 4
  State awareness:       Full TCP/UDP/ICMP connection tracking
  Match criteria:        All Gen 1 + connection state (NEW, ESTABLISHED, RELATED)
 
  How it works:
    • Maintains a connection state table (conntrack)
    • ESTABLISHED / RELATED return traffic allowed automatically
    • Unsolicited inbound packets blocked without explicit ACCEPT rule
    • Tracks TCP flags (SYN, ACK, FIN, RST) to validate session lifecycle
 
  Limitations:
    • Still blind to application-layer content
    • State table is a resource — DoS possible via SYN flood (exhausts entries)
    • Encrypted traffic (TLS) is opaque — content unknown
 
  Examples:  iptables + conntrack, nftables, pfSense, OPNsense, Cisco ASA (basic)
  Use today: Standard perimeter and host-based firewall baseline
 
  ┌
  │  Generation 3 — Application Layer Gateway / Proxy (Layer 7)             │
  └
  OSI layers inspected:  3–7 (full stack)
  State awareness:       Full stateful + application protocol parsing
  Match criteria:        URLs, HTTP methods, DNS names, file types, commands,
                         FTP verbs, SMTP sender/recipient, protocol anomalies
 
  How it works:
    • Acts as a proxy — terminates and re-originates connections
    • Fully parses application protocols; understands semantic content
    • Deep Packet Inspection (DPI): reconstructs streams, inspects payloads
    • Can modify or block individual commands within an allowed session
 
  Limitations:
    • High CPU/memory overhead (full proxy processing per connection)
    • TLS inspection requires MITM certificate → privacy implications
    • Application protocol support must be explicitly implemented
    • Proxy latency added to every transaction
 
  Examples:  Squid (HTTP proxy), mod_security (WAF), Snort/Suricata (IDS/IPS),
             DNS RPZ, FTP ALG in stateful firewalls
  Use today: Web filtering, WAF in front of web apps, DPI at enterprise perimeter
 
  ┌
  │  Next-Generation Firewall (NGFW)                                         │
  └
  An NGFW integrates all previous generations plus:
    • Application identification (App-ID): recognise apps regardless of port
      e.g. detect Slack/Zoom/BitTorrent even over port 443
    • User identity integration (User-ID): link traffic to AD/LDAP usernames
    • Integrated IPS: signature + anomaly-based inline threat prevention
    • TLS/SSL inspection: decrypt → inspect → re-encrypt (breaks end-to-end)
    • URL/web filtering: category-based blocking with cloud lookup
    • Sandboxing / threat intelligence feeds (WildFire, FortiSandbox)
    • Centralised policy management with logging to SIEM
 
  Limitations:
    • Expensive (hardware + licensing)
    • TLS inspection introduces latency and certificate trust issues
    • Complexity → misconfiguration risk
    • Not all NGFWs inspect all protocols equally well
 
  Examples:  Palo Alto PA-series, Fortinet FortiGate, Check Point NGFW,
             Cisco Firepower, pfSense + Snort/Suricata, OPNsense + Zenarmor
 
  ┌
  │  Deployment Positions                                                    │
  └
  Perimeter (north-south)
    Between the internet and the internal network / DMZ.
    Filters ingress and egress; enforces NAT; blocks unsolicited inbound.
    First and last line of network defence.
 
  Internal segmentation (east-west)
    Between internal network zones (servers ↔ workstations, VLAN-to-VLAN).
    Limits lateral movement — attacker who breaches one segment is contained.
    Zero Trust architecture depends on east-west enforcement.
 
  DMZ (De-Militarised Zone)
    A screened subnet between two firewalls.
    Internet-facing servers (web, mail, DNS) placed here.
    Compromise of DMZ host does not give direct access to internal LAN.
 
  Host-based
    Runs on each individual server or workstation.
    iptables/nftables/ufw (Linux), Windows Defender Firewall, macOS pf.
    Last line of defence if network-level firewalls are bypassed.
    Essential for Zero Trust and microsegmentation.
 
  Cloud / virtual
    AWS Security Groups (stateful, per-ENI)
    Azure Network Security Groups (NSG) + Azure Firewall
    GCP VPC Firewall Rules + Cloud Armor (WAF)
    These are attached to resources, not physical appliances.
 
  ┌
  │  Quick Comparison                                                        │
  └
  Type              Layer  State  App-aware  IPS  TLS-inspect  Overhead
              
  Packet filter     3–4    No     No         No   No           Minimal
  Stateful          3–4    Yes    No         No   No           Low
  App gateway/WAF   3–7    Yes    Yes        No   Partial      Medium
  NGFW              3–7    Yes    Yes        Yes  Yes          High
INFO
 
    #  2. INSTALLED FIREWALL SOFTWARE 
    section "Installed Firewall Software"
    echo
 
    # tool | display_name | version_flag | description
    local fw_tools=(
        "iptables|iptables|--version|Packet/stateful filter (IPv4) — classic Linux firewall"
        "ip6tables|ip6tables|--version|Packet/stateful filter (IPv6)"
        "nftables|nft|--version|Modern replacement for iptables/ip6tables/arptables/ebtables"
        "ufw|ufw|--version|Uncomplicated Firewall — iptables/nftables frontend"
        "firewalld|firewall-cmd|--version|Dynamic firewall daemon with zone model (RHEL/Fedora/CentOS)"
        "ipset|ipset|--version|Set-based matching for iptables/nftables (IP/MAC/port sets)"
        "nmap|nmap|--version|Port scanner — useful for validating firewall rules"
        "fail2ban|fail2ban-client|--version|Intrusion prevention — bans IPs via iptables/nftables"
        "hping3|hping3|--version|Packet crafting tool for firewall rule testing"
        "pf|pfctl|-x|BSD Packet Filter (macOS / FreeBSD)"
    )
 
    local found_count=0
    for entry in "${fw_tools[@]}"; do
        local key display ver_flag desc
        IFS='|' read -r key display ver_flag desc <<< "$entry"
 
        if command -v "$display" &>/dev/null; then
            (( found_count++ ))
            local ver
            ver=$("$display" "$ver_flag" 2>/dev/null | head -1 \
                  || echo "installed")
            # Trim long version strings
            ver=$(echo "$ver" | cut -c1-50)
            printf "  ${SUCCESS}✔${NC}  ${LABEL}%-14s${NC}  ${VALUE}%-20s${NC}  ${MUTED}%s${NC}\n" \
                "$display" "$ver" "$desc"
        fi
    done
 
    [[ $found_count -eq 0 ]] && \
        echo -e "  ${MUTED}  No recognised firewall tools found${NC}"
 
    #  3. ACTIVE SERVICE STATUS 
    section "Firewall Service Status"
    echo
 
    local services=("ufw" "firewalld" "iptables" "nftables" "fail2ban")
 
    for svc in "${services[@]}"; do
        # Skip if the binary isn't even installed
        local svc_bin
        case "$svc" in
            firewalld) svc_bin="firewall-cmd" ;;
            *)         svc_bin="$svc" ;;
        esac
        command -v "$svc_bin" &>/dev/null || continue
 
        local active enabled
        active=$(systemctl is-active  "$svc" 2>/dev/null || echo "unknown")
        enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")
 
        local active_col enabled_col
        [[ "$active"  == "active"  ]] && active_col="$SUCCESS"  || active_col="$MUTED"
        [[ "$enabled" == "enabled" ]] && enabled_col="$SUCCESS" || enabled_col="$MUTED"
 
        printf "  ${LABEL}%-14s${NC}  active: ${active_col}%-10s${NC}  enabled: ${enabled_col}%s${NC}\n" \
            "$svc" "$active" "$enabled"
    done
 
    #  4. UFW DETAILED STATUS 
    if command -v ufw &>/dev/null && systemctl is-active ufw &>/dev/null 2>&1; then
        section "UFW Rule Summary"
 
        local ufw_status
        ufw_status=$(ufw status verbose 2>/dev/null)
 
        # Overall policy
        local default_in default_out
        default_in=$(echo  "$ufw_status" | grep -oP 'Default:.*incoming \K\S+')
        default_out=$(echo "$ufw_status" | grep -oP 'outgoing \(\K\S+' \
                      || echo "$ufw_status" | grep -oP 'Default:.*outgoing \K\S+')
 
        echo
        local in_col out_col
        [[ "${default_in,,}"  == "deny"  ]] && in_col="$SUCCESS"  || in_col="$FAILURE"
        [[ "${default_out,,}" == "allow" ]] && out_col="$SUCCESS" || out_col="$MUTED"
 
        printf "  ${LABEL}Default policy:${NC}  inbound: ${in_col}%-8s${NC}  outbound: ${out_col}%s${NC}\n" \
            "${default_in:---}" "${default_out:---}"
 
        echo
        echo -e "  ${LABEL}Active rules:${NC}"
        echo "$ufw_status" | grep -E "ALLOW|DENY|REJECT|LIMIT" | head -20 \
            | while IFS= read -r rule_line; do
                local rule_col
                case "$rule_line" in
                    *DENY*|*REJECT*) rule_col="$FAILURE" ;;
                    *LIMIT*)         rule_col="$WARNING" ;;
                    *ALLOW*)         rule_col="$SUCCESS" ;;
                    *)               rule_col="$MUTED"   ;;
                esac
                printf "  ${rule_col}%s${NC}\n" "$rule_line"
            done
 
        local rule_count
        rule_count=$(ufw status numbered 2>/dev/null | grep -c '^\[')
        [[ -n "$rule_count" ]] && \
            echo -e "\n  ${MUTED}  Total rules: ${GOLD}${rule_count}${NC}"
    fi
 
    #  5. FIREWALLD ZONE SUMMARY 
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null 2>&1; then
        section "firewalld Zone Summary"
        echo
 
        local active_zones
        active_zones=$(firewall-cmd --get-active-zones 2>/dev/null)
 
        if [[ -n "$active_zones" ]]; then
            echo -e "  ${LABEL}Active zones:${NC}"
            echo "$active_zones" | sed 's/^/    /'
        fi
 
        echo
        local default_zone
        default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
        kv "  Default zone" "${default_zone:---}"
 
        echo
        echo -e "  ${LABEL}Services allowed in default zone (${default_zone}):${NC}"
        firewall-cmd --zone="${default_zone}" --list-services 2>/dev/null \
            | tr ' ' '\n' | while IFS= read -r svc_name; do
                [[ -z "$svc_name" ]] && continue
                printf "  ${SUCCESS}  %-20s${NC}\n" "$svc_name"
              done
 
        echo
        echo -e "  ${LABEL}Open ports in default zone:${NC}"
        local open_ports
        open_ports=$(firewall-cmd --zone="${default_zone}" --list-ports 2>/dev/null)
        if [[ -n "$open_ports" ]]; then
            echo "$open_ports" | tr ' ' '\n' | while IFS= read -r port_entry; do
                [[ -z "$port_entry" ]] && continue
                printf "  ${WARNING}  %-20s${NC}\n" "$port_entry"
            done
        else
            echo -e "  ${MUTED}    None explicitly listed${NC}"
        fi
    fi
 
    #  6. NFTABLES RULESET SUMMARY 
    if command -v nft &>/dev/null && systemctl is-active nftables &>/dev/null 2>&1; then
        section "nftables Ruleset Summary"
        echo
 
        local nft_tables
        nft_tables=$(nft list tables 2>/dev/null)
 
        if [[ -z "$nft_tables" ]]; then
            echo -e "  ${MUTED}  No nftables tables defined (empty ruleset)${NC}"
        else
            echo -e "  ${LABEL}Defined tables:${NC}"
            echo "$nft_tables" | while IFS= read -r table_line; do
                printf "  ${VALUE}  %s${NC}\n" "$table_line"
            done
 
            local chain_count rule_count
            chain_count=$(nft list ruleset 2>/dev/null | grep -c '^[[:space:]]*chain ')
            rule_count=$(nft list ruleset 2>/dev/null \
                | grep -c '^[[:space:]]\+[^{}]' || echo 0)
 
            echo
            printf "  ${LABEL}Chains:${NC} ${GOLD}%s${NC}   ${LABEL}Rules:${NC} ${GOLD}%s${NC}\n" \
                "${chain_count:-0}" "${rule_count:-0}"
 
            echo
            echo -e "  ${MUTED}  Full ruleset: sudo nft list ruleset${NC}"
        fi
    fi
 
    #  7. RAW IPTABLES SNAPSHOT 
    if command -v iptables &>/dev/null; then
        # Only show if ufw/firewalld are not managing iptables
        if ! systemctl is-active ufw      &>/dev/null 2>&1 && \
           ! systemctl is-active firewalld &>/dev/null 2>&1; then
            section "iptables Rule Snapshot (filter table)"
            echo
 
            local ipt_out
            ipt_out=$(iptables -L -n --line-numbers 2>/dev/null)
 
            if [[ -z "$ipt_out" ]]; then
                echo -e "  ${MUTED}  No iptables rules (requires root for full output)${NC}"
            else
                # Chain policy summary
                echo "$ipt_out" | grep '^Chain' | while IFS= read -r chain_line; do
                    local chain_name policy
                    chain_name=$(echo "$chain_line" | awk '{print $2}')
                    policy=$(echo "$chain_line" | grep -oP 'policy \K\S+')
 
                    local pol_col
                    [[ "${policy,,}" == "drop"  ]] && pol_col="$SUCCESS"
                    [[ "${policy,,}" == "accept" ]] && pol_col="$WARNING"
                    [[ -z "$pol_col" ]] && pol_col="$MUTED"
 
                    printf "  ${LABEL}Chain %-12s${NC}  default policy: ${pol_col}%s${NC}\n" \
                        "$chain_name" "${policy:---}"
                done
 
                echo
                local rule_total
                rule_total=$(echo "$ipt_out" | grep -cE '^[0-9]')
                echo -e "  ${LABEL}Total rules (filter table):${NC} ${GOLD}${rule_total}${NC}"
                echo -e "  ${MUTED}  Full view: sudo iptables -L -nv --line-numbers${NC}"
 
                # Check for default-ACCEPT on INPUT — common misconfiguration
                local input_policy
                input_policy=$(echo "$ipt_out" | grep '^Chain INPUT' \
                    | grep -oP 'policy \K\S+')
                if [[ "${input_policy,,}" == "accept" ]]; then
                    echo
                    echo -e "  ${FAILURE}[!] INPUT chain default policy is ACCEPT — explicitly allow and deny rules${NC}"
                    echo -e "  ${MUTED}     Best practice: set policy to DROP, then whitelist needed services${NC}"
                fi
            fi
 
            # IPv6 summary
            if command -v ip6tables &>/dev/null; then
                local ipt6_rules
                ipt6_rules=$(ip6tables -L -n 2>/dev/null | grep -cE '^[0-9]' || echo 0)
                local input6_policy
                input6_policy=$(ip6tables -L INPUT -n 2>/dev/null \
                    | grep '^Chain INPUT' | grep -oP 'policy \K\S+')
 
                echo
                printf "  ${LABEL}ip6tables rules:${NC} ${GOLD}%s${NC}   ${LABEL}INPUT policy:${NC} " \
                    "$ipt6_rules"
                if [[ "${input6_policy,,}" == "accept" ]]; then
                    echo -e "${FAILURE}${input6_policy} [!] IPv6 INPUT is ACCEPT — review rules${NC}"
                else
                    echo -e "${SUCCESS}${input6_policy:-unknown}${NC}"
                fi
            fi
        fi
    fi
 
    #  8. OPEN LISTENING PORTS 
    section "Open Listening Ports (Firewall Exposure)"
    echo
    echo -e "  ${MUTED}  Ports here are exposed to the network. Verify each is intentional.${NC}"
    echo
 
    printf "  ${BOLD}${TITLE}%-8s %-8s %-22s %-8s %s${NC}\n" \
        "Proto" "Port" "Address" "State" "Process"
    printf "  ${DARK_GRAY}%s${NC}\n" "$(printf '%*s' 70 '' | tr ' ' '-')"
 
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | tail -n +2 | \
        while IFS= read -r ss_line; do
            local state local_addr proc
            read -r state _ _ local_addr _ proc <<< "$ss_line"
            [[ -z "$local_addr" ]] && continue
 
            local port addr
            # Handle IPv6 addresses like [::]:22
            if [[ "$local_addr" =~ ^\[.*\]:([0-9]+)$ ]]; then
                port="${BASH_REMATCH[1]}"
                addr=$(echo "$local_addr" | grep -oP '^\[\K[^\]]+')
            else
                port="${local_addr##*:}"
                addr="${local_addr%:*}"
            fi
 
            # Flag well-known dangerous open ports
            local port_note=""
            case "$port" in
                21)   port_note="${FAILURE} [FTP — plaintext]${NC}" ;;
                23)   port_note="${FAILURE} [Telnet — plaintext]${NC}" ;;
                25)   port_note="${WARNING} [SMTP — verify relay config]${NC}" ;;
                80)   port_note="${MUTED} [HTTP]${NC}" ;;
                443)  port_note="${SUCCESS} [HTTPS]${NC}" ;;
                22)   port_note="${WARNING} [SSH — ensure key-auth only]${NC}" ;;
                3306) port_note="${FAILURE} [MySQL — should not be externally exposed]${NC}" ;;
                5432) port_note="${FAILURE} [PostgreSQL — should not be externally exposed]${NC}" ;;
                6379) port_note="${FAILURE} [Redis — unauthenticated by default]${NC}" ;;
                27017) port_note="${FAILURE} [MongoDB — verify auth is enabled]${NC}" ;;
                2375|2376) port_note="${FAILURE} [Docker daemon — critical if externally exposed]${NC}" ;;
            esac
 
            local proc_name
            proc_name=$(echo "$proc" | grep -oP 'users:\(\("\K[^"]+' | head -1)
            proc_name="${proc_name:---}"
 
            printf "  ${MUTED}%-8s${NC} ${GOLD}%-8s${NC} ${VALUE}%-22.22s${NC} ${SUCCESS}%-8s${NC} ${MUTED}%s${NC}" \
                "TCP" "$port" "$addr" "LISTEN" "$proc_name"
            echo -e "$port_note"
 
        done
 
        # UDP listeners
        ss -ulnp 2>/dev/null | tail -n +2 | head -10 | \
        while IFS= read -r ss_line; do
            local state local_addr proc
            read -r state _ _ local_addr _ proc <<< "$ss_line"
            [[ -z "$local_addr" ]] && continue
            local port="${local_addr##*:}"
            local proc_name
            proc_name=$(echo "$proc" | grep -oP 'users:\(\("\K[^"]+' | head -1)
            proc_name="${proc_name:---}"
            printf "  ${MUTED}%-8s${NC} ${GOLD}%-8s${NC} ${VALUE}%-22.22s${NC} ${MUTED}%-8s${NC} %s\n" \
                "UDP" "$port" "${local_addr%:*}" "UNBOUND" "$proc_name"
        done
 
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | tail -n +3 | head -20 | sed 's/^/  /'
    else
        echo -e "  ${MUTED}  ss and netstat not available — install iproute2${NC}"
    fi
 
    echo
    echo -e "  ${MUTED}  Review: any port not intentionally exposed should be firewalled or service stopped${NC}"
    echo
}

# IPTABLES
check_iptables() {
    header "iptables — Netfilter Firewall (IPv4)"

    section "iptables Concepts"
    cat << 'INFO'
  Tables (by priority):
    raw    — connection tracking bypass (PREROUTING, OUTPUT)
    mangle — packet modification (all chains)
    nat    — address/port translation (PREROUTING, INPUT, OUTPUT, POSTROUTING)
    filter — packet filtering (INPUT, FORWARD, OUTPUT) — DEFAULT table

  Built-in Chains:
    INPUT      — packets destined for this host
    OUTPUT     — packets originating from this host
    FORWARD    — packets routed through this host
    PREROUTING — before routing decision (nat/mangle)
    POSTROUTING— after routing decision (nat/mangle)

  Targets (what to do with a packet):
    ACCEPT     — allow the packet
    DROP       — silently discard (no response to sender)
    REJECT     — discard + send ICMP/RST error to sender
    LOG        — log to syslog and continue
    RETURN     — return to calling chain
    REDIRECT   — redirect to a local port (NAT table)
    MASQUERADE — dynamic SNAT for outbound traffic (NAT table)
    DNAT       — change destination address (PREROUTING)
    SNAT       — change source address (POSTROUTING)

  Packet flow (simplified):
    Network → PREROUTING → [routing decision] → INPUT (local) / FORWARD (route)
    Local process → OUTPUT → POSTROUTING → Network
INFO

    section "Live iptables Rules"
    echo -e "${INFO}Filter table — INPUT chain:${NC}"
    sudo iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -25 | sed 's/^/  /' \
        || echo -e "  ${MUTED}Cannot read (requires sudo or not installed)${NC}"

    echo
    echo -e "${INFO}Filter table — FORWARD chain:${NC}"
    sudo iptables -L FORWARD -n -v --line-numbers 2>/dev/null | head -15 | sed 's/^/  /'

    echo
    echo -e "${INFO}NAT table:${NC}"
    sudo iptables -t nat -L -n -v 2>/dev/null | head -15 | sed 's/^/  /'

    section "Recommended Hardened Baseline"
    cat << 'CMDS'
  # Flush and set secure defaults
  iptables -F && iptables -X && iptables -Z
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  # Allow loopback
  iptables -A INPUT -i lo -j ACCEPT

  # Allow established/related traffic (stateful)
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Drop invalid packets
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

  # Allow ICMP (ping) — rate-limited
  iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT

  # SSH — restrict to known source if possible
  iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

  # HTTP / HTTPS
  iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT

  # Log drops before final rule
  iptables -A INPUT -m limit --limit 5/m -j LOG --log-prefix "[iptables DROP] "

  # Persist (Debian/Ubuntu)
  apt install iptables-persistent
  netfilter-persistent save
CMDS

    section "iptables Statistics"
    echo -e "${INFO}Packet counts per chain:${NC}"
    sudo iptables -L -n -v 2>/dev/null | grep "Chain " | sed 's/^/  /'
}

# NFTABLES
check_nftables() {
    header "nftables — Modern Netfilter Replacement"

    section "nftables vs iptables"
    cat << 'INFO'
  nftables replaces iptables/ip6tables/arptables/ebtables with a single tool.
  Available since kernel 3.13 (2014). Default in Debian 10+, Fedora 18+.

  Key differences:
    ✓ Single tool for all protocols (IPv4, IPv6, ARP, bridge)
    ✓ Sets for efficient multi-value matching (no repeated rules)
    ✓ Better performance (rules compiled to bytecode)
    ✓ Maps for direct lookups (verdict map, NAT map)
    ✓ Atomic rule updates (no race conditions during reload)
    ✓ Cleaner syntax; easier to read rulesets

  Concepts:
    Tables    — top-level namespace (family: ip, ip6, inet, arp, bridge, netdev)
    Chains    — sequence of rules (type: filter/nat/route, hook, priority)
    Rules     — match + verdict
    Sets      — named collections of values (IP, port, MAC)
    Maps      — match → action lookup tables
INFO

    section "Live nftables Ruleset"
    if cmd_exists nft; then
        echo -e "${INFO}Current nftables ruleset:${NC}"
        sudo nft list ruleset 2>/dev/null | head -40 | sed 's/^/  /' \
            || echo -e "  ${MUTED}Cannot read (requires sudo)${NC}"

        echo
        echo -e "${INFO}Tables:${NC}"
        sudo nft list tables 2>/dev/null | sed 's/^/  /'
    else
        status_line neutral "nft not installed (apt install nftables)"
    fi

    section "nftables Hardened Baseline"
    cat << 'CONF'
  # /etc/nftables.conf — hardened baseline
  #!/usr/sbin/nft -f

  flush ruleset

  table inet filter {
      set allowed_tcp_dports {
          type inet_service
          elements = { 22, 80, 443 }
      }

      chain input {
          type filter hook input priority 0; policy drop;

          iif "lo" accept
          ct state invalid drop
          ct state { established, related } accept
          ip protocol icmp  limit rate 10/second accept
          ip6 nexthdr icmpv6 limit rate 10/second accept

          tcp dport @allowed_tcp_dports ct state new accept

          limit rate 5/minute log prefix "[nft DROP] "
      }

      chain forward {
          type filter hook forward priority 0; policy drop;
      }

      chain output {
          type filter hook output priority 0; policy accept;
      }
  }
CONF
}

# UFW
check_ufw() {
    header "UFW — Uncomplicated Firewall"

    section "UFW Overview"
    cat << 'INFO'
  UFW is an iptables/nftables frontend aimed at simplicity.
  Primarily for Ubuntu/Debian desktops and servers.
  GUI available: gufw

  Profiles: stored in /etc/ufw/applications.d/
  Default policies: defined in /etc/default/ufw
  Rules:  stored in /etc/ufw/user.rules (IPv4) and user6.rules (IPv6)
INFO

    if ! cmd_exists ufw; then
        status_line neutral "ufw not installed (apt install ufw)"
        return
    fi

    section "UFW Status"
    echo -e "${INFO}UFW status:${NC}"
    sudo ufw status verbose 2>/dev/null | sed 's/^/  /' \
        || echo -e "  ${MUTED}Cannot read (requires sudo)${NC}"

    section "UFW Command Reference"
    cat << 'CMDS'
  sudo ufw enable                        # Enable firewall
  sudo ufw disable                       # Disable (all traffic allowed)
  sudo ufw reset                         # Reset to defaults

  sudo ufw default deny incoming         # Block all inbound by default
  sudo ufw default allow outgoing        # Allow all outbound

  sudo ufw allow 22/tcp                  # Allow SSH
  sudo ufw allow 'Nginx Full'            # Allow HTTP + HTTPS (profile)
  sudo ufw allow from 10.0.0.0/8        # Allow entire subnet
  sudo ufw allow from 192.168.1.0/24 to any port 5432  # PostgreSQL from LAN

  sudo ufw deny 23/tcp                   # Block Telnet
  sudo ufw limit 22/tcp                  # Rate-limit SSH (brute-force protection)

  sudo ufw delete allow 22/tcp           # Remove a rule
  sudo ufw show added                    # Show pending rules

  sudo ufw logging on                    # Enable logging
  sudo ufw logging high                  # Verbose logging level
CMDS

    section "UFW Application Profiles"
    sudo ufw app list 2>/dev/null | sed 's/^/  /'
}

# IDS/IPS
check_ids_ips() {
    header "IDS / IPS — Intrusion Detection & Prevention"

    section "IDS vs IPS"
    cat << 'INFO'
  IDS (Intrusion Detection System):
    Monitors and ALERTS on suspicious activity.
    Passive — does not block traffic.
    Can be network-based (NIDS) or host-based (HIDS).
    False positives → alert fatigue; tune signatures carefully.

  IPS (Intrusion Prevention System):
    Monitors and BLOCKS suspicious activity inline.
    Active — sits in traffic path; can drop packets.
    Higher risk: false positive = blocked legitimate traffic.

  Deployment modes:
    Inline (IPS)   — traffic flows through the sensor
    Tap/span (IDS) — copy of traffic sent to sensor (passive)
    Host-based     — agent on each endpoint (auditd, OSSEC, Wazuh)

  Detection methods:
    Signature-based — match against known attack patterns (low FP, misses 0-day)
    Anomaly-based   — deviate from baseline (catches unknown, higher FP)
    Hybrid          — combines both
INFO

    section "Snort"
    if cmd_exists snort; then
        status_line ok "Snort is installed"
        echo -e "  ${MUTED}Version: $(snort -V 2>&1 | head -3 | tail -1)${NC}"
    else
        status_line neutral "Snort not installed (apt install snort)"
    fi

    section "Suricata"
    if cmd_exists suricata; then
        status_line ok "Suricata is installed"
        local ver
        ver=$(suricata --build-info 2>/dev/null | grep "^Version" | head -1)
        echo -e "  ${MUTED}${ver}${NC}"
        echo
        echo -e "${INFO}Suricata service status:${NC}"
        systemctl status suricata 2>/dev/null | head -6 | sed 's/^/  /'
    else
        status_line neutral "Suricata not installed (apt install suricata)"
    fi

    section "Zeek (formerly Bro)"
    if cmd_exists zeek || cmd_exists bro; then
        local z="${cmd:-zeek}"
        cmd_exists zeek && z=zeek || z=bro
        status_line ok "${z} is installed"
        $z --version 2>/dev/null | head -1 | sed 's/^/  /'
    else
        status_line neutral "Zeek not installed (apt install zeek)"
    fi

    section "OSSEC / Wazuh (HIDS)"
    for agent in wazuh-agent ossec; do
        if pgrep -x "$agent" &>/dev/null || systemctl is-active "$agent" &>/dev/null; then
            status_line ok "${agent} is running"
        fi
    done

    section "auditd — Kernel-level Auditing"
    if systemctl is-active auditd &>/dev/null; then
        status_line ok "auditd is active"
        echo
        echo -e "${INFO}Recent audit events (last 5):${NC}"
        sudo ausearch -m AVC,USER_AUTH,USER_LOGIN 2>/dev/null | tail -15 | sed 's/^/  /' \
            || sudo tail -5 /var/log/audit/audit.log 2>/dev/null | sed 's/^/  /'
        echo
        echo -e "${INFO}Audit rules loaded:${NC}"
        sudo auditctl -l 2>/dev/null | head -10 | sed 's/^/  /'
    else
        status_line neutral "auditd not running (apt install auditd audispd-plugins)"
    fi

    section "Suricata Rule Example"
    cat << 'RULES'
  # Alert on HTTP requests with 'cmd.exe' in URI
  alert http any any -> any any (
      msg:"Possible Windows command injection";
      http.uri; content:"cmd.exe"; nocase;
      classtype:web-application-attack;
      sid:1000001; rev:1;
  )

  # Alert on SSH brute-force (>5 attempts/60s)
  alert tcp any any -> $HOME_NET 22 (
      msg:"SSH brute-force attempt";
      flow:to_server;
      threshold: type threshold, track by_src, count 5, seconds 60;
      classtype:attempted-admin;
      sid:1000002; rev:1;
  )
RULES
}

# WAF
check_waf() {
    header "WAF — Web Application Firewall"

    section "WAF Overview"
    cat << 'INFO'
  A WAF protects web applications by inspecting HTTP/HTTPS traffic.
  Operates at Layer 7 — understands web protocol semantics.

  OWASP Top 10 attacks WAFs protect against:
    A01 Broken Access Control   — path traversal attempts
    A03 Injection               — SQLi, XSS, command injection
    A05 Security Misconfiguration— default files, debug endpoints
    A07 Auth & Session Failures — credential stuffing detection
    A10 SSRF                    — internal resource access blocking

  Deployment modes:
    Reverse proxy  — WAF sits in front (recommended; can decrypt TLS)
    Transparent    — layer 2 bridge (no IP change)
    Out-of-band    — traffic mirrored; alerts only (no blocking)
    Agent-based    — module in web server (mod_security/NGINX module)

  Popular WAFs:
    Open source: ModSecurity + OWASP CRS, Coraza, OpenResty+resty-waf
    Cloud:       Cloudflare WAF, AWS WAF, Google Cloud Armor, Akamai Kona
    Commercial:  F5 Advanced WAF, Imperva App Protect, Fortiweb
INFO

    section "ModSecurity Status"
    if cmd_exists modsec_sdbm_util 2>/dev/null || \
       apachectl -M 2>/dev/null | grep -q "security2" || \
       nginx -T 2>/dev/null | grep -q "modsecurity"; then
        status_line ok "ModSecurity is loaded"
    else
        status_line neutral "ModSecurity not detected"
    fi

    echo
    echo -e "${INFO}mod_security config:${NC}"
    for f in /etc/modsecurity/modsecurity.conf \
              /etc/apache2/mods-enabled/security2.conf; do
        [[ -f "$f" ]] && head -5 "$f" 2>/dev/null | sed 's/^/  /'
    done

    section "OWASP CRS Detection Rules (Concepts)"
    cat << 'INFO'
  OWASP Core Rule Set (CRS) — paranoia levels 1–4:

  Request Anomaly Score system:
    Each rule match adds to anomaly score.
    Total score exceeds threshold → block/log.
    Paranoia 1: common attacks (low FP), Paranoia 4: very strict (high FP).

  Sample rule categories:
    REQUEST-920: Protocol Enforcement
    REQUEST-930: Local File Inclusion (LFI)
    REQUEST-931: Remote File Inclusion (RFI)
    REQUEST-932: Remote Code Execution
    REQUEST-933: PHP injection
    REQUEST-941: Cross-Site Scripting (XSS)
    REQUEST-942: SQL Injection
    REQUEST-944: Java Application Attacks
INFO

    section "Common SQL Injection Patterns WAFs Block"
    cat << 'INFO'
  ' OR '1'='1                    -- Classic tautology bypass
  ' UNION SELECT NULL--           -- UNION-based extraction
  1; DROP TABLE users--           -- Stacked queries
  '; WAITFOR DELAY '0:0:5'--     -- Time-based blind
  admin'--                        -- Comment-out password check
  ' OR SLEEP(5)#                  -- MySQL time-based blind
INFO
}

# FAIL2BAN
check_fail2ban() {
    header "fail2ban — Brute-Force Protection"

    section "How fail2ban Works"
    cat << 'INFO'
  fail2ban monitors log files for patterns (failed auth attempts).
  On threshold breach: runs an action (usually iptables/nftables ban).
  After bantime expires: unbans automatically (or permanent with bantime=-1).

  Architecture:
    fail2ban-server   — daemon; reads config, watches logs via pyinotify
    fail2ban-client   — CLI to query/control the server

  Config hierarchy (each overrides the previous):
    /etc/fail2ban/fail2ban.conf    — base config
    /etc/fail2ban/jail.conf        — default jail definitions
    /etc/fail2ban/jail.local       — YOUR overrides (create this!)
    /etc/fail2ban/jail.d/*.conf    — per-jail overrides

  Key settings per jail:
    enabled   = true
    port      = ssh
    logpath   = /var/log/auth.log
    maxretry  = 5                # failures before ban
    findtime  = 600              # window (seconds)
    bantime   = 3600             # ban duration (seconds), -1 = permanent
    ignoreip  = 127.0.0.1/8 ::1 # never ban these
INFO

    if ! cmd_exists fail2ban-client; then
        status_line neutral "fail2ban not installed (apt install fail2ban)"
        return
    fi

    section "fail2ban Status"
    echo -e "${INFO}Service status:${NC}"
    systemctl status fail2ban 2>/dev/null | head -6 | sed 's/^/  /' \
        || pgrep -a fail2ban 2>/dev/null | sed 's/^/  /'

    echo
    echo -e "${INFO}All jails:${NC}"
    sudo fail2ban-client status 2>/dev/null | sed 's/^/  /'

    echo
    echo -e "${INFO}SSH jail detail:${NC}"
    sudo fail2ban-client status sshd 2>/dev/null | sed 's/^/  /' \
        || sudo fail2ban-client status ssh 2>/dev/null | sed 's/^/  /'

    section "Recommended jail.local"
    cat << 'CONF'
  # /etc/fail2ban/jail.local
  [DEFAULT]
  bantime  = 3600
  findtime = 600
  maxretry = 5
  ignoreip = 127.0.0.1/8 ::1

  banaction = iptables-multiport
  action    = %(action_mwl)s      # ban + log + send email (if configured)

  [sshd]
  enabled  = true
  port     = ssh
  logpath  = %(sshd_log)s
  maxretry = 3
  bantime  = 86400

  [nginx-http-auth]
  enabled  = true
  logpath  = /var/log/nginx/error.log

  [apache-auth]
  enabled  = true
  logpath  = /var/log/apache2/error.log
CONF
}

# FIREWALL HARDENING
check_firewall_hardening() {
    header "Comprehensive Firewall Hardening Audit"

    section "Kernel Network Security Parameters"
    echo
    declare -A kernel_checks=(
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["kernel.randomize_va_space"]="2"
    )

    printf "  ${BOLD}%-45s %-10s %-10s %s${NC}\n" \
        "Parameter" "Current" "Expected" "Status"
    printf "  ${DARK_GRAY}%-45s %-10s %-10s %s${NC}\n" \
        "$(printf '%.0s' {1..44})" "" "" ""

    local pass=0 fail=0
    for param in "${!kernel_checks[@]}"; do
        local current expected="${kernel_checks[$param]}"
        current=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        local color sym
        if [[ "$current" == "$expected" ]]; then
            color="$SUCCESS" sym="✔" ; (( pass++ ))
        else
            color="$FAILURE" sym="✘" ; (( fail++ ))
        fi
        printf "  ${LABEL}%-45s${NC} ${MUTED}%-10s${NC} %-10s ${color}%s${NC}\n" \
            "$param" "$current" "$expected" "$sym"
    done

    echo
    printf "  ${SUCCESS}Passed: %-3s${NC}  ${FAILURE}Failed: %-3s${NC}  Total: %s\n" \
        "$pass" "$fail" "$(( pass + fail ))"

    section "Open Listening Ports"
    echo -e "${INFO}All listening TCP/UDP ports:${NC}"
    ss -tlunp 2>/dev/null | tail -n +2 | while read -r proto _ _ local _ process; do
        local port="${local##*:}"
        local color="$MUTED"
        case "$port" in
            22|80|443) color="$SUCCESS" ;;
            23|21|25)  color="$WARNING" ;;
            3389|5900) color="$FAILURE" ;;
        esac
        printf "  ${color}%-8s${NC} ${CYAN}%-30s${NC} %s\n" "$proto" "$local" "${process:-}"
    done

    section "Connection State Summary"
    ss -tan 2>/dev/null | awk 'NR>1{print $1}' | sort | uniq -c | sort -rn | \
        while read -r count state; do
            printf "  ${CYAN}%-6s${NC} ${LABEL}%s${NC}\n" "$count" "$state"
        done
}

main() {
    check_firewall_types
    check_iptables
    check_nftables
    check_ufw
    check_ids_ips
    check_waf
    check_fail2ban
    check_firewall_hardening
}

main