#!/bin/bash

# /tools/network_tools.sh
# Network Tools Analyzer & Live Monitor
# New: input sanitization, bandwidth test, DNS bench, port range scanner, whois, better output

# Bootstrap
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$_SELF_DIR")"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
OUTPUT_DIR="$PROJECT_ROOT/output"
mkdir -p "$OUTPUT_DIR"

# Package manager detection (cached)
PKG_MANAGER=""
detect_pkg_manager() {
    [[ -n "$PKG_MANAGER" ]] && return
    for pm in apt dnf yum pacman brew; do
        cmd_exists "$pm" && PKG_MANAGER="$pm" && return
    done
    PKG_MANAGER="unknown"
}

# Install a package if missing, then verify the binary is reachable.
ensure_tool() {
    local tool="$1" pkg="${2:-$1}"
    cmd_exists "$tool" && return 0
    log_warning "$tool not found — attempting install..."
    case "$PKG_MANAGER" in
        apt)    sudo apt-get install -y "$pkg" -qq ;;
        dnf)    sudo dnf install -y "$pkg" -q ;;
        yum)    sudo yum install -y "$pkg" -q ;;
        pacman) sudo pacman -S --noconfirm "$pkg" ;;
        brew)   brew install "$pkg" ;;
        *)      log_error "Cannot auto-install $pkg — please install manually"; return 1 ;;
    esac
    # Re-verify: a successful package-manager exit code does not
    # guarantee the binary is on the current PATH.
    if cmd_exists "$tool"; then
        log_success "$tool installed and available"
        return 0
    else
        log_error "$tool installed but not found on PATH — try: hash -r"
        return 1
    fi
}

# Safely prompt for a host/IP
prompt_host() {
    local default="${1:-8.8.8.8}"
    local input
    read -rp "$(echo -e "  ${PROMPT}Target host/IP [default: ${default}]:${NC} ")" input
    input="${input:-$default}"
    if is_valid_ip "$input" || is_valid_host "$input"; then
        echo "$input"
    else
        log_warning "Invalid input '$input' — using default: $default"
        echo "$default"
    fi
}

#  TOOLS
run_interface_info() {
    header "Network Interface Information"

    echo -e "${INFO}Interface details (ip addr):${NC}"
    ip addr show 2>/dev/null | while IFS= read -r line; do
        if [[ "$line" =~ ^[0-9]+: ]]; then
            echo -e "  ${BOLD_WHITE}${line}${NC}"
        elif [[ "$line" =~ inet[6]? ]]; then
            echo -e "  ${CYAN}${line}${NC}"
        else
            echo -e "  ${MUTED}${line}${NC}"
        fi
    done

    echo
    echo -e "${INFO}Link speed & duplex (ethtool):${NC}"
    for iface in $(ip link show 2>/dev/null | awk -F': ' '/^[0-9]/{print $2}' | grep -v lo); do
        local speed duplex
        speed=$(ethtool "$iface" 2>/dev/null | grep -i "^.*speed:" | awk '{print $2}')
        duplex=$(ethtool "$iface" 2>/dev/null | grep -i "duplex:" | awk '{print $2}')
        [[ -n "$speed" ]] && kv "$iface" "${speed} / ${duplex:-unknown duplex}"
    done

    echo
    echo -e "${INFO}Interface statistics (bytes):${NC}"
    ip -s link show 2>/dev/null | grep -E "^[0-9]+:|RX:|TX:" | paste - - - | \
        awk '{printf "  %-14s RX %-16s TX %s\n", $2, $5, $12}' 2>/dev/null

    pause
}

run_connections() {
    header "Active Network Connections"

    echo -e "${INFO}All listening ports (TCP + UDP):${NC}"
    echo
    printf "  ${BOLD}%-8s %-24s %-20s %s${NC}\n" "Proto" "Local Address" "State" "Process"
    printf "  ${DARK_GRAY}%-8s %-24s %-20s %s${NC}\n" "───────" "───────────────────────" "───────────────────" "───────"
    ss -tulnp 2>/dev/null | tail -n +2 | while read -r proto _ _ local _ process; do
        local state=""
        printf "  ${GREEN}%-8s${NC} ${CYAN}%-24s${NC} ${MUTED}%-20s${NC} %s\n" \
            "$proto" "$local" "$state" "$process"
    done

    echo
    echo -e "${INFO}Established TCP connections:${NC}"
    ss -tnp state established 2>/dev/null | tail -n +2 | head -20 | \
        sed 's/^/  /'

    echo
    echo -e "${INFO}Socket summary:${NC}"
    ss -s 2>/dev/null | sed 's/^/  /'

    pause
}

run_ping() {
    header "Ping Test"

    local target count
    target=$(prompt_host "8.8.8.8")
    read -rp "$(echo -e "  ${PROMPT}Number of packets [default: 5]:${NC} ")" count
    count="${count:-5}"
    is_integer "$count" 1 100 || count=5

    echo
    echo -e "${INFO}Pinging ${target} with ${count} packets:${NC}"
    ping -c "$count" -i 0.5 "$target" 2>/dev/null || log_error "Ping failed"

    pause
}

run_traceroute() {
    header "Traceroute"

    local target
    target=$(prompt_host "google.com")
    local max_hops
    read -rp "$(echo -e "  ${PROMPT}Max hops [default: 15]:${NC} ")" max_hops
    max_hops="${max_hops:-15}"
    is_integer "$max_hops" 1 30 || max_hops=15

    echo
    echo -e "${INFO}Tracing route to ${target}:${NC}"
    if cmd_exists traceroute; then
        traceroute -m "$max_hops" -w 2 "$target" 2>/dev/null
    elif cmd_exists tracepath; then
        tracepath -n "$target" 2>/dev/null | head "$max_hops"
    else
        log_warning "traceroute/tracepath not found"
        ensure_tool traceroute
    fi

    pause
}

run_port_scan() {
    header "Port Scanner"

    local target
    target=$(prompt_host "127.0.0.1")
    local range
    read -rp "$(echo -e "  ${PROMPT}Scan mode — (1) common ports, (2) range, (3) nmap:${NC} ")" scan_mode

    echo

    case "$scan_mode" in
        2)
            local start_port end_port
            read -rp "$(echo -e "  ${PROMPT}Start port:${NC} ")" start_port
            read -rp "$(echo -e "  ${PROMPT}End port:${NC} ")"   end_port
            is_integer "$start_port" 1 65535 || start_port=1
            is_integer "$end_port"   1 65535 || end_port=1024

            echo -e "${INFO}Scanning ports ${start_port}–${end_port} on ${target}...${NC}"
            for (( p=start_port; p<=end_port; p++ )); do
                if port_open "$target" "$p"; then
                    printf "  ${SUCCESS}%-6d OPEN${NC}\n" "$p"
                fi
            done
            ;;
        3)
            ensure_tool nmap
            if cmd_exists nmap; then
                echo -e "${INFO}Running nmap service scan on ${target}:${NC}"
                nmap -sV --open "$target" 2>/dev/null
            fi
            ;;
        *)
            echo -e "${INFO}Scanning common ports on ${target}:${NC}"
            local common_ports=(21 22 23 25 53 80 110 111 135 139 143 443 445 587 993 995 1433 1521 3306 3389 5432 5900 6379 8080 8443 8888 27017)
            for port in "${common_ports[@]}"; do
                if port_open "$target" "$port"; then
                    printf "  ${SUCCESS}%-6d OPEN${NC}\n" "$port"
                else
                    printf "  ${MUTED}%-6d closed${NC}\n" "$port"
                fi
            done
            ;;
    esac

    pause
}

run_tcpdump() {
    header "Packet Capture (tcpdump)"

    ensure_tool tcpdump || { pause; return; }

    echo -e "${INFO}Available interfaces:${NC}"
    ip link show 2>/dev/null | grep -oP '^\d+: \K[^:@]+' | grep -v lo | nl -w2 -s'. '

    local iface count filter
    read -rp "$(echo -e "  ${PROMPT}Interface [default: first non-lo]:${NC} ")" iface
    iface="${iface:-$(ip link show 2>/dev/null | grep -oP '^\d+: \K[^:@]+' | grep -v lo | head -1)}"

    read -rp "$(echo -e "  ${PROMPT}Packets to capture [default: 20]:${NC} ")" count
    count="${count:-20}"
    is_integer "$count" 1 500 || count=20

    read -rp "$(echo -e "  ${PROMPT}BPF filter [e.g. 'tcp port 80', empty=none]:${NC} ")" filter

    echo
    log_warning "Packet capture requires sudo"
    if [[ -n "$filter" ]]; then
        sudo tcpdump -i "$iface" -c "$count" "$filter" 2>/dev/null
    else
        sudo tcpdump -i "$iface" -c "$count" 2>/dev/null
    fi

    pause
}

run_dns_bench() {
    header "DNS Benchmark"

    read -rp "$(echo -e "  ${PROMPT}Domain to test [default: example.com]:${NC} ")" domain
    domain="${domain:-example.com}"
    is_valid_host "$domain" || { log_warning "Invalid domain"; domain="example.com"; }

    local resolvers=("8.8.8.8:Google" "1.1.1.1:Cloudflare" "9.9.9.9:Quad9"
                     "208.67.222.222:OpenDNS" "185.228.168.9:CleanBrowsing"
                     "8.26.56.26:Comodo")

    echo
    printf "  ${BOLD}%-16s %-14s %-8s %s${NC}\n" "Resolver" "Provider" "Time(ms)" "Answer"
    printf "  ${DARK_GRAY}%-16s %-14s %-8s %s${NC}\n" "────────────────" "──────────────" "────────" "──────────"

    # Detect whether nanosecond timestamps are available once, outside the loop.
    local use_ns=0
    date +%s%N 2>/dev/null | grep -qP '^\d{19}' && use_ns=1

    for rs in "${resolvers[@]}"; do
        local ip="${rs%%:*}" name="${rs##*:}"
        local t_start t_end elapsed answer

        if [[ "$use_ns" -eq 1 ]]; then
            # Capture answer and timing in a single dig call per resolver.
            # Previously the fallback branch ran dig twice — once for timing
            # (discarding the answer) and once to capture the answer.
            t_start=$(date +%s%N)
            answer=$(dig +short +time=2 "$domain" "@$ip" 2>/dev/null | head -1)
            t_end=$(date +%s%N)
            elapsed=$(( (t_end - t_start) / 1000000 ))
        else
            # Second-precision fallback: single dig call; accept ~1s granularity.
            t_start=$(date +%s)
            answer=$(dig +short +time=2 "$domain" "@$ip" 2>/dev/null | head -1)
            t_end=$(date +%s)
            elapsed=$(( (t_end - t_start) * 1000 ))
        fi

        local color="$GREEN"
        (( elapsed > 200 )) && color="$YELLOW"
        (( elapsed > 500 )) && color="$FAILURE"
        [[ -z "$answer" ]] && color="$MUTED" && answer="(no answer)"

        printf "  ${CYAN}%-16s${NC} ${MUTED}%-14s${NC} ${color}%-8s${NC} %s\n" \
            "$ip" "$name" "${elapsed}ms" "$answer"
    done

    pause
}

run_whois() {
    header "WHOIS / IP Info"

    local target
    target=$(prompt_host "google.com")

    if cmd_exists whois; then
        echo -e "\n${INFO}WHOIS for ${target}:${NC}"
        whois "$target" 2>/dev/null | grep -iE "^(domain|registrar|creation|updated|expiry|name server|org|country|netname|descr|cidr|route|admin|tech)" | head -30 | sed 's/^/  /'
    elif cmd_exists curl; then
        echo -e "\n${INFO}IP info via ipinfo.io:${NC}"
        curl -s "https://ipinfo.io/${target}/json" 2>/dev/null | python3 -m json.tool 2>/dev/null | sed 's/^/  /' \
            || echo -e "  ${MUTED}No response${NC}"
    else
        log_warning "whois and curl not available"
    fi

    pause
}

run_bandwidth_monitor() {
    header "Bandwidth Monitor"

    echo -e "${INFO}Snapshot: Interface TX/RX (2-second interval):${NC}"

    local ifaces
    ifaces=$(ip link show 2>/dev/null | grep -oP '^\d+: \K[^:@]+' | grep -v lo)

    # Read stats twice, 2 seconds apart
    declare -A rx1 tx1
    for iface in $ifaces; do
        rx1["$iface"]=$(cat "/sys/class/net/${iface}/statistics/rx_bytes" 2>/dev/null || echo 0)
        tx1["$iface"]=$(cat "/sys/class/net/${iface}/statistics/tx_bytes" 2>/dev/null || echo 0)
    done

    echo -e "  ${MUTED}Sampling for 2 seconds...${NC}"
    sleep 2

    echo
    printf "  ${BOLD}%-14s %-16s %-16s${NC}\n" "Interface" "RX (bytes/s)" "TX (bytes/s)"
    printf "  ${DARK_GRAY}%-14s %-16s %-16s${NC}\n" "──────────────" "────────────────" "────────────────"

    for iface in $ifaces; do
        local rx2 tx2 rxdiff txdiff
        rx2=$(cat "/sys/class/net/${iface}/statistics/rx_bytes" 2>/dev/null || echo 0)
        tx2=$(cat "/sys/class/net/${iface}/statistics/tx_bytes" 2>/dev/null || echo 0)
        rxdiff=$(( rx2 - rx1["$iface"] ))
        txdiff=$(( tx2 - tx1["$iface"] ))
        printf "  ${CYAN}%-14s${NC} ${GREEN}%-16s${NC} ${YELLOW}%-16s${NC}\n" \
            "$iface" "${rxdiff} B/s" "${txdiff} B/s"
    done

    echo
    echo -e "  ${MUTED}Tip: Use 'iftop' or 'nethogs' for live per-connection monitoring${NC}"
    if ! cmd_exists iftop; then
        echo -e "  ${MUTED}Install: sudo apt install iftop${NC}"
    fi

    pause
}

run_install_all() {
    header "Check & Install Network Tools"

    detect_pkg_manager
    echo -e "${INFO}Package manager: ${PKG_MANAGER}${NC}"
    echo

    local tools=(
        "nmap:nmap"
        "tcpdump:tcpdump"
        "traceroute:traceroute"
        "dig:dnsutils"
        "ss:iproute2"
        "ip:iproute2"
        "netstat:net-tools"
        "iftop:iftop"
        "mtr:mtr"
        "whois:whois"
        "curl:curl"
        "ethtool:ethtool"
    )

    for entry in "${tools[@]}"; do
        local cmd="${entry%%:*}" pkg="${entry##*:}"
        if cmd_exists "$cmd"; then
            status_line ok "${cmd} (${pkg}) — already installed"
        else
            status_line fail "${cmd} (${pkg}) — NOT found"
            read -rp "    Install ${pkg}? [y/N]: " yn
            [[ "$yn" =~ ^[yY] ]] && ensure_tool "$cmd" "$pkg"
        fi
    done

    pause
}

main() {
    detect_pkg_manager
    run_interface_info
    run_connections
    run_ping
    run_traceroute
    run_port_scan
    run_tcpdump
    run_dns_bench
    run_whois
    run_bandwidth_monitor
}

main