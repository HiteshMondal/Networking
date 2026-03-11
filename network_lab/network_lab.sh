#!/bin/bash

# /network_lab/network_lab.sh
# Network Lab controller and menu handler
chmod -R +x network_lab
# DOUBLE SOURCE GUARD
[[ -n "${_NETWORK_LAB_LOADED:-}" ]] && return 0
_NETWORK_LAB_LOADED=1

# PATH RESOLUTION
NETWORK_LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$NETWORK_LAB_DIR")"}"

NETWORK_LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$NETWORK_LAB_DIR")"

source "$PROJECT_ROOT/lib/init.sh"

# INIT DIRECTORIES
_network_lab_init() {
    mkdir -p "$LOG_DIR" "$OUTPUT_DIR"
}

# TOOL LAUNCH HELPER
# Usage: _network_lab_launch "Label" "network_lab/script.sh"
_network_lab_launch() {
    local label="$1"
    local relative_path="$2"
    local full_path="$PROJECT_ROOT/$relative_path"

    if [[ ! -f "$full_path" ]]; then
        log_error "${label}: script not found at ${full_path}"
        return 1
    fi

    if [[ ! -r "$full_path" ]]; then
        log_error "${label}: script is not readable (check permissions)"
        return 1
    fi

    local safe_label
    safe_label=$(echo "$label" | tr '[:upper:] ' '[:lower:]_' | tr -cd 'a-z0-9_')

    local log_file="${LOG_DIR}/${safe_label}_$(date '+%Y%m%d_%H%M%S').log"

    # HEADER
    clear
    show_banner

    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${ACCENT}[>] %-$((W-7))s${NC}  ${BORDER}|${NC}\n" "$label"
    echo -e "${BORDER}${border}${NC}"
    echo

    log_info "Log: ${log_file}"
    echo

    {
        echo "=== ${label} started at $(date) ==="

        "$full_path"
        local rc=$?

        echo "=== ${label} completed at $(date) with exit code ${rc} ==="
        return $rc

    } 2>&1 | tee -a "$log_file"

    local exit_code="${PIPESTATUS[0]}"

    echo
    echo -e "  ${DARK_GRAY}$(printf '%*s' 50 '' | tr ' ' '-')${NC}"

    if [[ $exit_code -ne 0 ]]; then
        log_warning "${label} exited with code ${exit_code}"
    else
        log_success "${label} completed successfully."
    fi

    return $exit_code
}

# MENU
_network_lab_menu() {
    clear
    show_banner

    local W=54
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "NETWORK LAB"
    echo -e "${BORDER}${border}${NC}"
    echo
    echo -e "  ${AMBER}Diagnostics & Live Analysis${NC}"
    echo -e "  ${GREEN}  1.${NC}  Network Tools             ${MUTED}Interfaces, ports, ping, traceroute${NC}"
    echo -e "  ${GREEN}  2.${NC}  Core Protocols            ${MUTED}TCP/UDP, HTTP, DNS, ICMP${NC}"
    echo -e "  ${GREEN}  3.${NC}  IP Addressing             ${MUTED}Subnetting, NAT, ARP${NC}"
    echo -e "  ${GREEN}  4.${NC}  Packet Analysis           ${MUTED}Headers, Wireshark filters, PCAP${NC}"
    echo
    echo -e "  ${AMBER}Education & Reference${NC}"
    echo -e "  ${GREEN}  5.${NC}  Network Master            ${MUTED}All networking topics${NC}"
    echo -e "  ${GREEN}  6.${NC}  Networking Basics         ${MUTED}OSI, TCP/IP, switching${NC}"
    echo -e "  ${GREEN}  7.${NC}  Switching & Routing       ${MUTED}VLANs, MAC, RIP/OSPF/BGP${NC}"
    echo -e "  ${GREEN}  8.${NC}  Security Fundamentals     ${MUTED}CIA, TLS, AES, hashing${NC}"
    echo
    echo -e "  ${AMBER}Advanced Security${NC}"
    echo -e "  ${GREEN}  9.${NC}  Wireless Security         ${MUTED}WiFi standards, WPA3, attacks${NC}"
    echo -e "  ${GREEN} 10.${NC}  Firewall & IDS/IPS        ${MUTED}iptables, nftables, Snort${NC}"
    echo -e "  ${GREEN} 11.${NC}  Network Hardening         ${MUTED}SSH, VPN, Zero Trust${NC}"
    echo -e "  ${GREEN} 12.${NC}  Threat Intelligence       ${MUTED}OSINT, CVE, ATT&CK${NC}"
    echo
    echo -e "  ${AMBER}Automation${NC}"
    echo -e "  ${GREEN} 13.${NC}  Run All Network Lab Modules"
    echo
    echo -e "  ${RED}  0.${NC}  Back to Main Menu"
    echo
    echo -e "${BORDER}${border}${NC}"
}

run_all_network_lab_modules() {
    clear
    show_banner
    echo
    echo -e "  ${ACCENT}[>] Running ALL Network Lab modules sequentially"
    echo -e "  ${WARNING}[~] This will execute every networking lab topic."
    echo
    echo -e "  ${PROMPT}Starting in 3 seconds... Press Ctrl+C to cancel.${NC}"
    sleep 3
    _network_lab_launch "Network Tools"         "network_lab/networking/network_tools.sh"
    _network_lab_launch "Core Protocols"        "network_lab/networking/core_protocols.sh"
    _network_lab_launch "IP Addressing"         "network_lab/diagnostics/ip_addressing.sh"
    _network_lab_launch "Packet Analysis"       "network_lab/diagnostics/packet_analysis.sh"
    _network_lab_launch "Network Master"        "network_lab/networking/network_master.sh"
    _network_lab_launch "Networking Basics"     "network_lab/networking/networking_basics.sh"
    _network_lab_launch "Switching & Routing"   "network_lab/networking/switching_routing.sh"
    _network_lab_launch "Security Fundamentals" "network_lab/security/security_fundamentals.sh"
    _network_lab_launch "Wireless Security"     "network_lab/security/wireless_security.sh"
    _network_lab_launch "Firewall & IDS/IPS"    "network_lab/security/firewall_ids.sh"
    _network_lab_launch "Network Hardening"     "network_lab/networking/network_hardening.sh"
    _network_lab_launch "Threat Intelligence"   "network_lab/security/threat_intelligence.sh"
    echo
    log_success "All Network Lab modules completed."
    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to return to the menu...${NC}")"
}

# ENTRY POINT
network_lab() {
    _network_lab_init

    while true; do
        _network_lab_menu
        read -rp "$(echo -e "  ${PROMPT}[?] Choose an option: ${NC}")" network_lab_choice
        echo
        case "$network_lab_choice" in
            1)  _network_lab_launch "Network Tools"         "network_lab/networking/network_tools.sh" ;;
            2)  _network_lab_launch "Core Protocols"        "network_lab/networking/core_protocols.sh" ;;
            3)  _network_lab_launch "IP Addressing"         "network_lab/diagnostics/ip_addressing.sh" ;;
            4)  _network_lab_launch "Packet Analysis"       "network_lab/diagnostics/packet_analysis.sh" ;;
            5)  _network_lab_launch "Network Master"        "network_lab/networking/network_master.sh" ;;
            6)  _network_lab_launch "Networking Basics"     "network_lab/networking/networking_basics.sh" ;;
            7)  _network_lab_launch "Switching & Routing"   "network_lab/networking/switching_routing.sh" ;;
            8)  _network_lab_launch "Security Fundamentals" "network_lab/security/security_fundamentals.sh" ;;
            9)  _network_lab_launch "Wireless Security"     "network_lab/security/wireless_security.sh" ;;
            10) _network_lab_launch "Firewall & IDS/IPS"    "network_lab/security/firewall_ids.sh" ;;
            11) _network_lab_launch "Network Hardening"     "network_lab/networking/network_hardening.sh" ;;
            12) _network_lab_launch "Threat Intelligence"   "network_lab/security/threat_intelligence.sh" ;;
            13) run_all_network_lab_modules ;;
            0)
                log_info "Returning to main menu..."
                return 0
                ;;
            *)
                log_error "Invalid option '${network_lab_choice}'. Please try again."
                sleep 1
                ;;
        esac
        echo
        echo -e "  ${DARK_GRAY}$(printf '%*s' 50 '' | tr ' ' '-')${NC}"
        read -rp "$(echo -e "  ${MUTED}Press Enter to return to the network_lab menu...${NC}  ")"
    done
}