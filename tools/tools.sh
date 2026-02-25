#!/bin/bash

# /tools/tools.sh
# Tools menu handler

# Double-source guard (NOT exported)
[[ -n "$_TOOLS_LOADED" ]] && return 0
_TOOLS_LOADED=1

# Path resolution
_TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$_TOOLS_DIR")"}"

export LOG_DIR="${PROJECT_ROOT}/logs"
export OUTPUT_DIR="${PROJECT_ROOT}/output"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

# Directory init
_tools_init() {
    mkdir -p "$LOG_DIR" "$OUTPUT_DIR"
}

#  DISPATCH HELPER
# Usage: _launch "label" "tools/script.sh"
_launch() {
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

    # Launch header
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
        bash "$full_path"
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

#  MENU
_tools_menu() {
    clear
    show_banner
    local W=54
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')
    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "NETWORK TOOLS"
    echo -e "${BORDER}${border}${NC}"
    echo
    echo -e "  ${AMBER}Diagnostics & Live Analysis${NC}"
    echo -e "  ${GREEN}  1.${NC}  Network Tools             ${MUTED}Interfaces, ports, ping, traceroute${NC}"
    echo -e "  ${GREEN}  2.${NC}  Core Protocols            ${MUTED}TCP/UDP, HTTP, DNS, ICMP${NC}"
    echo -e "  ${GREEN}  3.${NC}  IP Addressing             ${MUTED}Subnetting, NAT, ARP${NC}"
    echo
    echo -e "  ${AMBER}Education & Reference${NC}"
    echo -e "  ${GREEN}  4.${NC}  Network Master            ${MUTED}All networking topics${NC}"
    echo -e "  ${GREEN}  5.${NC}  Networking Basics         ${MUTED}OSI, TCP/IP, bandwidth, switching${NC}"
    echo -e "  ${GREEN}  6.${NC}  Switching & Routing       ${MUTED}VLANs, MAC, RIP/OSPF/BGP${NC}"
    echo -e "  ${GREEN}  7.${NC}  Security Fundamentals     ${MUTED}CIA, AES, RSA, TLS, hashing${NC}"
    echo
    echo -e "  ${RED}  0.${NC}  Back to Main Menu"
    echo
    echo -e "${BORDER}${border}${NC}"
}

#  ENTRY POINT (called from run.sh as: tools)
tools() {
    _tools_init
    while true; do
        _tools_menu
        read -rp "$(echo -e "  ${PROMPT}[?] Choose an option: ${NC}")" tools_choice
        echo
        case "$tools_choice" in
            1) _launch "Network Tools"          "tools/network_tools.sh"         ;;
            2) _launch "Core Protocols"         "tools/core_protocols.sh"        ;;
            3) _launch "IP Addressing"          "tools/ip_addressing.sh"         ;;
            4) _launch "Network Master"         "tools/network_master.sh"        ;;
            5) _launch "Networking Basics"      "tools/networking_basics.sh"     ;;
            6) _launch "Switching & Routing"    "tools/switching_routing.sh"     ;;
            7) _launch "Security Fundamentals"  "tools/security_fundamentals.sh" ;;
            0)
                log_info "Returning to main menu..."
                return 0
                ;;
            *)
                log_error "Invalid option '${tools_choice}'. Please try again."
                sleep 1
                ;;
        esac

        # Brief pause after each tool run before returning to menu
        echo
        echo -e "  ${DARK_GRAY}$(printf '%*s' 50 '' | tr ' ' '-')${NC}"
        read -rp "$(echo -e "  ${MUTED}Press Enter to return to the Tools menu...${NC}  ")"
    done
}