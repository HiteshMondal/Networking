#!/bin/bash

# /tools/tools.sh
# Tools menu handler
# This file is sourced by run.sh.

[[ -n "$_TOOLS_LOADED" ]] && return 0
export _TOOLS_LOADED=1

# Path resolution
# SCRIPT_DIR must be resolved before PROJECT_ROOT.
_TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Only set PROJECT_ROOT if not already exported by a parent script.
: "${PROJECT_ROOT:="$(dirname "$_TOOLS_DIR")"}"

#  Source dependencies (guarded — avoid double-source) 
[[ -z "$_COLORS_LOADED"    ]] && source "$PROJECT_ROOT/lib/colors.sh"
[[ -z "$_FUNCTIONS_LOADED" ]] && source "$PROJECT_ROOT/lib/functions.sh"

# Directory init (inside function, not at top level)
_tools_init() {
    mkdir -p "$PROJECT_ROOT/logs" "$PROJECT_ROOT/output"
}

#  DISPATCH HELPER
#  Usage: _launch "label" "tools/script.sh"
#  Validates the script exists then runs it in a subshell.
#  Adding a new tool = one line in the case statement.
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

    log_info "Launching ${label}..."
    bash "$full_path"
    local rc=$?
    [[ $rc -ne 0 ]] && log_warning "${label} exited with code ${rc}"
    return $rc
}

#  MENU DISPLAY
_tools_menu() {
    clear
    show_banner
    echo -e "${BOLD_BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BOLD_GREEN}           🛠  Available Tools             ${NC}"
    echo -e "${BOLD_BLUE}══════════════════════════════════════════${NC}"
    echo
    echo -e "  ${GREEN} 1.${NC}  Network Tools           ${MUTED}(interfaces, ports, ping, traceroute)${NC}"
    echo -e "  ${GREEN} 2.${NC}  Core Protocols          ${MUTED}(TCP/UDP, HTTP, DNS, ICMP)${NC}"
    echo -e "  ${GREEN} 3.${NC}  IP Addressing           ${MUTED}(subnetting, NAT, ARP)${NC}"
    echo -e "  ${GREEN} 4.${NC}  Network Master          ${MUTED}(all networking topics)${NC}"
    echo -e "  ${GREEN} 5.${NC}  Networking Basics       ${MUTED}(OSI, TCP/IP, bandwidth, switching)${NC}"
    echo -e "  ${GREEN} 6.${NC}  Switching & Routing     ${MUTED}(VLANs, MAC, RIP/OSPF/BGP)${NC}"
    echo -e "  ${GREEN} 7.${NC}  Security Fundamentals   ${MUTED}(CIA, AES, RSA, TLS, hashing)${NC}"
    echo
    echo -e "  ${RED} 0.${NC}  Back to Main Menu"
    echo
    echo -e "${BOLD_BLUE}══════════════════════════════════════════${NC}"
}

#  MAIN TOOLS FUNCTION
#  Called from run.sh: tools
tools() {
    _tools_init

    while true; do
        _tools_menu
        read -rp "$(echo -e "  ${PROMPT}Choose an option:${NC} ")" choice
        echo

        case "$choice" in
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
                log_error "Invalid option '${choice}'. Please try again."
                sleep 1
                ;;
        esac
    done
}