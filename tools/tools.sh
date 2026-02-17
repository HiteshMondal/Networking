#!/bin/bash

# /tools/tools.sh
# Tools menu handler

# Double-source guard (NOT exported)
[[ -n "$_TOOLS_LOADED" ]] && return 0
_TOOLS_LOADED=1

# Path resolution
_TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Use :=  so a value already set by run.sh is never overwritten.
: "${PROJECT_ROOT:="$(dirname "$_TOOLS_DIR")"}"

# Canonical directory paths (exported for child scripts)
export LOG_DIR="${PROJECT_ROOT}/logs"
export OUTPUT_DIR="${PROJECT_ROOT}/output"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

# Directory init (called at entry point, not at source time)
_tools_init() {
    mkdir -p "$LOG_DIR" "$OUTPUT_DIR"
}

# DISPATCH HELPER
# Usage: _launch "label" "tools/script.sh"
# Validates the script exists, then runs it in a subshell.
# stdout+stderr are tee'd to a timestamped log file in $LOG_DIR.
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

    # Build a filename-safe version of the label for the log file name.
    local safe_label
    safe_label=$(echo "$label" | tr '[:upper:] ' '[:lower:]_' | tr -cd 'a-z0-9_')
    local log_file="${LOG_DIR}/${safe_label}_$(date '+%Y%m%d_%H%M%S').log"

    log_info "Launching ${label}…"
    log_info "Log: ${log_file}"

    # Run the tool, tee output to log file so the dashboard can read it.
    {
        echo "=== ${label} started at $(date) ==="
        bash "$full_path"
        local rc=$?
        echo "=== ${label} completed at $(date) with exit code ${rc} ==="
        return $rc
    } 2>&1 | tee -a "$log_file"

    # Recover the actual exit code from the subshell via PIPESTATUS.
    local exit_code="${PIPESTATUS[0]}"
    [[ $exit_code -ne 0 ]] && log_warning "${label} exited with code ${exit_code}"
    return $exit_code
}

# MENU DISPLAY
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

# MAIN TOOLS FUNCTION
# Called from run.sh: tools
tools() {
    _tools_init
    while true; do
        _tools_menu
        read -rp "$(echo -e "  ${PROMPT}Choose an option:${NC} ")" tools_choice
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
                log_info "Returning to main menu…"
                return 0
                ;;
            *)
                log_error "Invalid option '${tools_choice}'. Please try again."
                sleep 1
                ;;
        esac
    done
}