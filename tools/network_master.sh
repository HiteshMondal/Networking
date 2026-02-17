#!/bin/bash

# /tools/network_master.sh
# Network Concepts Checker — Master Launcher

# Bootstrap
# IMPORTANT: SCRIPT_DIR must be set BEFORE PROJECT_ROOT
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PROJECT_ROOT:="$(dirname "$SCRIPT_DIR")"}"

# Directory paths (inherit from env if launched via tools.sh)
: "${LOG_DIR:="${PROJECT_ROOT}/logs"}"
: "${OUTPUT_DIR:="${PROJECT_ROOT}/output"}"
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Export so child bash processes (run_topic, run_all) inherit them.
export LOG_DIR OUTPUT_DIR PROJECT_ROOT

# Source dependencies
[[ -z "$_COLORS_LOADED"    ]] && source "$PROJECT_ROOT/lib/colors.sh"
[[ -z "$_FUNCTIONS_LOADED" ]] && source "$PROJECT_ROOT/lib/functions.sh"

#  REQUIREMENTS CHECK
check_requirements() {
    local missing=()
    for tool in ip ss ping traceroute dig nslookup curl openssl; do
        cmd_exists "$tool" || missing+=("$tool")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo
        log_warning "Some tools are missing: ${missing[*]}"
        echo -e "  ${MUTED}Install with:${NC}"
        echo -e "  ${CYAN}  sudo apt-get install iproute2 iputils-ping traceroute dnsutils curl openssl${NC}"
        echo
    fi
}

#  SCRIPT RUNNER
run_topic() {
    local script_name="$1"
    local script_path="$SCRIPT_DIR/$script_name"

    if [[ ! -f "$script_path" ]]; then
        log_error "Script not found: $script_path"
        pause
        return 1
    fi

    if [[ ! -r "$script_path" ]]; then
        log_error "Script not readable: $script_path"
        pause
        return 1
    fi

    log_step "Launching: $script_name"
    # bash inherits exported variables (LOG_DIR, OUTPUT_DIR, PROJECT_ROOT)
    bash "$script_path"
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        log_warning "Script exited with code $rc"
    else
        log_success "Completed: $script_name"
    fi
    return $rc
}

#  FULL SYSTEM ANALYSIS (non-interactive run-all)
run_all() {
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')

    # Report artifact → output/  (user-facing deliverable)
    local report_file="${OUTPUT_DIR}/full_analysis_${timestamp}.txt"
    # Runtime log      → logs/   (execution record)
    local log_file="${LOG_DIR}/network_master_${timestamp}.log"

    log_info "Full analysis — report: $report_file"
    log_info "Runtime log  — log:    $log_file"

    {
        echo "══════════════════════════════════════════════════════"
        echo "  Network & Security Full Analysis"
        echo "  Generated : $(date)"
        echo "  Host      : $(hostname)"
        echo "  OS        : $(detect_os)"
        echo "══════════════════════════════════════════════════════"
        echo
    } | tee "$report_file" | tee -a "$log_file"

    local topics=(
        "networking_basics.sh:Networking Basics"
        "ip_addressing.sh:IP & Addressing"
        "core_protocols.sh:Core Protocols"
        "switching_routing.sh:Switching & Routing"
        "security_fundamentals.sh:Security Fundamentals"
    )

    local passed=0 failed=0
    for entry in "${topics[@]}"; do
        local script="${entry%%:*}" label="${entry##*:}"
        echo
        echo -e "${GOLD}${BOLD}┌── Running: ${label} ──${NC}"

        if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
            status_line fail "$label — script missing"
            (( failed++ ))
            continue
        fi

        {
            echo
            echo "── ${label} ──"
            # Child script inherits LOG_DIR, OUTPUT_DIR, PROJECT_ROOT via export
            bash "$SCRIPT_DIR/$script" 2>&1 || true
        } | tee -a "$report_file" | tee -a "$log_file"

        status_line ok "$label — complete"
        (( passed++ ))
    done

    echo
    echo -e "${BOLD}Analysis Complete:${NC}"
    kv "Passed"  "$passed"
    kv "Failed"  "$failed"
    kv "Report"  "$report_file"
    kv "Log"     "$log_file"

    pause
}

#  MENU
show_menu() {
    clear
    show_banner
    echo -e "${BOLD_CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD_CYAN}║     Network Concepts Checker & Demonstrator          ║${NC}"
    echo -e "${BOLD_CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "  ${GREEN} 1.${NC}  Networking Basics  ${MUTED}(OSI/TCP-IP, Bandwidth, Switching)${NC}"
    echo -e "  ${GREEN} 2.${NC}  IP & Addressing    ${MUTED}(IPv4/6, Subnetting, NAT, ARP)${NC}"
    echo -e "  ${GREEN} 3.${NC}  Core Protocols     ${MUTED}(TCP/UDP, HTTP, DNS, ICMP)${NC}"
    echo -e "  ${GREEN} 4.${NC}  Switching & Routing${MUTED}(VLANs, MAC, RIP/OSPF/BGP)${NC}"
    echo -e "  ${GREEN} 5.${NC}  Security Fundamentals${MUTED}(CIA, AES, RSA, TLS, JWT)${NC}"
    echo
    echo -e "  ${GOLD}  A.${NC}  Run ALL — Full System Analysis (saves report)"
    echo
    echo -e "  ${RED}  0.${NC}  Exit"
    echo
}

#  MAIN
main() {
    check_requirements

    while true; do
        show_menu
        read -rp "$(echo -e "  ${PROMPT}Choice:${NC} ")" choice
        case "$choice" in
            1) run_topic "networking_basics.sh" ;;
            2) run_topic "ip_addressing.sh" ;;
            3) run_topic "core_protocols.sh" ;;
            4) run_topic "switching_routing.sh" ;;
            5) run_topic "security_fundamentals.sh" ;;
            [aA]) run_all ;;
            0)
                echo -e "\n${CYAN}  Goodbye!${NC}\n"
                exit 0
                ;;
            *)
                log_warning "Invalid choice — try again"
                sleep 1
                ;;
        esac
    done
}

main