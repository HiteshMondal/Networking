#!/bin/bash

# /network_lab/networking/network_master.sh
# Network Concepts Checker — Master Launcher

# Bootstrap — script lives 2 levels below PROJECT_ROOT
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SELF_DIR/../.." && pwd)"
source "$PROJECT_ROOT/lib/init.sh"

# Export so child bash processes (run_full_analysis) inherit them.
export LOG_DIR OUTPUT_DIR PROJECT_ROOT

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

#  FULL SYSTEM ANALYSIS (non-interactive run-all)
run_full_analysis() {
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')

    local report_file="${OUTPUT_DIR}/full_analysis_${timestamp}.txt"
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
    } | tee -a "$report_file" | tee -a "$log_file"

    local shim_file="${OUTPUT_DIR}/.noninteractive_shim_$$.sh"
    cat > "$shim_file" << 'SHIM'
# Injected by network_master.sh — suppresses blocking calls in child scripts.
pause()          { echo; }
countdown()      { echo; }
confirm()        { return 1; }
read()           { return 0; }
SHIM

    trap 'rm -f "$shim_file"; unset BASH_ENV' EXIT INT TERM HUP

    export BASH_ENV="$shim_file"

    local topics=(
        "networking_basics.sh:Networking Basics"
        "ip_addressing.sh:IP & Addressing"
        "core_protocols.sh:Core Protocols"
        "switching_routing.sh:Switching & Routing"
        "security_fundamentals.sh:Security Fundamentals"
    )

    # Map each script to its actual path — some live in diagnostics/, others in networking/ or security/
    declare -A script_paths=(
        ["networking_basics.sh"]="$_SELF_DIR/networking_basics.sh"
        ["ip_addressing.sh"]="$(dirname "$_SELF_DIR")/diagnostics/ip_addressing.sh"
        ["core_protocols.sh"]="$_SELF_DIR/core_protocols.sh"
        ["switching_routing.sh"]="$_SELF_DIR/switching_routing.sh"
        ["security_fundamentals.sh"]="$(dirname "$_SELF_DIR")/security/security_fundamentals.sh"
    )

    local passed=0 failed=0

    for entry in "${topics[@]}"; do
        local script="${entry%%:*}" label="${entry##*:}"
        local full_path="${script_paths[$script]}"

        echo
        echo -e "${GOLD}${BOLD}┌── Running: ${label} ──${NC}"

        if [[ ! -f "$full_path" ]]; then
            status_line fail "$label — script missing at ${full_path}"
            failed=$(( failed + 1 ))
            continue
        fi

        {
            echo
            echo "── ${label} ──"
            bash "$full_path" 2>&1 || true
        } | tee -a "$report_file" | tee -a "$log_file"

        status_line ok "$label — complete"
        passed=$(( passed + 1 ))
    done

    rm -f "$shim_file"
    unset BASH_ENV
    trap - EXIT INT TERM HUP

    echo
    echo -e "${BOLD}Analysis Complete:${NC}"
    kv "Passed"  "$passed"
    kv "Failed"  "$failed"
    kv "Report"  "$report_file"
    kv "Log"     "$log_file"

    pause
}

#  MAIN
main() {
    check_requirements
    run_full_analysis
}

main