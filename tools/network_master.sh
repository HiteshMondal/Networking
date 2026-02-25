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

#  FULL SYSTEM ANALYSIS (non-interactive run-all)
run_full_analysis() {
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
    } | tee -a "$report_file" | tee -a "$log_file"

    # Create a BASH_ENV shim that overrides interactive helpers so child
    # scripts don't block waiting for user input when run non-interactively.
    # This does NOT modify any existing function — it only takes effect in
    # the child bash processes spawned by the loop below.
    local shim_file="${OUTPUT_DIR}/.noninteractive_shim_$$.sh"
    cat > "$shim_file" << 'SHIM'
# Injected by network_master.sh — suppresses blocking calls in child scripts.
pause()          { echo; }
countdown()      { echo; }
confirm()        { return 1; }
# Override read-based prompts: strip the prompt and return the default value
# embedded in each function's own default variable (already coded in scripts).
# We achieve this by making read a no-op — the caller's default applies.
read()           { return 0; }
SHIM

    # Register cleanup BEFORE exporting BASH_ENV so the trap is in place for
    # every possible exit path: normal completion, Ctrl+C (INT), kill (TERM),
    # or hangup (HUP). Without this, an interrupted run leaves BASH_ENV
    # exported in the parent tools.sh session, silently suppressing pause/read
    # in every subsequent _launch call for the rest of that session.
    trap 'rm -f "$shim_file"; unset BASH_ENV' EXIT INT TERM HUP

    export BASH_ENV="$shim_file"

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
            failed=$(( failed + 1 ))
            continue
        fi

        {
            echo
            echo "── ${label} ──"
            # Child script inherits LOG_DIR, OUTPUT_DIR, PROJECT_ROOT, BASH_ENV via export
            bash "$SCRIPT_DIR/$script" 2>&1 || true
        } | tee -a "$report_file" | tee -a "$log_file"

        status_line ok "$label — complete"
        passed=$(( passed + 1 ))
    done

    # Explicit cleanup on clean exit — the trap above covers all other paths
    # (INT/TERM/HUP/crash), so this is a belt-and-suspenders safety call.
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