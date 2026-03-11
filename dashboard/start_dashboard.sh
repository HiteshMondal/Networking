#!/usr/bin/env bash

# /dashboard/start_dashboard.sh
# Dashboard launcher with PID management

# Bash version guard
if [[ -z "${BASH_VERSION}" ]]; then
    echo "Error: This script requires Bash. Invoke as: bash start_dashboard.sh" >&2
    exit 1
fi

# Double-source guard (NOT exported)
[[ -n "${_START_DASHBOARD_LOADED:-}" ]] && return 0
_START_DASHBOARD_LOADED=1

# Path resolution
DASHBOARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${DASHBOARD_DIR}")"
LOG_DIR="${PROJECT_ROOT}/logs"
OUTPUT_DIR="${PROJECT_ROOT}/output"

# Source dependencies
_source_or_fail() {
    local file="$1"
    if [[ ! -f "${file}" ]]; then
        echo "Error: Required file missing: ${file}" >&2
        return 1
    fi
    # shellcheck source=/dev/null
    source "${file}"
}

_source_or_fail "${PROJECT_ROOT}/lib/colors.sh"    || return 1
_source_or_fail "${PROJECT_ROOT}/lib/functions.sh" || return 1
_source_or_fail "${PROJECT_ROOT}/config/settings.conf" || {
    log_warning "settings.conf not found; using built-in defaults."
}

# Configuration defaults
: "${DASHBOARD_PORT:=8000}"
PID_FILE="${PID_FILE:-${PROJECT_ROOT}/logs/dashboard.pid}"

#  HELPERS
is_dashboard_running() {
    [[ -f "${PID_FILE}" ]] || return 1
    local pid
    pid=$(< "${PID_FILE}")
    if kill -0 "${pid}" 2>/dev/null; then
        return 0
    else
        rm -f "${PID_FILE}"
        return 1
    fi
}

_wait_for_port() {
    local port="${1}"
    local timeout="${2:-8}"
    local i=0
    while (( i < timeout )); do
        if bash -c ">/dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        (( i++ ))
    done
    return 1
}

_port_in_use() {
    local port="${1}"
    if cmd_exists ss; then
        ss -tlnp 2>/dev/null | grep -qE ":${port}(\s|$)"
        return $?
    elif cmd_exists netstat; then
        netstat -an 2>/dev/null | grep -qE ":${port}(\s|$)"
        return $?
    fi
    return 1
}

# Shared header
_dashboard_header() {
    local title="${1:-DASHBOARD}"
    clear
    show_banner

    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "$title"
    echo -e "${BORDER}${border}${NC}"
    echo
}

#  STOP
stop_dashboard() {
    _dashboard_header "STOP DASHBOARD"

    if [[ ! -f "${PID_FILE}" ]]; then
        log_warning "Dashboard not running (no PID file found)."
        return 0
    fi

    local pid
    pid=$(< "${PID_FILE}")

    if ! kill -0 "${pid}" 2>/dev/null; then
        rm -f "${PID_FILE}"
        log_warning "Dashboard not running (stale PID file removed)."
        return 0
    fi

    log_info "Stopping dashboard (PID: ${pid})..."
    kill "${pid}"

    local waited=0
    while kill -0 "${pid}" 2>/dev/null && (( waited < 20 )); do
        printf "\r  ${MUTED}[>] Waiting for process to exit... %ds${NC}" "$waited"
        sleep 0.5
        (( waited++ ))
    done
    printf "\r%-50s\r" ""

    if kill -0 "${pid}" 2>/dev/null; then
        log_warning "Process did not exit gracefully — sending SIGKILL..."
        kill -9 "${pid}" 2>/dev/null
        sleep 0.5
    fi

    rm -f "${PID_FILE}"
    log_success "Dashboard stopped."
}

#  START
start_dashboard() {
    _dashboard_header "START DASHBOARD"

    mkdir -p "${LOG_DIR}"

    # ── Verify dashboard files ─────────────────────────────────
    if [[ ! -d "${DASHBOARD_DIR}" ]]; then
        log_error "Dashboard directory not found: ${DASHBOARD_DIR}"
        echo
        read -r -p "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
        return 1
    fi

    if [[ ! -f "${DASHBOARD_DIR}/server.py" ]]; then
        log_error "server.py not found in: ${DASHBOARD_DIR}"
        echo
        read -r -p "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
        return 1
    fi

    # Detect Python 3
    local python_cmd=""
    if cmd_exists python3; then
        python_cmd="python3"
    elif cmd_exists python; then
        local py_major
        py_major=$(python --version 2>&1 | grep -oP '\d+' | head -1)
        if [[ "${py_major}" -ge 3 ]]; then
            python_cmd="python"
        else
            log_error "Python 3 is required; only Python ${py_major} was found."
            echo
            read -r -p "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
            return 1
        fi
    else
        log_error "Python is not installed."
        log_info  "Install with: sudo apt install python3"
        echo
        echo -e "  ${MUTED}[>] Attempting to open static dashboard instead...${NC}"
        if cmd_exists xdg-open; then
            xdg-open "${DASHBOARD_DIR}/index.html" 2>/dev/null &
        elif cmd_exists open; then
            open "${DASHBOARD_DIR}/index.html" 2>/dev/null &
        fi
        echo
        read -r -p "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
        return 1
    fi

    # Check already running
    if is_dashboard_running; then
        log_success "Dashboard already running at http://localhost:${DASHBOARD_PORT}"
    else
        # Port conflict check
        if _port_in_use "${DASHBOARD_PORT}"; then
            log_warning "Port ${DASHBOARD_PORT} is already in use by another process."
            log_info    "Change DASHBOARD_PORT in config/settings.conf."
            echo -e "  ${MUTED}  URL: http://localhost:${DASHBOARD_PORT}${NC}"
            echo
            read -r -p "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
            return 1
        fi

        # Launch server
        log_info "Starting dashboard server on port ${DASHBOARD_PORT}..."
        DASHBOARD_PORT="${DASHBOARD_PORT}" \
            nohup "${python_cmd}" "${DASHBOARD_DIR}/server.py" \
            > "${LOG_DIR}/dashboard.log" 2>&1 &
        local pid=$!

        sleep 0.2
        if ! kill -0 "${pid}" 2>/dev/null; then
            log_error "Server process exited immediately."
            echo
            echo -e "  ${AMBER}=== dashboard.log ===${NC}"
            cat "${LOG_DIR}/dashboard.log" 2>/dev/null | sed 's/^/  /'
            echo -e "  ${AMBER}====================${NC}"
            return 1
        fi

        echo "${pid}" > "${PID_FILE}"

        log_info "Waiting for server on port ${DASHBOARD_PORT}..."

        # Animated wait
        local spin='/-\|'
        local si=0
        local ready=0
        for (( i=0; i<8; i++ )); do
            printf "\r  ${CYAN}${spin:$((si % 4)):1}${NC}  ${MUTED}Connecting to port ${DASHBOARD_PORT}...${NC}   "
            (( si++ ))
            sleep 0.5
            if bash -c ">/dev/tcp/127.0.0.1/${DASHBOARD_PORT}" 2>/dev/null; then
                ready=1
                break
            fi
        done
        printf "\r%-55s\r" ""

        if [[ $ready -eq 1 ]]; then
            log_success "Dashboard is live and accepting connections (PID: ${pid})."
        else
            if kill -0 "${pid}" 2>/dev/null; then
                log_error "Server process is alive but not accepting connections on port ${DASHBOARD_PORT}."
            else
                log_error "Server process exited unexpectedly."
                rm -f "${PID_FILE}"
            fi
            echo
            echo -e "  ${AMBER}=== dashboard.log ===${NC}"
            cat "${LOG_DIR}/dashboard.log" 2>/dev/null | sed 's/^/  /'
            echo -e "  ${AMBER}====================${NC}"
            echo
            read -r -p "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
            return 1
        fi
    fi

    # Open in browser
    local url="http://localhost:${DASHBOARD_PORT}"
    log_info "Opening dashboard: ${url}"

    if cmd_exists xdg-open; then
        xdg-open "${url}" 2>/dev/null &
    elif cmd_exists open; then
        open "${url}" 2>/dev/null &
    else
        echo -e "  ${WARNING}[~] No browser detected — open manually.${NC}"
    fi

    echo
    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '-')
    echo -e "  ${DARK_GRAY}${border}${NC}"
    kv "  Dashboard" "${url}"
    kv "  Log file"  "${LOG_DIR}/dashboard.log"
    kv "  Stop"      "Select option 7 from the main menu"
    echo -e "  ${DARK_GRAY}${border}${NC}"
    echo

    read -r -p "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}  ")"
}

#  ENTRY POINT
start_dashboard_main() {
    start_dashboard
}