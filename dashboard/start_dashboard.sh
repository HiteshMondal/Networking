#!/usr/bin/env bash

# /dashboard/start_dashboard.sh
# Dashboard launcher with PID management


# Bash version guard
if [[ -z "${BASH_VERSION}" ]]; then
    echo "Error: This script requires Bash. Invoke as: bash start_dashboard.sh" >&2
    exit 1
fi

# Double-source guard (NOT exported — see lib/colors.sh for rationale)
[[ -n "${_START_DASHBOARD_LOADED}" ]] && return 0
_START_DASHBOARD_LOADED=1

# ── Path resolution
DASHBOARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${DASHBOARD_DIR}")"
LOG_DIR="${PROJECT_ROOT}/logs"
OUTPUT_DIR="${PROJECT_ROOT}/output"

# Source dependencies with explicit guards
_source_or_fail() {
    local file="$1"
    # shellcheck source=/dev/null
    if [[ ! -f "${file}" ]]; then
        echo "Error: Required file missing: ${file}" >&2
        return 1
    fi
    source "${file}"
}

_source_or_fail "${PROJECT_ROOT}/lib/colors.sh"    || return 1
_source_or_fail "${PROJECT_ROOT}/lib/functions.sh" || return 1
_source_or_fail "${PROJECT_ROOT}/config/settings.conf" || {
    # settings.conf is not critical — warn but continue with defaults.
    log_warning "settings.conf not found; using built-in defaults."
}

#  Configuration defaults
# Use := so a value already exported by settings.conf or the parent shell
# is never overwritten.
: "${DASHBOARD_PORT:=8000}"

# PID_FILE: use :- (read-only default) so we never silently clobber a value
# from settings.conf, but also never leave it empty.
PID_FILE="${PID_FILE:-${PROJECT_ROOT}/logs/dashboard.pid}"

# Helpers

# Return 0 if the process recorded in PID_FILE is alive; clean up stale file.
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
    local timeout="${2:-8}"   # iterations × 0.5 s = effective seconds
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

# Return 0 if $1 is already bound to a TCP port.
_port_in_use() {
    local port="${1}"
    # Use word-boundary anchors so port 8000 does not match 18000 / 8000x.
    if cmd_exists ss; then
        ss -tlnp 2>/dev/null | grep -qE ":${port}(\s|$)"
        return $?
    elif cmd_exists netstat; then
        netstat -an 2>/dev/null | grep -qE ":${port}(\s|$)"
        return $?
    fi
    return 1  # can't determine — assume not in use
}

# Stop
stop_dashboard() {
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

    log_info "Stopping dashboard (PID: ${pid})…"
    kill "${pid}"

    local waited=0
    while kill -0 "${pid}" 2>/dev/null && (( waited < 20 )); do
        sleep 0.5
        (( waited++ ))
    done

    if kill -0 "${pid}" 2>/dev/null; then
        log_warning "Process did not exit after SIGTERM — sending SIGKILL…"
        kill -9 "${pid}" 2>/dev/null
        sleep 0.5
    fi

    rm -f "${PID_FILE}"
    log_success "Dashboard stopped."
}

# Start
start_dashboard() {
    clear
    show_banner
    echo -e "${YELLOW}Starting Dashboard…${NC}\n"

    mkdir -p "${LOG_DIR}"

    # Verify dashboard directory and server script exist.
    if [[ ! -d "${DASHBOARD_DIR}" ]]; then
        log_error "Dashboard directory not found: ${DASHBOARD_DIR}"
        read -r -p "$(echo -e "\nPress Enter to continue…")"
        return 1
    fi

    if [[ ! -f "${DASHBOARD_DIR}/server.py" ]]; then
        log_error "server.py not found in: ${DASHBOARD_DIR}"
        read -r -p "$(echo -e "\nPress Enter to continue…")"
        return 1
    fi

    # Detect Python 3.
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
            read -r -p "$(echo -e "\nPress Enter to continue…")"
            return 1
        fi
    else
        log_error "Python is not installed."
        log_info "Install with: sudo apt install python3"

        # Fallback: open the static HTML directly.
        echo -e "${YELLOW}Attempting to open static dashboard instead…${NC}"
        if cmd_exists xdg-open; then
            xdg-open "${DASHBOARD_DIR}/index.html" 2>/dev/null &
        elif cmd_exists open; then
            open "${DASHBOARD_DIR}/index.html" 2>/dev/null &
        fi
        read -r -p "$(echo -e "\nPress Enter to continue…")"
        return 1
    fi

    # Check if already running.
    if is_dashboard_running; then
        log_success "Dashboard already running at http://localhost:${DASHBOARD_PORT}"
    else
        # Check if the port is already bound by something else.
        if _port_in_use "${DASHBOARD_PORT}"; then
            log_warning "Port ${DASHBOARD_PORT} is already in use by another process."
            log_info "Change DASHBOARD_PORT in config/settings.conf to use a different port."
            echo -e "  Current: http://localhost:${DASHBOARD_PORT}"
            read -r -p "$(echo -e "\nPress Enter to continue…")"
            return 1
        fi

        # Launch the server.
        log_info "Starting dashboard server on port ${DASHBOARD_PORT}…"
        # Pass the configured port to the server via environment variable.
        DASHBOARD_PORT="${DASHBOARD_PORT}" \
            nohup "${python_cmd}" "${DASHBOARD_DIR}/server.py" \
            > "${LOG_DIR}/dashboard.log" 2>&1 &
        local pid=$!

        # Verify the process actually started before writing the PID file.
        sleep 0.2
        if ! kill -0 "${pid}" 2>/dev/null; then
            log_error "Server process exited immediately."
            echo -e "${YELLOW}=== dashboard.log ===${NC}"
            cat "${LOG_DIR}/dashboard.log" 2>/dev/null
            echo -e "${YELLOW}====================${NC}"
            return 1
        fi

        echo "${pid}" > "${PID_FILE}"

        log_info "Waiting for server on port ${DASHBOARD_PORT} (up to 4 s)…"
        if _wait_for_port "${DASHBOARD_PORT}" 8; then
            log_success "Dashboard is up and accepting connections (PID: ${pid})."
        else
            if kill -0 "${pid}" 2>/dev/null; then
                log_error "Server process is alive (PID: ${pid}) but not accepting connections."
            else
                log_error "Server process exited unexpectedly."
                rm -f "${PID_FILE}"
            fi
            echo -e "${YELLOW}=== dashboard.log ===${NC}"
            cat "${LOG_DIR}/dashboard.log" 2>/dev/null
            echo -e "${YELLOW}====================${NC}"
            read -r -p "$(echo -e "\nPress Enter to continue…")"
            return 1
        fi
    fi

    # Open in browser.
    local url="http://localhost:${DASHBOARD_PORT}"
    log_info "Opening dashboard at ${url}"

    if cmd_exists xdg-open; then
        xdg-open "${url}" 2>/dev/null &
    elif cmd_exists open; then
        open "${url}" 2>/dev/null &
    else
        echo -e "${YELLOW}No browser detected — open manually: ${CYAN}${url}${NC}"
    fi

    echo
    echo -e "  ${SUCCESS}Dashboard:${NC}  ${CYAN}${url}${NC}"
    echo -e "  ${MUTED}Log file:${NC}   ${LOG_DIR}/dashboard.log"
    echo -e "  ${MUTED}Stop:${NC}       select option 7 from the main menu"
    read -r -p "$(echo -e "\nPress Enter to return to menu…")"
}

# Entry point
start_dashboard_main() {
    start_dashboard
}