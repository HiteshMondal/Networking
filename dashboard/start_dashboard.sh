#!/bin/bash

# /dashboard/start_dashboard.sh
# Dashboard launcher with PID management

# Path resolution
DASHBOARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$DASHBOARD_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

# Config validation
: "${DASHBOARD_PORT:=8080}"   # sensible default if settings.conf omits it
if [[ -z "$PID_FILE" ]]; then
    PID_FILE="$PROJECT_ROOT/logs/dashboard.pid"
fi

# Compatibility shim
command_exists() { cmd_exists "$1"; }

safe_cd() {
    local target="$1"
    if [[ ! -d "$target" ]]; then
        log_error "Directory does not exist: $target"
        return 1
    fi
    cd "$target" || { log_error "Cannot cd into: $target"; return 1; }
}

#  HELPERS

# Return 0 if the dashboard process recorded in PID_FILE is alive.
is_dashboard_running() {
    [[ -f "$PID_FILE" ]] || return 1
    local pid
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        return 0
    else
        rm -f "$PID_FILE"   # stale PID file
        return 1
    fi
}

# Block until the TCP port is accepting connections or timeout expires.
# Returns 0 if port becomes reachable, 1 if timed out.
_wait_for_port() {
    local port="$1"
    local timeout="${2:-8}"
    local elapsed=0
    while (( elapsed < timeout )); do
        # Use /dev/tcp to probe the port — no extra tools required.
        if bash -c ">/dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        (( elapsed++ ))
    done
    return 1
}

#  STOP

stop_dashboard() {
    if [[ ! -f "$PID_FILE" ]]; then
        log_warning "Dashboard not running (no PID file found)"
        return 0
    fi

    local pid
    pid=$(cat "$PID_FILE")

    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$PID_FILE"
        log_warning "Dashboard not running (stale PID file removed)"
        return 0
    fi

    log_info "Stopping dashboard (PID: $pid)..."
    kill "$pid"

    local waited=0
    while kill -0 "$pid" 2>/dev/null && (( waited < 10 )); do
        sleep 0.5
        (( waited++ ))
    done

    if kill -0 "$pid" 2>/dev/null; then
        log_warning "Process did not exit after SIGTERM — sending SIGKILL..."
        kill -9 "$pid" 2>/dev/null
        sleep 0.5
    fi

    rm -f "$PID_FILE"
    log_success "Dashboard stopped"
}

#  START

start_dashboard() {
    clear
    show_banner
    echo -e "${YELLOW}Starting Dashboard...${NC}\n"

    # Ensure log directory exists before any logging to files.
    mkdir -p "$LOG_DIR"

    # Change into the dashboard directory.
    if ! safe_cd "$DASHBOARD_DIR"; then
        log_error "Cannot access dashboard directory: $DASHBOARD_DIR"
        read -rp "$(echo -e "\nPress Enter to continue...")"
        return 1
    fi

    # Verify server file exists.
    if [[ ! -f "server.py" ]]; then
        log_error "server.py not found in $DASHBOARD_DIR"
        echo -e "${YELLOW}Expected: $DASHBOARD_DIR/server.py${NC}"
        read -rp "$(echo -e "\nPress Enter to continue...")"
        return 1
    fi

    # Detect Python interpreter.
    local python_cmd=""
    if command_exists python3; then
        python_cmd="python3"
    elif command_exists python; then
        # Guard against 'python' pointing at Python 2 on some systems.
        local py_ver
        py_ver=$(python --version 2>&1 | grep -oP '\d+' | head -1)
        if [[ "$py_ver" -ge 3 ]]; then
            python_cmd="python"
        else
            log_error "Python 3 is required but only Python 2 was found."
            read -rp "$(echo -e "\nPress Enter to continue...")"
            return 1
        fi
    else
        log_error "Python is not installed."
        log_info "Install with: sudo apt install python3"
        echo -e "${YELLOW}Attempting to open static dashboard instead...${NC}"
        if command_exists xdg-open; then
            xdg-open "index.html" 2>/dev/null &
        elif command_exists open; then
            open "index.html" 2>/dev/null &
        fi
        read -rp "$(echo -e "\nPress Enter to continue...")"
        return 1
    fi

    # Already running — no need to start again.
    if is_dashboard_running; then
        log_success "Dashboard already running at http://localhost:${DASHBOARD_PORT}"
    else
        # Check if the port is already bound by a different process.
        if ss -tlnp 2>/dev/null | grep -q ":${DASHBOARD_PORT} " || \
           netstat -an 2>/dev/null | grep -q ":${DASHBOARD_PORT} "; then
            log_warning "Port ${DASHBOARD_PORT} is already in use by another process."
            echo -e "${YELLOW}Stop the conflicting process or change DASHBOARD_PORT in config/settings.conf${NC}"
            echo -e "  Check: http://localhost:${DASHBOARD_PORT}"
            read -rp "$(echo -e "\nPress Enter to continue...")"
            return 1
        fi

        # Launch the server in the background.
        log_info "Starting dashboard server on port ${DASHBOARD_PORT}..."
        nohup "$python_cmd" server.py > "$LOG_DIR/dashboard.log" 2>&1 &
        local pid=$!
        echo "$pid" > "$PID_FILE"
        log_info "Waiting for server to become reachable on port ${DASHBOARD_PORT}..."
        if _wait_for_port "$DASHBOARD_PORT" 8; then
            log_success "Dashboard started and reachable (PID: $pid)"
        else
            # Server process may still be alive but not listening — check both.
            if kill -0 "$pid" 2>/dev/null; then
                log_error "Server process is running (PID: $pid) but not accepting connections."
            else
                log_error "Server process exited unexpectedly."
            fi
            echo -e "${YELLOW}=== dashboard.log ===${NC}"
            cat "$LOG_DIR/dashboard.log" 2>/dev/null
            echo -e "${YELLOW}====================${NC}"
            rm -f "$PID_FILE"
            read -rp "$(echo -e "\nPress Enter to continue...")"
            return 1
        fi
    fi

    # Open in browser.
    local url="http://localhost:${DASHBOARD_PORT}"
    log_info "Opening dashboard at $url"

    if command_exists xdg-open; then
        xdg-open "$url" 2>/dev/null &
    elif command_exists open; then
        open "$url" 2>/dev/null &
    else
        echo -e "${YELLOW}Browser not detected — open manually: ${CYAN}${url}${NC}"
    fi

    echo
    echo -e "  ${SUCCESS}Dashboard running:${NC} ${CYAN}${url}${NC}"
    echo -e "  ${MUTED}Logs:${NC}             ${LOG_DIR}/dashboard.log"
    echo -e "  ${MUTED}Stop:${NC}             select option 7 from the main menu"
    read -rp "$(echo -e "\nPress Enter to return to menu...")"
}

#  ENTRY POINT

start_dashboard_main() {
    start_dashboard
}