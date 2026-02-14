#!/bin/bash

# /dashboard/start_dashboard.sh
# Dashboard launcher with PID management

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

# Check if dashboard is running
is_dashboard_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0  # Running
        else
            rm -f "$PID_FILE"  # Stale PID file
            return 1
        fi
    fi
    return 1
}

# Stop dashboard
stop_dashboard() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping dashboard (PID: $pid)..."
            kill "$pid"
            rm -f "$PID_FILE"
            log_success "Dashboard stopped"
        else
            rm -f "$PID_FILE"
            log_warning "Dashboard not running (stale PID file removed)"
        fi
    else
        log_warning "Dashboard not running"
    fi
}

# Start dashboard
start_dashboard() {
    clear
    show_banner
    echo -e "${YELLOW}Starting Dashboard...${NC}\n"
    
    # Change to dashboard directory
    if ! safe_cd "$SCRIPT_DIR"; then
        log_error "Cannot access dashboard directory"
        echo -e "\nPress Enter to continue..."
        read
        return 1
    fi
    
    # Detect Python
    local python_cmd=""
    if command_exists python3; then
        python_cmd="python3"
    elif command_exists python; then
        python_cmd="python"
    else
        log_error "Python is not installed. Opening static dashboard..."
        xdg-open "index.html" 2>/dev/null || open "index.html" || start "index.html"
        echo -e "\nPress Enter to continue..."
        read
        return 1
    fi
    
    # Check if already running
    if is_dashboard_running; then
        log_success "Dashboard already running at http://localhost:$DASHBOARD_PORT"
    else
        # Check if port is in use by another process
        if ss -ltn 2>/dev/null | grep -q ":$DASHBOARD_PORT " || \
           netstat -an 2>/dev/null | grep -q ":$DASHBOARD_PORT "; then
            log_warning "Port $DASHBOARD_PORT is in use by another process"
            echo -e "${YELLOW}Try stopping existing processes or changing DASHBOARD_PORT in config/settings.conf${NC}"
            echo -e "\nPress Enter to continue..."
            read
            return 1
        fi
        
        # Start server
        log_info "Starting dashboard server on port $DASHBOARD_PORT..."
        nohup $python_cmd server.py > "$LOG_DIR/dashboard.log" 2>&1 &
        local pid=$!
        echo $pid > "$PID_FILE"
        
        # Wait for server to start
        sleep 2
        
        # Verify it started
        if kill -0 "$pid" 2>/dev/null; then
            log_success "Dashboard started (PID: $pid)"
        else
            log_error "Failed to start dashboard. Check $LOG_DIR/dashboard.log"
            rm -f "$PID_FILE"
            echo -e "\nPress Enter to continue..."
            read
            return 1
        fi
    fi
    
    # Open in browser
    local url="http://localhost:$DASHBOARD_PORT"
    log_info "Opening dashboard at $url"
    
    if command_exists xdg-open; then
        xdg-open "$url" 2>/dev/null
    elif command_exists open; then
        open "$url" 2>/dev/null
    elif command_exists start; then
        start "$url" 2>/dev/null
    else
        echo -e "${YELLOW}Please open manually: $url${NC}"
    fi
    
    echo
    echo -e "${CYAN}Dashboard is running in background${NC}"
    echo -e "${YELLOW}To stop: use option 9 from main menu or run: kill \$(cat $PID_FILE)${NC}"
    echo -e "\nPress Enter to return to menu..."
    read
}

# Main entry point
start_dashboard_main() {
    start_dashboard
}
