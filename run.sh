#!/bin/bash

set -o pipefail

# Networking & Cybersecurity Automation Toolkit
# Main control script
# /run.sh

# Root check
if [[ $EUID -ne 0 ]]; then
    echo ""
    echo "  [!] This script must be run with sudo or as root."
    echo "  [>] Run: sudo $0"
    echo ""
    exit 1
fi

# Project root
export PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Source dependencies
source "$PROJECT_ROOT/config/settings.conf"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/modules/run_modules.sh"
source "$PROJECT_ROOT/network_lab/network_lab.sh"
source "$PROJECT_ROOT/dashboard/start_dashboard.sh"

# Directory setup
MODULES_DIR="$PROJECT_ROOT/modules"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
TARGET=""

mkdir -p "$LOG_DIR" "$OUTPUT_DIR"
touch "$LOG_DIR/main.log"

# MAIN MENU
show_main_menu() {
    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "MAIN MENU"
    echo -e "${BORDER}${border}${NC}"
    echo
    echo -e "  ${MUTED}Current Target:${NC} ${GREEN}${TARGET:-Not Set}${NC}"
    echo
    echo -e "  ${LABEL}SECURITY${NC}"
    echo -e "  ${GREEN}  1.${NC}  Run Security Modules"
    echo
    echo -e "  ${LABEL}MONITORING${NC}"
    echo -e "  ${GREEN}  2.${NC}  View Dashboard"
    echo -e "  ${GREEN}  7.${NC}  Stop Dashboard"
    echo
    echo -e "  ${LABEL}SYSTEM${NC}"
    echo -e "  ${GREEN}  3.${NC}  View Recent Logs"
    echo -e "  ${GREEN}  4.${NC}  Clean Logs & Output"
    echo -e "  ${GREEN}  5.${NC}  System Information"
    echo
    echo -e "  ${LABEL}NETWORK LAB${NC}"
    echo -e "  ${GREEN}  6.${NC}  Network Lab"
    echo
    echo -e "  ${RED}  0.${NC}  Exit"
    echo
    echo -e "${BORDER}${border}${NC}"
}

# CENTRAL TARGET
set_target() {
    clear
    show_banner

    echo -e "${LABEL}TARGET CONFIGURATION${NC}"
    echo

    read -rp "$(echo -e "${PROMPT}[?] Enter target (domain/IP/URL): ${NC}")" TARGET

    if [[ -z "$TARGET" ]]; then
        log_error "Target cannot be empty"
        sleep 1
        return
    fi

    log_success "Target set to: $TARGET"
    sleep 1
}

# VIEW LOGS
view_logs() {
    clear
    show_banner

    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "RECENT LOGS"
    echo -e "${BORDER}${border}${NC}"
    echo

    if [[ -n "$(ls -A "$LOG_DIR" 2>/dev/null)" ]]; then

        echo -e "  ${LABEL}Available log files:${NC}"
        echo
        ls -lht "$LOG_DIR" | head -n 11 | sed 's/^/  /'
        echo
        echo -e "  ${MUTED}$(printf '%*s' 46 '' | tr ' ' '-')${NC}"
        read -rp "$(echo -e "  ${PROMPT}[?] Enter filename to view, or 'q' to go back: ${NC}")" log_choice

        if [[ "$log_choice" != "q" && -f "$LOG_DIR/$log_choice" ]]; then
            less "$LOG_DIR/$log_choice"
        fi
    else
        echo -e "  ${MUTED}No logs found. Run some modules first.${NC}"
    fi

    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

# CLEAN DATA
clean_data() {
    clear
    show_banner

    echo -e "  ${FAILURE}[!] WARNING: This will permanently delete all logs and output files!"
    echo

    read -rp "$(echo -e "  ${WARNING}[?] Are you sure? [yes/no]: ${NC}")" confirm

    if [[ "$confirm" == "yes" ]]; then
        rm -rf "${LOG_DIR:?}/"* "${OUTPUT_DIR:?}/"*
        log_success "Cleaned successfully."
    else
        log_info "Operation cancelled."
    fi

    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

# SYSTEM INFO
show_system_info() {
    clear
    show_banner

    echo -e "  ${AMBER}Host${NC}"
    kv "  Operating System" "$(detect_os)"
    kv "  Hostname" "$(hostname)"
    kv "  User" "$(whoami)"
    kv "  Date" "$(date '+%Y-%m-%d %H:%M:%S')"
    kv "  Uptime" "$(uptime -p 2>/dev/null || uptime)"
    echo
    echo -e "  ${AMBER}Toolkit${NC}"

    kv "  Log files" "$(find "$LOG_DIR" -type f 2>/dev/null | wc -l)"
    kv "  Output files" "$(find "$OUTPUT_DIR" -type f 2>/dev/null | wc -l)"
    kv "  Modules" "$(find "$MODULES_DIR" -name '*.sh' ! -name 'run_modules.sh' | wc -l)"

    echo

    if [[ -f "$PID_FILE" ]]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kv "  Dashboard" "${SUCCESS}Running${NC} (PID: ${pid})"
        else
            kv "  Dashboard" "${FAILURE}Not running (stale PID)"
        fi
    else
        kv "  Dashboard" "${MUTED}Not running${NC}"
    fi
    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

# CLEANUP
cleanup() {
    echo
    log_info "Toolkit shutting down..."
}

trap cleanup EXIT INT TERM

# MAIN LOOP
main() {
    while true; do
        clear
        show_banner
        show_main_menu

        read -rp "$(echo -e "  ${PROMPT}[?] Enter your choice: ${NC}")" choice
        echo

        case $choice in
            1)
            if [[ -z "$TARGET" ]]; then
                set_target
            fi    
                while true; do
                    show_modules_menu
                    read -rp "$(echo -e "  ${PROMPT}[?] Enter your choice: ${NC}")" module_choice

                    [[ "$module_choice" == "0" ]] && break

                    run_modules "$module_choice"
                done
                ;;
            2) start_dashboard_main ;;
            3) view_logs ;;
            4) clean_data ;;
            5) show_system_info ;;
            6) network_lab ;;
            7) stop_dashboard ;;
            0)
                clear
                show_banner
                echo -e "  ${SUCCESS}[+] Thank you for using the Networking & Cybersecurity Toolkit!"
                echo
                exit 0
                ;;
            *)
                log_error "Invalid choice. Please try again."
                sleep 1
                ;;
        esac
    done
}

main