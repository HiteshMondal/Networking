#!/bin/bash

set -o pipefail

# Networking & Cybersecurity Automation Toolkit
# Main control script
# /run.sh

# Root check
if [[ "$EUID" -ne 0 ]]; then
    echo ""
    echo "  [!] This script must be run with sudo or as root."
    echo "  [>] Run:  sudo $0"
    echo ""
    exit 1
fi

# Project root
export PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Source dependencies
source "$PROJECT_ROOT/config/settings.conf"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/scripts/run_script.sh"
source "$PROJECT_ROOT/tools/tools.sh"
source "$PROJECT_ROOT/dashboard/start_dashboard.sh"

# Directory setup
SCRIPT_DIR="$PROJECT_ROOT/scripts"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
TOOLS="$PROJECT_ROOT/tools"

mkdir -p "$LOG_DIR" "$OUTPUT_DIR"
touch "$LOG_DIR/main.log"

#  DISPLAY FUNCTIONS

# Main menu
show_main_menu() {
    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "MAIN MENU"
    echo -e "${BORDER}${border}${NC}"
    echo
    echo -e "  ${LABEL}SECURITY${NC}"
    echo -e "  ${GREEN}  1.${NC}  Run Security Scripts"
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
    echo -e "  ${LABEL}TOOLS${NC}"
    echo -e "  ${GREEN}  6.${NC}  Network Tools"
    echo
    echo -e "  ${RED}  0.${NC}  Exit"
    echo
    echo -e "${BORDER}${border}${NC}"
}

# Script selection menu
show_script_menu() {
    clear
    show_banner

    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "SECURITY SCRIPTS"
    echo -e "${BORDER}${border}${NC}"
    echo

    echo -e "  ${AMBER}Network Analysis${NC}"
    echo -e "  ${GREEN}  1.${NC}  Detect Suspicious Network Activity"
    echo

    echo -e "  ${AMBER}System Security${NC}"
    echo -e "  ${GREEN}  2.${NC}  Secure System"
    echo -e "  ${GREEN}  3.${NC}  Revert Security Changes"
    echo

    echo -e "  ${AMBER}Information Gathering${NC}"
    echo -e "  ${GREEN}  4.${NC}  System Information"
    echo

    echo -e "  ${AMBER}Forensics${NC}"
    echo -e "  ${GREEN}  5.${NC}  Forensic Data Collection"
    echo

    echo -e "  ${AMBER}Reconnaissance${NC}"
    echo -e "  ${GREEN}  6.${NC}  Web Reconnaissance"
    echo

    echo -e "  ${RED}  0.${NC}  Back to Main Menu"
    echo
    echo -e "${BORDER}${border}${NC}"
}

# View logs
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

    if [ "$(ls -A "$LOG_DIR" 2>/dev/null)" ]; then
        echo -e "  ${LABEL}Available log files:${NC}"
        echo
        ls -lht "$LOG_DIR" | head -n 11 | sed 's/^/  /'
        echo
        echo -e "  ${MUTED}$(printf '%*s' 46 '' | tr ' ' '-')${NC}"
        read -rp "$(echo -e "  ${PROMPT}[?] Enter filename to view, or 'q' to go back: ${NC}")" log_choice

        if [[ "$log_choice" != "q" ]] && [ -f "$LOG_DIR/$log_choice" ]; then
            less "$LOG_DIR/$log_choice"
        fi
    else
        echo -e "  ${MUTED}No logs found. Run some scripts first.${NC}"
    fi

    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

# Clean data
clean_data() {
    clear
    show_banner

    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "CLEAN LOGS & OUTPUT"
    echo -e "${BORDER}${border}${NC}"
    echo
    echo -e "  ${FAILURE}[!] WARNING: This will permanently delete all logs and output files!${NC}"
    echo
    echo -e "  ${MUTED}Log directory   : ${LOG_DIR}${NC}"
    echo -e "  ${MUTED}Output directory: ${OUTPUT_DIR}${NC}"
    echo

    read -rp "$(echo -e "  ${WARNING}[?] Are you sure? [yes/no]: ${NC}")" confirm

    if [[ "$confirm" == "yes" ]]; then
        rm -rf "$LOG_DIR"/* "$OUTPUT_DIR"/*
        echo
        log_success "Cleaned successfully."
    else
        echo
        log_info "Operation cancelled."
    fi

    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

# System info
show_system_info() {
    clear
    show_banner

    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "SYSTEM INFORMATION"
    echo -e "${BORDER}${border}${NC}"
    echo

    echo -e "  ${AMBER}Host${NC}"
    kv "  Operating System" "$(detect_os)"
    kv "  Hostname"         "$(hostname)"
    kv "  User"             "$(whoami)"
    kv "  Date"             "$(date '+%Y-%m-%d %H:%M:%S')"
    kv "  Uptime"           "$(uptime -p 2>/dev/null || uptime)"
    echo

    echo -e "  ${AMBER}Toolkit${NC}"
    kv "  Log files"        "$(find "$LOG_DIR"    -type f 2>/dev/null | wc -l)"
    kv "  Output files"     "$(find "$OUTPUT_DIR" -type f 2>/dev/null | wc -l)"
    kv "  Scripts"          "$(find "$SCRIPT_DIR" -type f 2>/dev/null | wc -l)"
    echo

    echo -e "  ${AMBER}Dashboard${NC}"
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kv "  Status" "$(echo -e "${SUCCESS}Running${NC} (PID: ${pid})")"
        else
            kv "  Status" "$(echo -e "${FAILURE}Not running (stale PID)${NC}")"
        fi
    else
        kv "  Status" "$(echo -e "${MUTED}Not running${NC}")"
    fi

    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

#  CLEANUP
cleanup() {
    echo
    log_info "Toolkit shutting down..."
}

trap cleanup EXIT

#  MAIN LOOP
main() {
    if [ ! -d "$PROJECT_ROOT/lib" ]; then
        echo -e "${FAILURE}[!] Error: Required libraries not found.${NC}"
        echo -e "${WARNING}[~] Please run the setup steps from the documentation.${NC}"
        exit 1
    fi

    while true; do
        clear
        show_banner
        show_main_menu

        echo -e -n "  "
        read -rp "$(echo -e "${PROMPT}[?] Enter your choice: ${NC}")" choice

        echo

        case $choice in
            1)
                while true; do
                    show_script_menu
                    echo -e -n "  "
                    read -rp "$(echo -e "${PROMPT}[?] Enter your choice: ${NC}")" script_choice

                    if [[ "$script_choice" == "0" ]]; then
                        break
                    fi

                    run_script "$script_choice"
                done
                ;;
            2) start_dashboard_main ;;
            3) view_logs ;;
            4) clean_data ;;
            5) show_system_info ;;
            6) tools ;;
            7)
                source "$PROJECT_ROOT/dashboard/start_dashboard.sh"
                stop_dashboard
                echo
                read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
                ;;
            0)
                clear
                show_banner
                echo -e "  ${SUCCESS}[+] Thank you for using the Networking & Cybersecurity Toolkit!${NC}"
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