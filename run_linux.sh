#!/bin/bash
# CyberSec Toolkit - Linux Runner

set -e

# ─────────────────────────────────────────────────────────────
# Paths (absolute, single source of truth)
# ─────────────────────────────────────────────────────────────

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCRIPT_DIR="$BASE_DIR/scripts"
DASHBOARD_DIR="$BASE_DIR/dashboard"
LOG_DIR="$BASE_DIR/logs"
OUTPUT_DIR="$BASE_DIR/outputs"

WEB_RECON_DIR="$OUTPUT_DIR/web_recon"
NET_DIR="$OUTPUT_DIR/network"
FORENSIC_DIR="$OUTPUT_DIR/forensics"
SYSTEM_DIR="$OUTPUT_DIR/system"

TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
LOG_FILE="$LOG_DIR/run_$TIMESTAMP.log"

mkdir -p "$LOG_DIR" "$WEB_RECON_DIR" "$NET_DIR" "$FORENSIC_DIR" "$SYSTEM_DIR"

# Export for child scripts
export OUTPUT_DIR WEB_RECON_DIR NET_DIR FORENSIC_DIR SYSTEM_DIR

# ─────────────────────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   🛡 CyberSec Toolkit – Linux Runner 🛡               ║"
    echo "║   Network Security & Forensics Suite                ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────

log_message() {
    local level="$1"
    local msg="$2"
    echo "[$(date +"%F %T")] [$level] $msg" | tee -a "$LOG_FILE"
}

# ─────────────────────────────────────────────────────────────
# Script helpers
# ─────────────────────────────────────────────────────────────

check_script() {
    local name="$1"
    local path="$SCRIPT_DIR/${name}.sh"

    if [[ ! -f "$path" ]]; then
        echo -e "${RED}Missing script: $path${NC}"
        return 1
    fi

    [[ -x "$path" ]] || chmod +x "$path"
    return 0
}

execute_script() {
    local name="$1"
    local path="$SCRIPT_DIR/${name}.sh"

    echo -e "${GREEN}▶ Running: $name${NC}"
    log_message "INFO" "Started $name"

    if bash "$path" >>"$LOG_FILE" 2>&1; then
        log_message "SUCCESS" "$name completed"
    else
        log_message "ERROR" "$name failed"
    fi
}

# ─────────────────────────────────────────────────────────────
# Menu & utilities (requested)
# ─────────────────────────────────────────────────────────────

show_menu() {
    echo -e "${PURPLE}════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                MAIN MENU${NC}"
    echo -e "${PURPLE}════════════════════════════════════════════${NC}"
    echo "1) Secure System"
    echo "2) Detect Suspicious Net"
    echo "3) Revert Security"
    echo "4) Forensic Collection"
    echo "5) System Information"
    echo "6) Web Reconnaissance"
    echo "7) Launch Dashboard"
    echo "8) View Logs"
    echo "9) Run All Security"
    echo "10) Help"
    echo "0) Exit"
}

launch_dashboard() {
    [[ -f "$DASHBOARD_DIR/index.html" ]] || {
        echo -e "${RED}Dashboard not found${NC}"
        return
    }
    xdg-open "$DASHBOARD_DIR/index.html" >/dev/null 2>&1 &
    log_message "INFO" "Dashboard launched"
}

view_logs() {
    [[ -f "$LOG_FILE" ]] && tail -n 50 "$LOG_FILE" || echo "No logs yet"
}

run_all_security() {
    for s in secure_system detect_suspicious_net; do
        check_script "$s" && execute_script "$s"
    done
}

show_help() {
    echo "CyberSec Toolkit Runner"
    echo "Artifacts → outputs/"
    echo "Logs      → logs/"
}

# ─────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────

main() {
    show_banner
    log_message "INFO" "Runner started"

    while true; do
        show_menu
        read -p "Choice: " c
        echo ""
        case "$c" in
            1) check_script secure_system && execute_script secure_system ;;
            2) check_script detect_suspicious_net && execute_script detect_suspicious_net ;;
            3) check_script revert_security && execute_script revert_security ;;
            4) check_script forensic_collect && execute_script forensic_collect ;;
            5) check_script system_info && execute_script system_info ;;
            6) check_script web_recon && execute_script web_recon ;;
            7) launch_dashboard ;;
            8) view_logs ;;
            9) run_all_security ;;
            10) show_help ;;
            0) log_message "INFO" "Exiting"; exit 0 ;;
            *) echo -e "${RED}Invalid choice${NC}" ;;
        esac
        read -p "Press Enter to continue..."
        show_banner
    done
}

main "$@"
