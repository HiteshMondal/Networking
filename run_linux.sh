#!/bin/bash

# CyberSec Toolkit - Linux Runner
# Centralized execution script for all security tools

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="../scripts"
LOG_DIR="../logs"
DASHBOARD_DIR="../dashboard"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$LOG_DIR/run_$TIMESTAMP.log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Banner
function show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║        🛡️  CyberSec Toolkit - Linux Runner 🛡️             ║"
    echo "║                                                            ║"
    echo "║           Network Security & Forensics Suite               ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# Logging function
function log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Check if script exists
function check_script() {
    local script_name=$1
    local script_path="$SCRIPT_DIR/${script_name}.sh"
    
    if [ ! -f "$script_path" ]; then
        echo -e "${RED}Error: Script not found: $script_path${NC}"
        return 1
    fi
    
    if [ ! -x "$script_path" ]; then
        echo -e "${YELLOW}Making script executable: $script_path${NC}"
        chmod +x "$script_path"
    fi
    
    return 0
}

# Execute script with logging
function execute_script() {
    local script_name=$1
    local script_path="$SCRIPT_DIR/${script_name}.sh"
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}▶ Executing: $script_name${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    log_message "INFO" "Starting execution of $script_name"
    
    # Execute the script
    if bash "$script_path" 2>&1 | tee -a "$LOG_FILE"; then
        log_message "SUCCESS" "$script_name completed successfully"
        echo ""
        echo -e "${GREEN}✓ Script completed successfully${NC}"
        return 0
    else
        log_message "ERROR" "$script_name failed with exit code $?"
        echo ""
        echo -e "${RED}✗ Script failed${NC}"
        return 1
    fi
}

# Menu functions
function show_menu() {
    echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    MAIN MENU${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}Security Tools:${NC}"
    echo "  1) Secure System           - Harden system security"
    echo "  2) Detect Suspicious Net   - Monitor network activity"
    echo "  3) Revert Security         - Restore original settings"
    echo ""
    echo -e "${GREEN}Forensic Tools:${NC}"
    echo "  4) Forensic Collection     - Collect system artifacts"
    echo "  5) System Information      - Gather system info"
    echo ""
    echo -e "${GREEN}Reconnaissance:${NC}"
    echo "  6) Web Reconnaissance      - Web-based recon"
    echo ""
    echo -e "${GREEN}Dashboard & Utilities:${NC}"
    echo "  7) Launch Dashboard        - Open web dashboard"
    echo "  8) View Logs              - Display execution logs"
    echo "  9) Run All Security       - Execute all security tools"
    echo "  10) Help                  - Show help information"
    echo ""
    echo -e "${RED}  0) Exit${NC}"
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

# Launch web dashboard
function launch_dashboard() {
    echo -e "${CYAN}Launching Web Dashboard...${NC}"
    
    if [ ! -f "$DASHBOARD_DIR/index.html" ]; then
        echo -e "${RED}Error: Dashboard not found at $DASHBOARD_DIR/index.html${NC}"
        return 1
    fi
    
    # Try to open with default browser
    if command -v xdg-open > /dev/null; then
        xdg-open "$DASHBOARD_DIR/index.html" &
    elif command -v firefox > /dev/null; then
        firefox "$DASHBOARD_DIR/index.html" &
    elif command -v chromium > /dev/null; then
        chromium "$DASHBOARD_DIR/index.html" &
    else
        echo -e "${YELLOW}Could not detect browser. Please open manually:${NC}"
        echo -e "${BLUE}file://$(realpath $DASHBOARD_DIR/index.html)${NC}"
    fi
    
    log_message "INFO" "Dashboard launched"
}

# View logs
function view_logs() {
    echo -e "${CYAN}Recent Log Entries:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    
    if [ -f "$LOG_FILE" ]; then
        tail -n 50 "$LOG_FILE"
    else
        echo -e "${YELLOW}No logs available for this session${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
}

# Run all security tools
function run_all_security() {
    echo -e "${CYAN}Running all security tools...${NC}"
    echo ""
    
    local scripts=("secure_system" "detect_suspicious_net")
    local failed=0
    
    for script in "${scripts[@]}"; do
        if check_script "$script"; then
            execute_script "$script"
            echo ""
        else
            ((failed++))
        fi
    done
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    if [ $failed -eq 0 ]; then
        echo -e "${GREEN}All security tools completed successfully${NC}"
    else
        echo -e "${YELLOW}$failed tool(s) failed or were not found${NC}"
    fi
}

# Show help
function show_help() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}CyberSec Toolkit Help${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "This runner script provides a unified interface to execute"
    echo "all security, forensic, and reconnaissance tools."
    echo ""
    echo -e "${GREEN}Usage:${NC}"
    echo "  ./run_linux.sh [option]"
    echo ""
    echo -e "${GREEN}Options:${NC}"
    echo "  --auto-secure    Run all security tools automatically"
    echo "  --dashboard      Launch dashboard directly"
    echo "  --help           Show this help message"
    echo ""
    echo -e "${GREEN}Features:${NC}"
    echo "  • Automatic logging of all operations"
    echo "  • Script validation and permission checking"
    echo "  • Color-coded output for better readability"
    echo "  • Web-based dashboard for visual monitoring"
    echo ""
    echo -e "${GREEN}Log Location:${NC}"
    echo "  $LOG_FILE"
    echo ""
}

# Main function
function main() {
    show_banner
    
    # Check for command line arguments
    if [ $# -gt 0 ]; then
        case "$1" in
            --auto-secure)
                run_all_security
                exit 0
                ;;
            --dashboard)
                launch_dashboard
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    fi
    
    log_message "INFO" "CyberSec Toolkit Runner started"
    
    # Interactive menu loop
    while true; do
        show_menu
        read -p "Enter your choice: " choice
        echo ""
        
        case $choice in
            1)
                check_script "secure_system" && execute_script "secure_system"
                ;;
            2)
                check_script "detect_suspicious_net" && execute_script "detect_suspicious_net"
                ;;
            3)
                check_script "revert_security" && execute_script "revert_security"
                ;;
            4)
                check_script "forensic_collect" && execute_script "forensic_collect"
                ;;
            5)
                check_script "system_info" && execute_script "system_info"
                ;;
            6)
                check_script "web_recon" && execute_script "web_recon"
                ;;
            7)
                launch_dashboard
                ;;
            8)
                view_logs
                ;;
            9)
                run_all_security
                ;;
            10)
                show_help
                ;;
            0)
                echo -e "${GREEN}Exiting CyberSec Toolkit...${NC}"
                log_message "INFO" "CyberSec Toolkit Runner stopped"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please try again.${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        clear
        show_banner
    done
}

# Run main function
main "$@"