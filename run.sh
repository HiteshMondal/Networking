#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

# Networking & Cybersecurity Automation Toolkit
# Main control script

# Color definitions
RED='\033[1;31m'      # Bright red, readable everywhere
GREEN='\033[1;32m'    # Bright green
YELLOW='\033[1;33m'   # Bright yellow, good highlight
BLUE='\033[1;34m'     # Bright blue, not too dark
MAGENTA='\033[1;35m'  # Bright magenta
CYAN='\033[1;36m'     # Bright cyan
WHITE='\033[1;37m'    # Bright white, softer than 97
NC='\033[0m'          # Reset
BOLD='\033[1m'        # Bold

# Directories
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR="$PROJECT_ROOT/scripts"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
TOOLS="$PROJECT_ROOT/tools"

# Create necessary directories
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Function to display banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║${NC}                                                                ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${RED}🚀${YELLOW} Networking ${GREEN}&${BLUE} Cybersecurity ${MAGENTA}Automation Toolkit${NC}   ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}  ${BLUE}🔒${WHITE} Professional ${CYAN}Security ${GREEN}& ${YELLOW}Network Analysis Suite${NC} ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}║${NC}                                                                ${CYAN}${BOLD}║${NC}"
    echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to show main menu
show_main_menu() {
    echo -e "${BOLD}${BLUE}═══════════════════ Main Menu ═══════════════════${NC}\n"
    echo -e "${GREEN}1.${NC} Run Security Scripts"
    echo -e "${GREEN}2.${NC} View Dashboard"
    echo -e "${GREEN}3.${NC} View Recent Logs"
    echo -e "${GREEN}4.${NC} Clean Logs & Output"
    echo -e "${GREEN}5.${NC} System Information"
    echo -e "${GREEN}6.${NC} Help & Documentation"
    echo -e "${GREEN}7.${NC} See networking tools"
    echo -e "${RED}0.${NC} Exit"
    echo -e "\n${BLUE}═════════════════════════════════════════════════${NC}"
}

# Function to show script selection menu
show_script_menu() {
    local os=$(detect_os)
    clear
    show_banner
    echo -e "${BOLD}${MAGENTA}═══════════════ Available Scripts ═══════════════${NC}\n"
    
    echo -e "${CYAN}Network Analysis:${NC}"
    if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
        echo -e "${GREEN}1.${NC} Detect Suspicious Network Activity (Linux)"
    fi
    if [[ "$os" == "windows" ]]; then
        echo -e "${GREEN}2.${NC} Detect Suspicious Network Activity (Windows)"
    fi
    
    echo -e "\n${CYAN}System Security:${NC}"
    if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
        echo -e "${GREEN}3.${NC} Secure System (Linux)"
        echo -e "${GREEN}4.${NC} Revert Security Changes (Linux)"
    fi
    if [[ "$os" == "windows" ]]; then
        echo -e "${GREEN}5.${NC} Secure System (Windows)"
    fi
    
    echo -e "\n${CYAN}System Information:${NC}"
    if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
        echo -e "${GREEN}6.${NC} System Information (Linux)"
    fi
    if [[ "$os" == "windows" ]]; then
        echo -e "${GREEN}7.${NC} System Information (Windows)"
    fi
    
    echo -e "\n${CYAN}Forensics:${NC}"
    if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
        echo -e "${GREEN}8.${NC} Forensic Data Collection (Linux)"
    fi
    if [[ "$os" == "windows" ]]; then
        echo -e "${GREEN}9.${NC} Forensic Data Collection (Windows)"
    fi
    
    echo -e "\n${CYAN}Web Reconnaissance:${NC}"
    if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
        echo -e "${GREEN}10.${NC} Web Reconnaissance (Linux)"
    fi
    if [[ "$os" == "windows" ]]; then
        echo -e "${GREEN}11.${NC} Web Reconnaissance (Windows)"
    fi
    
    echo -e "\n${GREEN}12.${NC} Run All Compatible Scripts"
    echo -e "${RED}0.${NC} Back to Main Menu"
    echo -e "\n${MAGENTA}═════════════════════════════════════════════════${NC}"
}

# Function to execute a script
execute_script() {
    local script_path=$1
    local script_name=$(basename "$script_path")
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local log_file="$LOG_DIR/${script_name}_${timestamp}.log"
    echo -e "\n${YELLOW}Executing: ${script_name}${NC}"
    echo -e "${BLUE}Log file: ${log_file}${NC}\n"

    # Ensure output directory exists
    mkdir -p "$OUTPUT_DIR"

    # Make script executable (Linux/macOS)
    chmod +x "$script_path" 2>/dev/null
    echo "=== Execution started at $(date) ===" > "$log_file"
    if [[ "$script_path" == *.bat ]]; then
        (
            cd "$OUTPUT_DIR" || exit 1
            cmd.exe /c "$script_path"
        ) 2>&1 | tee -a "$log_file"
        exit_code=${PIPESTATUS[0]}
    else
        (
            cd "$OUTPUT_DIR" || exit 1
            "$script_path"
        ) 2>&1 | tee -a "$log_file"
        exit_code=${PIPESTATUS[0]}
    fi
    echo "=== Execution completed at $(date) with exit code $exit_code ===" >> "$log_file"
    if [ "$exit_code" -eq 0 ]; then
        echo -e "\n${GREEN}✓ Script completed successfully${NC}"
    else
        echo -e "\n${RED}✗ Script completed with errors (exit code: $exit_code)${NC}"
    fi
    echo -e "\nPress Enter to continue..."
    read
}

# Function to run scripts based on selection
run_script() {
    local choice=$1
    local os=$(detect_os)
    
    case $choice in
        1) execute_script "$SCRIPT_DIR/detect_suspicious_net_linux.sh" ;;
        2) execute_script "$SCRIPT_DIR/detect_suspicious_net_windows.bat" ;;
        3) execute_script "$SCRIPT_DIR/secure_system.sh" ;;
        4) execute_script "$SCRIPT_DIR/revert_security.sh" ;;
        5) execute_script "$SCRIPT_DIR/secure_system.bat" ;;
        6) execute_script "$SCRIPT_DIR/system_info.sh" ;;
        7) execute_script "$SCRIPT_DIR/system_info.bat" ;;
        8) execute_script "$SCRIPT_DIR/forensic_collect.sh" ;;
        9) execute_script "$SCRIPT_DIR/forensic_collect.bat" ;;
        10) execute_script "$SCRIPT_DIR/web_recon.sh" ;;
        11) execute_script "$SCRIPT_DIR/web_recon.bat" ;;
        12) run_all_scripts ;;
        0) return ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
}

# Function to run all compatible scripts
run_all_scripts() {
    local os=$(detect_os)
    echo -e "${YELLOW}Running all compatible scripts for $os...${NC}\n"
    
    if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
        for script in "$SCRIPT_DIR"/*.sh; do
            if [ -f "$script" ]; then
                execute_script "$script"
            fi
        done
    elif [[ "$os" == "windows" ]]; then
        for script in "$SCRIPT_DIR"/*.bat; do
            if [ -f "$script" ]; then
                execute_script "$script"
            fi
        done
    fi
    
    echo -e "\n${GREEN}All scripts completed${NC}"
    echo -e "Press Enter to continue..."
    read
}

# Function to start dashboard
start_dashboard() {
    clear
    show_banner
    echo -e "${YELLOW}Starting Dashboard...${NC}\n"

    cd "$DASHBOARD_DIR" || return

    # Detect Python
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        echo -e "${RED}Python is not installed. Opening static dashboard...${NC}"
        xdg-open "index.html" 2>/dev/null || open "index.html"
        return
    fi

    # Check if server already running (portable)
    if ss -ltn 2>/dev/null | grep -q ':8000' || netstat -an 2>/dev/null | grep -q ':8000'; then
        echo -e "${GREEN}✓ Dashboard already running at http://localhost:8000${NC}"
    else
        echo -e "${GREEN}✓ Starting dashboard server at http://localhost:8000${NC}"
        nohup $PYTHON_CMD server.py > /dev/null 2>&1 &
        sleep 1
    fi

    # Open dashboard via SERVER (important)
    if command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:8000"
    elif command -v open &> /dev/null; then
        open "http://localhost:8000"
    elif command -v start &> /dev/null; then
        start "http://localhost:8000"
    else
        echo -e "${YELLOW}Please open manually: http://localhost:8000${NC}"
    fi

    echo -e "\n${CYAN}Dashboard running in background${NC}"
    echo -e "${YELLOW}Press Enter to return to menu...${NC}"
    read
}

# Function to view recent logs
view_logs() {
    clear
    show_banner
    echo -e "${BOLD}${CYAN}═══════════════ Recent Logs ═══════════════${NC}\n"
    
    if [ "$(ls -A $LOG_DIR 2>/dev/null)" ]; then
        echo -e "${GREEN}Available log files:${NC}\n"
        ls -lht "$LOG_DIR" | head -n 11
        
        echo -e "\n${YELLOW}Enter log file name to view (or 'q' to quit):${NC} "
        read log_choice
        
        if [[ "$log_choice" != "q" ]] && [ -f "$LOG_DIR/$log_choice" ]; then
            less "$LOG_DIR/$log_choice"
        fi
    else
        echo -e "${YELLOW}No logs found. Run some scripts first.${NC}"
    fi
    
    echo -e "\nPress Enter to continue..."
    read
}

# Function to clean logs and output
clean_data() {
    clear
    show_banner
    echo -e "${RED}${BOLD}Warning: This will delete all logs and output files!${NC}"
    echo -e "${YELLOW}Are you sure? (yes/no):${NC} "
    read confirm
    
    if [[ "$confirm" == "yes" ]]; then
        rm -rf "$LOG_DIR"/* "$OUTPUT_DIR"/*
        echo -e "${GREEN}✓ Cleaned successfully${NC}"
    else
        echo -e "${CYAN}Operation cancelled${NC}"
    fi
    
    echo -e "\nPress Enter to continue..."
    read
}

# Function to show system info
show_system_info() {
    clear
    show_banner
    echo -e "${BOLD}${CYAN}═══════════════ System Information ═══════════════${NC}\n"
    echo -e "${GREEN}Operating System:${NC} $(detect_os)"
    echo -e "${GREEN}Hostname:${NC} $(hostname)"
    echo -e "${GREEN}User:${NC} $(whoami)"
    echo -e "${GREEN}Date:${NC} $(date)"
    echo -e "${GREEN}Uptime:${NC} $(uptime -p 2>/dev/null || uptime)"
    echo -e "\n${GREEN}Toolkit Statistics:${NC}"
    echo -e "  Log files: $(find "$LOG_DIR" -type f 2>/dev/null | wc -l)"
    echo -e "  Output files: $(find "$OUTPUT_DIR" -type f 2>/dev/null | wc -l)"
    echo -e "  Available scripts: $(find "$SCRIPT_DIR" -type f 2>/dev/null | wc -l)"
    echo -e "\nPress Enter to continue..."
    read
}

# Function to show help
show_help() {
    clear
    show_banner
    echo -e "${BOLD}${CYAN}════════════════ Help & Documentation ═════════════════${NC}\n"
    echo -e "${GREEN}📖 About:${NC}"
    echo "  This toolkit automates security and network analysis tasks,"
    echo "  making it easier to detect threats, secure systems, and gather forensic data."
    echo ""
    echo -e "${GREEN}✨ Features:${NC}"
    echo "  • Detect suspicious network activity"
    echo "  • System hardening and configuration"
    echo "  • Forensic data collection"
    echo "  • Web reconnaissance & scanning"
    echo "  • Comprehensive logging and reporting"
    echo ""
    echo -e "${GREEN}🛠️ Usage:${NC}"
    echo "  1️⃣  Choose scripts from the main menu"
    echo "  2️⃣  Execute tasks and monitor output"
    echo "  3️⃣  Check logs for detailed insights"
    echo ""
    echo -e "${GREEN}📂 Logs Location:${NC} $LOG_DIR"
    echo -e "${GREEN}📂 Output Location:${NC} $OUTPUT_DIR"
    echo -e "\nPress Enter to return to the menu..."
    read
}

# Function to check tools
tools() {
    clear
    echo -e "${BLUE}══════════════════════════════════════${NC}"
    echo -e "${GREEN}        🛠  Available Tools${NC}"
    echo -e "${BLUE}══════════════════════════════════════${NC}"
    echo
    echo -e "${GREEN} 1.${NC} Run Network Tools"
    echo -e "${GREEN} 2.${NC} Back to Main Menu"
    echo
    echo -e "${BLUE}──────────────────────────────────────${NC}"
    read -p "$(echo -e ${YELLOW}'👉 Choose an option: '${NC})" choice
    echo
    case $choice in
        1)
            if [ -f "$TOOLS/network_tools.sh" ]; then
                echo -e "${GREEN}[+] Running network tools...${NC}"
                chmod +x "$TOOLS/network_tools.sh"
                bash "$TOOLS/network_tools.sh"
            else
                echo -e "${RED}[!] network_tools.sh not found${NC}"
            fi
            ;;
        2)
            echo -e "${YELLOW}[*] Returning to main menu...${NC}"
            sleep 1
            ;;
        *)
            echo -e "${RED}[!] Invalid option. Please try again.${NC}"
            sleep 1
            ;;
    esac
}

# Main loop
main() {
    while true; do
        show_banner
        show_main_menu
        echo -e -n "\n${YELLOW}Enter your choice:${NC} "
        read choice
        
        case $choice in
            1)
                while true; do
                    show_script_menu
                    echo -e -n "\n${YELLOW}Enter your choice:${NC} "
                    read script_choice
                    
                    if [[ "$script_choice" == "0" ]]; then
                        break
                    fi
                    
                    run_script "$script_choice"
                done
                ;;
            2) start_dashboard ;;
            3) view_logs ;;
            4) clean_data ;;
            5) show_system_info ;;
            6) show_help ;;
            7) tools ;;
            0) 
                echo -e "\n${GREEN}Thank you for using the Networking & Cybersecurity Toolkit!${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}Invalid choice. Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Run main function
main