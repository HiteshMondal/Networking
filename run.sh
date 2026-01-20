#!/bin/bash

# Networking & Cybersecurity Automation Toolkit
# Main control script

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Directories
SCRIPT_DIR="./scripts"
LOG_DIR="./logs"
OUTPUT_DIR="./output"
DASHBOARD_DIR="./dashboard"

# Create necessary directories
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Function to display banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║   Networking & Cybersecurity Automation Toolkit            ║"
    echo "║   Professional Security & Network Analysis Suite           ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
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
    
    # Make script executable
    chmod +x "$script_path" 2>/dev/null
    
    # Execute and log
    echo "=== Execution started at $(date) ===" > "$log_file"
    
    if [[ "$script_path" == *.bat ]]; then
        cmd.exe /c "$script_path" 2>&1 | tee -a "$log_file"
    else
        "$script_path" 2>&1 | tee -a "$log_file"
    fi
    
    local exit_code=$?
    echo "=== Execution completed at $(date) with exit code $exit_code ===" >> "$log_file"
    
    if [ $exit_code -eq 0 ]; then
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
    
    # Check if Python is installed
    if command -v python3 &> /dev/null; then
        cd "$DASHBOARD_DIR"
        echo -e "${GREEN}Dashboard server starting at http://localhost:8000${NC}"
        echo -e "${CYAN}Press Ctrl+C to stop the server${NC}\n"
        python3 server.py
    elif command -v python &> /dev/null; then
        cd "$DASHBOARD_DIR"
        echo -e "${GREEN}Dashboard server starting at http://localhost:8000${NC}"
        echo -e "${CYAN}Press Ctrl+C to stop the server${NC}\n"
        python server.py
    else
        echo -e "${RED}Python is not installed. Please install Python to use the dashboard.${NC}"
        echo -e "Opening static dashboard in browser..."
        
        # Try to open in default browser
        if command -v xdg-open &> /dev/null; then
            xdg-open "$DASHBOARD_DIR/index.html"
        elif command -v open &> /dev/null; then
            open "$DASHBOARD_DIR/index.html"
        elif command -v start &> /dev/null; then
            start "$DASHBOARD_DIR/index.html"
        else
            echo -e "${YELLOW}Please manually open: $DASHBOARD_DIR/index.html${NC}"
        fi
    fi
    
    echo -e "\nPress Enter to continue..."
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
    echo -e "  Log files: $(ls -1 $LOG_DIR 2>/dev/null | wc -l)"
    echo -e "  Output files: $(ls -1 $OUTPUT_DIR 2>/dev/null | wc -l)"
    echo -e "  Available scripts: $(ls -1 $SCRIPT_DIR 2>/dev/null | wc -l)"
    
    echo -e "\nPress Enter to continue..."
    read
}

# Function to show help
show_help() {
    clear
    show_banner
    echo -e "${BOLD}${CYAN}═══════════════ Help & Documentation ═══════════════${NC}\n"
    
    echo -e "${GREEN}About:${NC}"
    echo "This toolkit provides automated security and network analysis scripts."
    echo ""
    echo -e "${GREEN}Features:${NC}"
    echo "  • Network suspicious activity detection"
    echo "  • System hardening and security configuration"
    echo "  • Forensic data collection"
    echo "  • Web reconnaissance"
    echo "  • Comprehensive logging and reporting"
    echo ""
    echo -e "${GREEN}Usage:${NC}"
    echo "  1. Select scripts from the menu to execute"
    echo "  2. View results in the dashboard"
    echo "  3. Check logs for detailed information"
    echo ""
    echo -e "${GREEN}Logs Location:${NC} $LOG_DIR"
    echo -e "${GREEN}Output Location:${NC} $OUTPUT_DIR"
    
    echo -e "\nPress Enter to continue..."
    read
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