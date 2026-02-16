#!/bin/bash

set -o pipefail

# Networking & Cybersecurity Automation Toolkit
# Main control script
# /run.sh

# Establish project root
export PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Source files
source "$PROJECT_ROOT/config/settings.conf"
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/scripts/run_script.sh"
source "$PROJECT_ROOT/tools/tools.sh"
source "$PROJECT_ROOT/dashboard/start_dashboard.sh"
source "$PROJECT_ROOT/implementation_integration/Fundamentals/setup.sh"

# Directories
SCRIPT_DIR="$PROJECT_ROOT/scripts"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
TOOLS="$PROJECT_ROOT/tools"

# Create necessary directories
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Initialize main log
touch "$LOG_DIR/main.log"

# Function to show main menu
show_main_menu() {
    echo -e "${BOLD}${BLUE}═══════════════════ Main Menu ═══════════════════${NC}\n"
    echo -e "${GREEN}1.${NC} Run Security Scripts"
    echo -e "${GREEN}2.${NC} View Dashboard"
    echo -e "${GREEN}3.${NC} View Recent Logs"
    echo -e "${GREEN}4.${NC} Clean Logs & Output"
    echo -e "${GREEN}5.${NC} System Information"
    echo -e "${GREEN}6.${NC} Help & Documentation"
    echo -e "${GREEN}7.${NC} Network Tools"
    echo -e "${GREEN}8.${NC} Networking Fundamentals Setup"
    echo -e "${GREEN}9.${NC} Stop Dashboard"
    echo -e "${RED}0.${NC} Exit"
    echo -e "\n${BLUE}═════════════════════════════════════════════════${NC}"
}

# Function to show script selection menu
show_script_menu() {
    local os=$(detect_os)
    clear
    show_banner
    echo -e "${BOLD}${MAGENTA}═══════════════ Available Scripts ═══════════════${NC}\n"
    
    local option_num=1

    echo -e "${CYAN}Network Analysis:${NC}"
    echo -e "${GREEN}${option_num}.${NC} Detect Suspicious Network Activity (Linux)"
    ((option_num++))

    echo -e "\n${CYAN}System Security:${NC}"
    echo -e "${GREEN}${option_num}.${NC} Secure System (Linux)"
    ((option_num++))
    echo -e "${GREEN}${option_num}.${NC} Revert Security Changes (Linux)"
    ((option_num++))

    echo -e "\n${CYAN}System Information:${NC}"
    echo -e "${GREEN}${option_num}.${NC} System Information (Linux)"
    ((option_num++))
    
    echo -e "\n${CYAN}Forensics:${NC}"
    echo -e "${GREEN}${option_num}.${NC} Forensic Data Collection (Linux)"
    ((option_num++))

    echo -e "\n${CYAN}Web Reconnaissance:${NC}"
    echo -e "${GREEN}${option_num}.${NC} Web Reconnaissance (Linux)"
    ((option_num++))

    echo -e "${RED}0.${NC} Back to Main Menu"
    echo -e "\n${MAGENTA}═════════════════════════════════════════════════${NC}"
}

# Function to view recent logs
view_logs() {
    clear
    show_banner
    echo -e "${BOLD}${CYAN}═══════════════ Recent Logs ═══════════════${NC}\n"
    
    if [ "$(ls -A "$LOG_DIR" 2>/dev/null)" ]; then
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
        log_success "Cleaned successfully"
    else
        log_info "Operation cancelled"
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
    
    # Show dashboard status
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "  Dashboard: ${GREEN}Running${NC} (PID: $pid)"
        else
            echo -e "  Dashboard: ${RED}Not running${NC}"
        fi
    else
        echo -e "  Dashboard: ${RED}Not running${NC}"
    fi
    
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
    echo "  • Network tools and diagnostics"
    echo "  • Networking fundamentals practice"
    echo ""
    echo -e "${GREEN}🛠️ Usage:${NC}"
    echo "  1️⃣  Choose scripts from the main menu"
    echo "  2️⃣  Execute tasks and monitor output"
    echo "  3️⃣  Check logs for detailed insights"
    echo "  4️⃣  Use dashboard for visualization"
    echo ""
    echo -e "${GREEN}📂 Important Locations:${NC}"
    echo -e "  Logs:    ${CYAN}$LOG_DIR${NC}"
    echo -e "  Outputs: ${CYAN}$OUTPUT_DIR${NC}"
    echo -e "  Config:  ${CYAN}$PROJECT_ROOT/config/settings.conf${NC}"
    echo ""
    echo -e "${GREEN}🔧 Configuration:${NC}"
    echo "  Edit config/settings.conf to customize:"
    echo "    - Dashboard port"
    echo "    - Log rotation settings"
    echo "    - Python command"
    echo -e "\nPress Enter to return to the menu..."
    read
}

# Cleanup function on exit
cleanup() {
    log_info "Toolkit shutting down..."
}

trap cleanup EXIT

# Main loop
main() {
    # Initial check
    if [ ! -d "$PROJECT_ROOT/lib" ]; then
        echo -e "${RED}Error: Required libraries not found.${NC}"
        echo -e "${YELLOW}Please run the setup steps from the documentation.${NC}"
        exit 1
    fi
    
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
            2) start_dashboard_main ;;
            3) view_logs ;;
            4) clean_data ;;
            5) show_system_info ;;
            6) show_help ;;
            7) tools ;;
            8) setup ;;
            9) 
                source "$PROJECT_ROOT/dashboard/start_dashboard.sh"
                stop_dashboard
                echo -e "\nPress Enter to continue..."
                read
                ;;
            0) 
                echo -e "\n${GREEN}Thank you for using the Networking & Cybersecurity Toolkit!${NC}"
                exit 0
                ;;
            *) 
                log_error "Invalid choice. Please try again."
                sleep 2
                ;;
        esac
    done
}


# Run main function
main
