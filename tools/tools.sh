#!/bin/bash

# /tools/tools.sh
# Tools menu handler

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
TOOLS_DIR="$PROJECT_ROOT/tools"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

# Create directories if needed
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Main tools function
tools() {
    while true; do
        clear
        show_banner
        echo -e "${BLUE}══════════════════════════════════════${NC}"
        echo -e "${GREEN}        🛠  Available Tools${NC}"
        echo -e "${BLUE}══════════════════════════════════════${NC}"
        echo
        echo -e "${GREEN} 1.${NC} Run Network Tools"
        echo -e "${GREEN} 2.${NC} Core protocols"
        echo -e "${GREEN} 3.${NC} IP addressing"
        echo -e "${GREEN} 4.${NC} Run network master"
        echo -e "${GREEN} 5.${NC} Switching routing"
        echo -e "${GREEN} 6.${NC} Security_fundamentals"
        echo -e "${RED} 0.${NC} Back to Main Menu"
        echo
        echo -e "${BLUE}══════════════════════════════════════${NC}"
        read -p "$(echo -e ${YELLOW}'👉 Choose an option: '${NC})" choice
        echo
        
        case $choice in
            1)
                if [ -f "$PROJECT_ROOT/tools/network_tools.sh" ]; then
                    log_info "Launching network tools..."
                    bash "$PROJECT_ROOT/tools/network_tools.sh"
                else
                    log_error "network_tools.sh not found at $PROJECT_ROOT/tools"
                fi
                ;;
            2)  if [ -f "$PROJECT_ROOT/tools/core_protocols.sh" ]; then
                    log_info "Launching tools..."
                    bash "$PROJECT_ROOT/tools/core_protocols.sh"
                else
                    log_error "core_protocols.sh not found at $PROJECT_ROOT/tools"
                fi
                ;;
            3)  if [ -f "$PROJECT_ROOT/tools/ip_addressing.sh" ]; then
                    log_info "Launching ip addressing tools..."
                    bash "$PROJECT_ROOT/tools/ip_addressing.sh"
                else
                    log_error "ip_addressing.sh not found at $PROJECT_ROOT/tools"
                fi
                ;;
                
            4)  if [ -f "$PROJECT_ROOT/tools/network_master.sh" ]; then
                    log_info "Launching network master tools..."
                    bash "$PROJECT_ROOT/tools/network_master.sh"
                else
                    log_error "network_master.sh not found at $PROJECT_ROOT/tools"
                fi
                ;;
            5)  if [ -f "$PROJECT_ROOT/tools/switching_routing.sh" ]; then
                    log_info "Launching switching routing..."
                    bash "$PROJECT_ROOT/tools/switching_routing.sh"
                else
                    log_error "switching_routing.sh not found at $PROJECT_ROOT/tools"
                fi
                ;;
            6)  if [ -f "$PROJECT_ROOT/tools/security_fundamentals.sh" ]; then
                    log_info "Launching Security fundamentals..."
                    bash "$PROJECT_ROOT/tools/security_fundamentals.sh"
                else
                    log_error "security_fundamentals.sh not found at $PROJECT_ROOT/tools"
                fi
                ;;
            0)
                log_info "Returning to main menu..."
                return 0
                ;;
            *)
                log_error "Invalid option. Please try again."
                ;;
        esac
    done
}
