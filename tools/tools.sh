#!/bin/bash

# /tools/tools.sh
# Tools menu handler

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"

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
        echo -e "${GREEN} 2.${NC} View Tools Documentation"
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
                    sleep 2
                fi
                ;;
            2)
                cat $PROJECT_ROOT/tools/guide
                echo ""
                echo -e "\nPress Enter to continue..."
                read
                ;;
            0)
                log_info "Returning to main menu..."
                return 0
                ;;
            *)
                log_error "Invalid option. Please try again."
                sleep 1
                ;;
        esac
    done
}
