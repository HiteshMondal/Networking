#!/bin/bash

###############################################################################
# Network Concepts Checker - Master Script
# This script runs all networking topic checks and demonstrations
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          NETWORK CONCEPTS CHECKER & DEMONSTRATOR             ║"
    echo "║                                                              ║"
    echo "║  This suite demonstrates and checks networking concepts      ║"
    echo "║  on your system using real commands and outputs              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Menu
show_menu() {
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Select a topic to explore:${NC}"
    echo ""
    echo "  1) Networking Basics (OSI/TCP-IP Models, Bandwidth, Latency)"
    echo "  2) IP & Addressing (IPv4/IPv6, Subnetting, NAT, ARP)"
    echo "  3) Core Protocols (TCP/UDP, HTTP, DNS, ICMP)"
    echo "  4) Switching & Routing (VLANs, MAC, Routing Protocols)"
    echo ""
    echo "  5) Run ALL Checks (Full System Analysis)"
    echo ""
    echo "  0) Exit"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -n "Enter choice [0-5]: "
}

# Execute script safely
run_script() {
    local script_name=$1
    local script_path="$SCRIPT_DIR/$script_name"
    
    if [[ -f "$script_path" ]]; then
        echo -e "\n${CYAN}Running: $script_name${NC}\n"
        bash "$script_path"
        echo -e "\n${GREEN}✓ Completed: $script_name${NC}\n"
    else
        echo -e "${RED}✗ Script not found: $script_path${NC}"
    fi
}

# Main execution
main() {
    print_banner
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                run_script "01_networking_basics.sh"
                ;;
            2)
                run_script "02_ip_addressing.sh"
                ;;
            3)
                run_script "03_core_protocols.sh"
                ;;
            4)
                run_script "04_switching_routing.sh"
                ;;
            5)
                echo -e "\n${MAGENTA}Running complete system analysis...${NC}\n"
                run_script "01_networking_basics.sh"
                run_script "02_ip_addressing.sh"
                run_script "03_core_protocols.sh"
                run_script "04_switching_routing.sh"
                echo -e "\n${GREEN}✓✓✓ All checks completed! ✓✓✓${NC}\n"
                ;;
            0)
                echo -e "\n${CYAN}Exiting Network Checker. Goodbye!${NC}\n"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please try again.${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
    done
}

# Check for required tools
check_requirements() {
    local missing_tools=()
    
    for tool in ip netstat ss route ping traceroute dig nslookup arp; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Some tools are missing: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}Some checks may not work. Install with:${NC}"
        echo "  sudo apt-get install iproute2 net-tools iputils-ping traceroute dnsutils"
        echo ""
    fi
}

check_requirements
main