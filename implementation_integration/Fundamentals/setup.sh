#!/bin/bash
###############################################################################
# /implementation_integration/Fundamentals/setup.sh
# Network Fundamentals - Installation & Setup Script
###############################################################################

# Get correct project root (two levels up from this script)
FUNDAMENTALS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$FUNDAMENTALS_DIR")")"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh" 2>/dev/null || {
    # Fallback colors if lib not available
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
}

# Correct directory paths
SCRIPT_DIR="$PROJECT_ROOT/scripts"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"
DASHBOARD_DIR="$PROJECT_ROOT/dashboard"
TOOLS_DIR="$PROJECT_ROOT/tools"

# Create directories if needed
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Main setup function
setup() {
    clear
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║         Network Concepts Checker - Setup & Installation          ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="rhel"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi

    echo -e "${BLUE}Detected OS: $OS${NC}\n"
    
    # Function to check if command exists
    command_exists() {
        command -v "$1" >/dev/null 2>&1
    }

    # Check required tools
    echo -e "${YELLOW}Checking required tools...${NC}\n"

    REQUIRED_TOOLS=(
        "bash:Shell interpreter"
        "ip:Network configuration"
        "ping:Connectivity testing"
    )

    RECOMMENDED_TOOLS=(
        "ss:Socket statistics"
        "netstat:Network statistics"
        "traceroute:Path tracing"
        "dig:DNS queries"
        "nslookup:DNS lookup"
        "curl:HTTP testing"
        "arp:ARP table"
        "route:Routing table"
        "ethtool:Ethernet settings"
        "tcpdump:Packet capture"
    )

    # Check required tools
    missing_required=()
    for tool_desc in "${REQUIRED_TOOLS[@]}"; do
        tool="${tool_desc%%:*}"
        desc="${tool_desc#*:}"
        if command_exists "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool - $desc"
        else
            echo -e "  ${RED}✗${NC} $tool - $desc (REQUIRED)"
            missing_required+=("$tool")
        fi
    done

    echo ""

    # Check recommended tools
    missing_recommended=()
    for tool_desc in "${RECOMMENDED_TOOLS[@]}"; do
        tool="${tool_desc%%:*}"
        desc="${tool_desc#*:}"
        if command_exists "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool - $desc"
        else
            echo -e "  ${YELLOW}○${NC} $tool - $desc (recommended)"
            missing_recommended+=("$tool")
        fi
    done

    echo ""

    # Provide installation instructions based on OS
    if [[ ${#missing_required[@]} -gt 0 ]] || [[ ${#missing_recommended[@]} -gt 0 ]]; then
        echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}Installation Instructions${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}\n"
        
        case $OS in
            ubuntu|debian)
                echo -e "${BLUE}For Ubuntu/Debian:${NC}"
                echo ""
                echo "sudo apt-get update"
                echo "sudo apt-get install -y \\"
                echo "    iproute2 \\"
                echo "    net-tools \\"
                echo "    iputils-ping \\"
                echo "    traceroute \\"
                echo "    dnsutils \\"
                echo "    curl \\"
                echo "    ethtool \\"
                echo "    tcpdump"
                ;;
                
            rhel|centos|fedora|rocky|almalinux)
                echo -e "${BLUE}For RHEL/CentOS/Fedora:${NC}"
                echo ""
                echo "sudo yum install -y \\"
                echo "    iproute \\"
                echo "    net-tools \\"
                echo "    iputils \\"
                echo "    traceroute \\"
                echo "    bind-utils \\"
                echo "    curl \\"
                echo "    ethtool \\"
                echo "    tcpdump"
                ;;
                
            arch|manjaro)
                echo -e "${BLUE}For Arch Linux:${NC}"
                echo ""
                echo "sudo pacman -S \\"
                echo "    iproute2 \\"
                echo "    net-tools \\"
                echo "    iputils \\"
                echo "    traceroute \\"
                echo "    bind-tools \\"
                echo "    curl \\"
                echo "    ethtool \\"
                echo "    tcpdump"
                ;;
                
            macos)
                echo -e "${BLUE}For macOS:${NC}"
                echo ""
                echo "# Install Homebrew if not already installed"
                echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
                echo ""
                echo "# Install tools"
                echo "brew install iproute2mac bind-tools"
                ;;
                
            *)
                echo -e "${YELLOW}Unknown OS. Please install these packages manually:${NC}"
                echo "  - iproute2 (ip command)"
                echo "  - net-tools (netstat, arp, route)"
                echo "  - iputils (ping)"
                echo "  - traceroute"
                echo "  - dnsutils/bind-utils (dig, nslookup)"
                echo "  - curl"
                echo "  - ethtool"
                echo "  - tcpdump"
                ;;
        esac
        
        echo ""
        echo -e "${YELLOW}After installation, run this option again to verify.${NC}"
        echo ""
        
        # Ask if user wants to install now (Ubuntu/Debian only for safety)
        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
            read -p "$(echo -e ${CYAN}'Would you like to install missing packages now? (y/n): '${NC})" response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                echo ""
                echo -e "${GREEN}Installing packages...${NC}"
                sudo apt-get update
                sudo apt-get install -y iproute2 net-tools iputils-ping traceroute dnsutils curl ethtool tcpdump
                echo ""
                echo -e "${GREEN}Installation complete!${NC}"
            fi
        fi
    else
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ✓ All tools are installed!                                 ║${NC}"
        echo -e "${GREEN}║  You're ready to run the network checker.                   ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
        
        echo -e "${CYAN}To get started from Fundamentals directory:${NC}"
        echo "  ./network_master.sh      # Run interactive menu"
        echo "  ./networking_basics.sh   # Check networking basics"
        echo "  ./ip_addressing.sh       # Check IP & addressing"
        echo "  ./core_protocols.sh      # Check core protocols"
        echo "  ./switching_routing.sh   # Check switching & routing"
    fi

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Additional Setup${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}\n"

    echo -e "${YELLOW}Making scripts executable:${NC}"
    chmod +x "$FUNDAMENTALS_DIR"/*.sh 2>/dev/null && \
        echo "  ✓ Fundamentals scripts are now executable" || \
        echo "  Note: May need sudo to make scripts executable"

    echo ""
    echo -e "${YELLOW}Verifying directory structure:${NC}"
    for dir in "$LOG_DIR" "$OUTPUT_DIR"; do
        if [ -d "$dir" ]; then
            echo "  ✓ $dir exists"
        else
            mkdir -p "$dir" && echo "  ✓ Created $dir" || echo "  ✗ Failed to create $dir"
        fi
    done

    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    [ -f "$PROJECT_ROOT/README.md" ] && echo "  ✓ README.md found" || echo "  ○ README.md not found"

    echo ""
    echo -e "${GREEN}Setup complete! Happy learning! 🚀${NC}"
    echo ""
    
    echo -e "${YELLOW}Press Enter to return to main menu...${NC}"
    read
}

# If called directly, run setup
if [ "${BASH_SOURCE[0]}" -ef "$0" ]; then
    setup
fi
