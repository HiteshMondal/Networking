#!/bin/bash

# Network Tools Analyzer and Installer
# Automatically installs and runs popular network monitoring tools

# Color codes for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect package manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v brew &> /dev/null; then
        echo "brew"
    else
        echo "unknown"
    fi
}

# Function to install a tool
install_tool() {
    local tool=$1
    local pkg_manager=$2
    
    print_info "Installing $tool..."
    
    case $pkg_manager in
        apt)
            sudo apt-get update -qq && sudo apt-get install -y $tool
            ;;
        yum)
            sudo yum install -y $tool
            ;;
        dnf)
            sudo dnf install -y $tool
            ;;
        pacman)
            sudo pacman -S --noconfirm $tool
            ;;
        brew)
            brew install $tool
            ;;
        *)
            print_error "Unknown package manager. Please install $tool manually."
            return 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        print_success "$tool installed successfully"
        return 0
    else
        print_error "Failed to install $tool"
        return 1
    fi
}

# Function to check and install tool if needed
check_and_install() {
    local tool=$1
    local pkg_manager=$2
    
    if command -v $tool &> /dev/null; then
        print_success "$tool is already installed"
        return 0
    else
        print_warning "$tool is not installed"
        install_tool $tool $pkg_manager
        return $?
    fi
}

# Function to run netstat analysis
run_netstat() {
    print_info "Running netstat analysis..."
    echo ""
    echo "=== Active Network Connections ==="
    netstat -tuln
    echo ""
    echo "=== Routing Table ==="
    netstat -rn
}

# Function to run ss (socket statistics)
run_ss() {
    print_info "Running ss (socket statistics)..."
    echo ""
    echo "=== Listening Ports ==="
    ss -tuln
    echo ""
    echo "=== Established Connections ==="
    ss -tn state established
}

# Function to run ifconfig/ip
run_interface_info() {
    print_info "Network Interface Information..."
    echo ""
    if command -v ip &> /dev/null; then
        echo "=== IP Addresses ==="
        ip addr show
        echo ""
        echo "=== Link Status ==="
        ip link show
    elif command -v ifconfig &> /dev/null; then
        ifconfig
    fi
}

# Function to run nmap scan
run_nmap() {
    print_info "Running nmap scan..."
    read -p "Enter target (IP/hostname) or press Enter for localhost: " target
    target=${target:-127.0.0.1}
    echo ""
    print_info "Scanning $target..."
    nmap -sV $target
}

# Function to run tcpdump
run_tcpdump() {
    print_info "Running tcpdump (packet capture)..."
    echo "Available interfaces:"
    if command -v ip &> /dev/null; then
        ip link show | grep -E "^[0-9]+" | awk '{print $2}' | tr -d ':'
    else
        ifconfig -a | grep -E "^[a-z]" | awk '{print $1}' | tr -d ':'
    fi
    echo ""
    read -p "Enter interface name (or press Enter for any): " interface
    read -p "Enter number of packets to capture (default 20): " count
    count=${count:-20}
    
    echo ""
    print_warning "Starting packet capture... (requires sudo)"
    if [ -z "$interface" ]; then
        sudo tcpdump -c $count
    else
        sudo tcpdump -i $interface -c $count
    fi
}

# Function to run ping test
run_ping() {
    read -p "Enter hostname/IP to ping (default: 8.8.8.8): " target
    target=${target:-8.8.8.8}
    read -p "Enter number of packets (default: 4): " count
    count=${count:-4}
    echo ""
    print_info "Pinging $target..."
    ping -c $count $target
}

# Function to run traceroute
run_traceroute() {
    read -p "Enter destination (default: google.com): " target
    target=${target:-google.com}
    echo ""
    print_info "Tracing route to $target..."
    if command -v traceroute &> /dev/null; then
        traceroute $target
    elif command -v tracepath &> /dev/null; then
        tracepath $target
    fi
}

# Function to run bandwidth monitoring
run_iftop() {
    print_info "Running iftop (bandwidth monitor)..."
    print_warning "This requires sudo access. Press Ctrl+C to exit."
    sleep 2
    sudo iftop
}

# Main menu
show_menu() {
    clear
    echo "======================================"
    echo "  Network Tools Analyzer & Monitor"
    echo "======================================"
    echo "1.  Network Interfaces (ip/ifconfig)"
    echo "2.  Active Connections (netstat)"
    echo "3.  Socket Statistics (ss)"
    echo "4.  Ping Test"
    echo "5.  Traceroute"
    echo "6.  Port Scan (nmap)"
    echo "7.  Packet Capture (tcpdump)"
    echo "8.  Bandwidth Monitor (iftop)"
    echo "9.  Install/Check All Tools"
    echo "0.  Exit"
    echo "======================================"
}

# Main execution
main() {
    # Detect package manager
    PKG_MANAGER=$(detect_package_manager)
    print_info "Detected package manager: $PKG_MANAGER"
    echo ""
    
    # Define tools to check/install
    TOOLS=("net-tools" "iproute2" "nmap" "tcpdump" "iftop" "traceroute")
    
    while true; do
        show_menu
        read -p "Select an option: " choice
        echo ""
        
        case $choice in
            1)
                run_interface_info
                ;;
            2)
                check_and_install "net-tools" $PKG_MANAGER
                run_netstat
                ;;
            3)
                check_and_install "iproute2" $PKG_MANAGER
                run_ss
                ;;
            4)
                run_ping
                ;;
            5)
                check_and_install "traceroute" $PKG_MANAGER
                run_traceroute
                ;;
            6)
                check_and_install "nmap" $PKG_MANAGER
                run_nmap
                ;;
            7)
                check_and_install "tcpdump" $PKG_MANAGER
                run_tcpdump
                ;;
            8)
                check_and_install "iftop" $PKG_MANAGER
                run_iftop
                ;;
            9)
                print_info "Checking and installing all network tools..."
                for tool in "${TOOLS[@]}"; do
                    check_and_install $tool $PKG_MANAGER
                    echo ""
                done
                print_success "Tool check/installation complete!"
                ;;
            0)
                print_info "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run main function
main