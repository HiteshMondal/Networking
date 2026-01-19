#!/bin/bash

# Networking & Cybersecurity Tools - Linux Runner Script
# This script provides a menu-driven interface to run various security tools

set -e

# Color codes for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directory setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_PATH="${SCRIPT_DIR}/scripts"
OUTPUT_DIR="${SCRIPT_DIR}/output"
LOGS_DIR="${SCRIPT_DIR}/logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create necessary directories
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${LOGS_DIR}"

# Function to print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to log execution
log_execution() {
    local script_name=$1
    local log_file="${LOGS_DIR}/${script_name}_${TIMESTAMP}.log"
    echo "=== Execution started at $(date) ===" | tee -a "${log_file}"
    echo "Script: ${script_name}" | tee -a "${log_file}"
    echo "Output directory: ${OUTPUT_DIR}" | tee -a "${log_file}"
    echo "======================================" | tee -a "${log_file}"
    echo "${log_file}"
}

# Function to run a script with logging
run_script() {
    local script_name=$1
    local script_path="${SCRIPTS_PATH}/${script_name}"
    
    if [ ! -f "${script_path}" ]; then
        print_message "${RED}" "Error: Script ${script_name} not found!"
        return 1
    fi
    
    if [ ! -x "${script_path}" ]; then
        print_message "${YELLOW}" "Making script executable..."
        chmod +x "${script_path}"
    fi
    
    local log_file=$(log_execution "${script_name%.sh}")
    
    print_message "${BLUE}" "Running ${script_name}..."
    print_message "${YELLOW}" "Log file: ${log_file}"
    
    # Run script and capture output
    cd "${OUTPUT_DIR}"
    bash "${script_path}" 2>&1 | tee -a "${log_file}"
    local exit_code=${PIPESTATUS[0]}
    cd "${SCRIPT_DIR}"
    
    if [ ${exit_code} -eq 0 ]; then
        print_message "${GREEN}" "✓ ${script_name} completed successfully"
    else
        print_message "${RED}" "✗ ${script_name} failed with exit code ${exit_code}"
    fi
    
    echo "=== Execution ended at $(date) ===" >> "${log_file}"
    echo ""
}

# Main menu
show_menu() {
    clear
    print_message "${BLUE}" "╔════════════════════════════════════════════════════════╗"
    print_message "${BLUE}" "║   Networking & Cybersecurity Tools - Linux Runner     ║"
    print_message "${BLUE}" "╚════════════════════════════════════════════════════════╝"
    echo ""
    print_message "${GREEN}" "Output Directory: ${OUTPUT_DIR}"
    print_message "${GREEN}" "Logs Directory: ${LOGS_DIR}"
    echo ""
    print_message "${YELLOW}" "Available Tools:"
    echo "  1) System Information Collection"
    echo "  2) Detect Suspicious Network Activity"
    echo "  3) Secure System Configuration"
    echo "  4) Revert Security Changes"
    echo "  5) Forensic Data Collection"
    echo "  6) Web Reconnaissance"
    echo ""
    echo "  7) Run All Security Scripts (1-6)"
    echo "  8) Open Dashboard"
    echo "  9) Clean Output/Logs Directories"
    echo "  0) Exit"
    echo ""
}

# Function to open dashboard
open_dashboard() {
    local dashboard_path="${SCRIPT_DIR}/dashboard/index.html"
    
    if [ ! -f "${dashboard_path}" ]; then
        print_message "${RED}" "Error: Dashboard not found at ${dashboard_path}"
        return 1
    fi
    
    print_message "${BLUE}" "Opening dashboard..."
    
    if command -v xdg-open &> /dev/null; then
        xdg-open "${dashboard_path}" &
    elif command -v gnome-open &> /dev/null; then
        gnome-open "${dashboard_path}" &
    elif command -v firefox &> /dev/null; then
        firefox "${dashboard_path}" &
    elif command -v chromium-browser &> /dev/null; then
        chromium-browser "${dashboard_path}" &
    else
        print_message "${YELLOW}" "Please open ${dashboard_path} in your browser manually"
    fi
}

# Function to clean directories
clean_directories() {
    print_message "${YELLOW}" "This will delete all files in output and logs directories."
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "${confirm}" == "yes" ]; then
        rm -rf "${OUTPUT_DIR}"/*
        rm -rf "${LOGS_DIR}"/*
        print_message "${GREEN}" "✓ Directories cleaned successfully"
    else
        print_message "${YELLOW}" "Operation cancelled"
    fi
}

# Function to run all scripts
run_all_scripts() {
    print_message "${BLUE}" "Running all security scripts..."
    echo ""
    
    run_script "system_info.sh"
    run_script "detect_suspicious_net_linux.sh"
    run_script "secure_system.sh"
    run_script "forensic_collect.sh"
    run_script "web_recon.sh"
    
    print_message "${GREEN}" "✓ All scripts completed"
}

# Main loop
main() {
    # Check if running with appropriate permissions
    if [ "$EUID" -ne 0 ] && [ "${1}" != "--no-root-check" ]; then
        print_message "${YELLOW}" "Warning: Some scripts may require sudo privileges"
        print_message "${YELLOW}" "Consider running with: sudo ${0}"
        echo ""
    fi
    
    while true; do
        show_menu
        read -p "Enter your choice [0-9]: " choice
        echo ""
        
        case ${choice} in
            1)
                run_script "system_info.sh"
                ;;
            2)
                run_script "detect_suspicious_net_linux.sh"
                ;;
            3)
                run_script "secure_system.sh"
                ;;
            4)
                run_script "revert_security.sh"
                ;;
            5)
                run_script "forensic_collect.sh"
                ;;
            6)
                run_script "web_recon.sh"
                ;;
            7)
                run_all_scripts
                ;;
            8)
                open_dashboard
                ;;
            9)
                clean_directories
                ;;
            0)
                print_message "${GREEN}" "Exiting... Goodbye!"
                exit 0
                ;;
            *)
                print_message "${RED}" "Invalid option. Please try again."
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run main function
main "$@"