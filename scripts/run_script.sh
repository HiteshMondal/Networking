#!/bin/bash
# /scripts/run_script.sh
# Script execution handler

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"

# Source dependencies
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

# Map menu choices to scripts (OS-aware)
get_script_for_choice() {
    local choice=$1
    local os=$2
    
    # Define script mappings
    case $choice in
        1) 
            if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
                echo "$SCRIPT_DIR/detect_suspicious_net_linux.sh"
            fi
            ;;
        2) 
            if [[ "$os" == "windows" ]]; then
                echo "$SCRIPT_DIR/detect_suspicious_net_windows.bat"
            elif [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
                echo "$SCRIPT_DIR/secure_system.sh"
            fi
            ;;
        3) 
            if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
                echo "$SCRIPT_DIR/revert_security.sh"
            elif [[ "$os" == "windows" ]]; then
                echo "$SCRIPT_DIR/secure_system.bat"
            fi
            ;;
        4)
            if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
                echo "$SCRIPT_DIR/system_info.sh"
            fi
            ;;
        5)
            if [[ "$os" == "windows" ]]; then
                echo "$SCRIPT_DIR/system_info.bat"
            elif [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
                echo "$SCRIPT_DIR/forensic_collect.sh"
            fi
            ;;
        6)
            if [[ "$os" == "linux" ]] || [[ "$os" == "macos" ]]; then
                echo "$SCRIPT_DIR/web_recon.sh"
            elif [[ "$os" == "windows" ]]; then
                echo "$SCRIPT_DIR/forensic_collect.bat"
            fi
            ;;
        7)
            if [[ "$os" == "windows" ]]; then
                echo "$SCRIPT_DIR/web_recon.bat"
            fi
            ;;
        0) echo "EXIT" ;;
        *) echo "" ;;
    esac
}

# Execute script with proper error handling
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

# Log rotation
rotate_logs() {
    local log_count=$(find "$LOG_DIR" -type f -name "*.log" | wc -l)
    
    if [ "$log_count" -gt "$MAX_LOG_FILES" ]; then
        log_info "Rotating old logs..."
        find "$LOG_DIR" -type f -name "*.log" -printf '%T@ %p\n' | \
            sort -n | \
            head -n -"$MAX_LOG_FILES" | \
            cut -d' ' -f2- | \
            xargs rm -f
    fi
}

# Main script runner function
run_script() {
    local choice="$1"
    local os
    os=$(detect_os)

    local script=""
    case $choice in
        1) execute_script "$SCRIPT_DIR/detect_suspicious_net_linux.sh" ;;
        2) execute_script "$SCRIPT_DIR/secure_system.sh" ;;
        3) execute_script "$SCRIPT_DIR/revert_security.sh" ;;
        4) execute_script "$SCRIPT_DIR/system_info.sh" ;;
        5) execute_script "$SCRIPT_DIR/forensic_collect.sh" ;;
        6) execute_script "$SCRIPT_DIR/web_recon.sh" ;;
        0) return ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac

    if [[ ! -x "$script" ]]; then
        log_error "Script not executable: $script"
        return
    fi

    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local logfile="$LOG_DIR/$(basename "$script")_$ts.log"

    log_info "Executing: $(basename "$script")"
    log_info "Log file: $logfile"

    # EXECUTE — NOT SOURCE
    (
        export OUTPUT_DIR
        export PROJECT_ROOT
        bash "$script"
    ) 2>&1 | tee -a "$logfile"

    local rc=${PIPESTATUS[0]}
    if [[ $rc -eq 0 ]]; then
        log_success "Script completed successfully"
    else
        log_error "Script failed with exit code $rc"
    fi
}
