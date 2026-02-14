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
    
    # Validate script exists
    if [ ! -f "$script_path" ]; then
        log_error "Script not found: $script_path"
        echo -e "\nPress Enter to continue..."
        read
        return 1
    fi
    
    echo -e "\n${YELLOW}Executing: ${script_name}${NC}"
    echo -e "${BLUE}Log file: ${log_file}${NC}\n"

    # Ensure directories exist
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR"

    # Make script executable (Linux/macOS)
    chmod +x "$script_path" 2>/dev/null
    
    # Log execution start
    echo "=== Execution started at $(date) ===" > "$log_file"
    echo "Script: $script_path" >> "$log_file"
    echo "Working directory: $OUTPUT_DIR" >> "$log_file"
    echo "===" >> "$log_file"
    
    # Execute based on file type
    if [[ "$script_path" == *.bat ]]; then
        # Windows batch file
        (
            safe_cd "$OUTPUT_DIR" || exit 1
            cmd.exe /c "$script_path"
        ) 2>&1 | tee -a "$log_file"
        exit_code=${PIPESTATUS[0]}
    else
        # Unix shell script - run from script's own directory
        local script_dir=$(dirname "$script_path")
        (
            safe_cd "$script_dir" || exit 1
            export OUTPUT_DIR  # Make available to child script
            export LOG_DIR
            "./$script_name"
        ) 2>&1 | tee -a "$log_file"
        exit_code=${PIPESTATUS[0]}
    fi
    
    # Log completion
    echo "=== Execution completed at $(date) with exit code $exit_code ===" >> "$log_file"
    
    # Show result
    if [ "$exit_code" -eq 0 ]; then
        log_success "Script completed successfully"
    else
        log_error "Script completed with errors (exit code: $exit_code)"
    fi
    
    # Rotate logs if needed
    rotate_logs
    
    echo -e "\nPress Enter to continue..."
    read
    return $exit_code
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
    local choice=$1
    local os=$(detect_os)
    
    if [ "$choice" == "0" ]; then
        return 0
    fi
    
    local script_path=$(get_script_for_choice "$choice" "$os")
    
    if [ -z "$script_path" ]; then
        log_error "Invalid choice or script not available for your OS"
        sleep 2
        return 1
    fi
    
    if [ "$script_path" == "EXIT" ]; then
        return 0
    fi
    
    execute_script "$script_path"
}
