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

# Execute script with proper error handling
execute_script() {
    local script_path=$1
    local script_name=$(basename "$script_path")
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local log_file="$LOG_DIR/${script_name}_${timestamp}.log"
    local output_file="$LOG_DIR/${script_name}_${timestamp}.log"
    local SCRIPT_PID=""

    # Set up Ctrl+C trap
    trap 'handle_ctrl_c' INT
    
    handle_ctrl_c() {
        echo -e "\n${YELLOW}Interrupted by Ctrl+C${NC}"
        if [ -n "$SCRIPT_PID" ] && kill -0 "$SCRIPT_PID" 2>/dev/null; then
            echo -e "${YELLOW}Stopping script...${NC}"
            kill -TERM "$SCRIPT_PID" 2>/dev/null
            sleep 1
            kill -KILL "$SCRIPT_PID" 2>/dev/null
            wait "$SCRIPT_PID" 2>/dev/null
        fi
        echo -e "${RED}Script cancelled${NC}"
        echo -e "\nPress Enter to continue..."
        read
        trap - INT  # Remove trap
        return 1
    }

    echo -e "\n${YELLOW}Executing: ${script_name}${NC}"
    echo -e "${BLUE}Log file: ${log_file}${NC}\n"
    echo -e "${BLUE}Output file: ${output_file}${NC}\n"
    
    # Check if script should have a timeout
    local script_timeout=""
    case "$script_name" in
      detect_suspicious_net_linux.sh)
        script_timeout=800
        echo -e "${YELLOW}⏱  This script may take up to several minutes${NC}"
        echo -e "${YELLOW}You can press Ctrl+C to cancel if needed${NC}\n"
        ;;
      forensic_collect.sh)
        script_timeout=400
        ;;
      *)
        script_timeout=200
        ;;
    esac
    
    # Ensure output directory exists
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        log_error "Failed to create output directory: $OUTPUT_DIR"
        echo -e "${YELLOW}Check permissions and try again${NC}"
        echo -e "\nPress Enter to continue..."
        read
        return 1
    fi
    chmod +x "$script_path" 2>/dev/null
    
    echo "=== Execution started at $(date) ===" > "$log_file"

    # Run script in BACKGROUND
    (
        cd "$OUTPUT_DIR" || exit 1
        if [ -n "$script_timeout" ]; then
          timeout "$script_timeout" "$script_path"
        else
          "$script_path"
        fi
    ) 2>&1 | tee -a "$log_file" &    # Add & to run in background

    SCRIPT_PID=$!

    echo -e "${YELLOW}Script running (PID: $SCRIPT_PID)${NC}"
    echo -e "${YELLOW}Press 'q' to cancel, or wait for completion...${NC}\n"

    while kill -0 "$SCRIPT_PID" 2>/dev/null; do
      if read -t 0.1 -n 1 KEY 2>/dev/null; then
        if [[ "$KEY" == "q" ]] || [[ "$KEY" == "Q" ]]; then
          echo -e "\n${YELLOW}Cancelling script...${NC}"
          
          # Try graceful termination first
          kill -TERM "$SCRIPT_PID" 2>/dev/null
          
          # Wait up to 3 seconds for graceful shutdown
          local count=0
          while kill -0 "$SCRIPT_PID" 2>/dev/null && [ $count -lt 30 ]; do
            sleep 0.1
            ((count++))
          done
          
          # Force kill if still running
          if kill -0 "$SCRIPT_PID" 2>/dev/null; then
            echo -e "${YELLOW}Force killing unresponsive script...${NC}"
            kill -KILL "$SCRIPT_PID" 2>/dev/null
          fi
          
          wait "$SCRIPT_PID" 2>/dev/null
          echo -e "${RED}Script cancelled by user${NC}"
          echo -e "\nPress Enter to continue..."
          read
          return 1
        fi
    fi
    sleep 1
    done

    wait "$SCRIPT_PID"
    exit_code=$?

    echo "=== Execution completed at $(date) with exit code $exit_code ===" >> "$log_file"

    if [ "$exit_code" -eq 124 ]; then
        echo -e "\n${RED}⏱  Script timed out after ${script_timeout} seconds${NC}"
        echo -e "${YELLOW}Results may be incomplete. Check log: ${log_file}${NC}"
    elif [ "$exit_code" -eq 0 ]; then
        echo -e "\n${GREEN}✓ Script completed successfully${NC}"
    else
        echo -e "\n${RED}✗ Script completed with errors (exit code: $exit_code)${NC}"
        echo -e "${YELLOW}Check log for details: ${log_file}${NC}"
    fi

    echo -e "\nPress Enter to continue..."
    read

    # Clean up trap before returning
    trap - INT
}

# Main script runner function
run_script() {
    local choice="$1"
    case $choice in
        1) execute_script "$SCRIPT_DIR/detect_suspicious_net_linux.sh" ;;
        2) execute_script "$SCRIPT_DIR/secure_system.sh" ;;
        3) execute_script "$SCRIPT_DIR/revert_security.sh" ;;
        4) execute_script "$SCRIPT_DIR/system_info.sh" ;;
        5) execute_script "$SCRIPT_DIR/forensic_collect.sh" ;;
        6) execute_script "$SCRIPT_DIR/web_recon.sh" ;;
        0) return ;;
        *) 
            log_error "Invalid choice"
            return 1
            ;;
    esac
}
