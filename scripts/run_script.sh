#!/bin/bash
# /scripts/run_script.sh
# Script execution handler

# Path setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
OUTPUT_DIR="$PROJECT_ROOT/output"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

# Script selection menu
show_script_menu() {
    clear
    show_banner

    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "SECURITY SCRIPTS"
    echo -e "${BORDER}${border}${NC}"
    echo
    echo -e "  ${AMBER}Network Analysis${NC}"
    echo -e "  ${GREEN}  1.${NC}  Detect Suspicious Network Activity"
    echo
    echo -e "  ${AMBER}System Security${NC}"
    echo -e "  ${GREEN}  2.${NC}  Secure System"
    echo -e "  ${GREEN}  3.${NC}  Revert Security Changes"
    echo
    echo -e "  ${AMBER}Information Gathering${NC}"
    echo -e "  ${GREEN}  4.${NC}  System Information"
    echo
    echo -e "  ${AMBER}Forensics${NC}"
    echo -e "  ${GREEN}  5.${NC}  Forensic Data Collection"
    echo
    echo -e "  ${AMBER}Reconnaissance${NC}"
    echo -e "  ${GREEN}  6.${NC}  Web Reconnaissance"
    echo
    echo -e "  ${AMBER}Threat Detection${NC}"
    echo -e "  ${GREEN}  7.${NC}  Malware Analysis"
    echo -e "  ${GREEN}  8.${NC}  Lateral Movement Detection"
    echo -e "  ${GREEN}  9.${NC}  Log Analysis"
    echo -e "  ${GREEN} 10.${NC}  Cloud Exposure Audit"
    echo -e "  ${GREEN} 11.${NC}  Data Exfiltration Detection"
    echo
    echo -e "  ${RED}  0.${NC}  Back to Main Menu"
    echo
    echo -e "${BORDER}${border}${NC}"
}

#  EXECUTE SCRIPT
execute_script() {
    local script_path=$1
    local script_name
    script_name=$(basename "$script_path")
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local log_file="$LOG_DIR/${script_name}_${timestamp}.log"
    local output_file="$LOG_DIR/${script_name}_${timestamp}.log"
    local SCRIPT_PID=""

    # Ctrl+C trap
    trap 'handle_ctrl_c' INT

    handle_ctrl_c() {
        echo
        echo -e "  ${WARNING}[~] Interrupted by Ctrl+C${NC}"
        if [ -n "$SCRIPT_PID" ] && kill -0 "$SCRIPT_PID" 2>/dev/null; then
            echo -e "  ${MUTED}[>] Stopping script...${NC}"
            kill -TERM "$SCRIPT_PID" 2>/dev/null
            sleep 1
            kill -KILL "$SCRIPT_PID" 2>/dev/null
            wait "$SCRIPT_PID" 2>/dev/null
        fi
        echo -e "  ${FAILURE}[!] Script cancelled.${NC}"
        echo
        read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
        trap - INT
        return 1
    }

    # Determine timeout
    local script_timeout=""
    case "$script_name" in
        detect_suspicious_net_linux.sh)
            script_timeout=800
            ;;
        forensic_collect.sh)
            script_timeout=400
            ;;
        malware_analysis.sh)
            script_timeout=600
            ;;
        lateral_movement_detect.sh)
            script_timeout=300
            ;;
        log_analysis.sh)
            script_timeout=300
            ;;
        cloud_exposure_audit.sh)
            script_timeout=200
            ;;
        data_exfil_detect.sh)
            script_timeout=300
            ;;
        *)
            script_timeout=200
            ;;
    esac

    # Run header
    clear
    show_banner

    local W=60
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${ACCENT}[>] RUNNING: %-$((W-14))s${NC}  ${BORDER}|${NC}\n" "$script_name"
    echo -e "${BORDER}${border}${NC}"
    echo

    kv "  Script"  "$script_path"
    kv "  Log"     "$log_file"
    kv "  Timeout" "${script_timeout}s"
    echo

    case "$script_name" in
        detect_suspicious_net_linux.sh)
            echo -e "  ${WARNING}[~] This script may take several minutes to complete.${NC}"
            echo -e "  ${MUTED}    Press 'q' at any time to cancel.${NC}"
            ;;
        malware_analysis.sh)
            echo -e "  ${WARNING}[~] Performs static & dynamic analysis. May take several minutes.${NC}"
            echo -e "  ${MUTED}    Press 'q' at any time to cancel.${NC}"
            ;;
        lateral_movement_detect.sh)
            echo -e "  ${WARNING}[~] Analyses auth logs and network state for lateral movement.${NC}"
            echo -e "  ${MUTED}    Some checks require root for full results.${NC}"
            ;;
        log_analysis.sh)
            echo -e "  ${WARNING}[~] Parses system logs and hunts for threat indicators.${NC}"
            echo -e "  ${MUTED}    Some checks require root for full log access.${NC}"
            ;;
        cloud_exposure_audit.sh)
            echo -e "  ${WARNING}[~] Probes cloud metadata services and container security.${NC}"
            echo -e "  ${MUTED}    IMDS probes are read-only and non-destructive.${NC}"
            ;;
        data_exfil_detect.sh)
            echo -e "  ${WARNING}[~] Scans for data exfiltration channels and staged sensitive data.${NC}"
            echo -e "  ${MUTED}    DLP scan covers /tmp, /home, /root, /var/tmp.${NC}"
            ;;
    esac
    echo

    # Pre-flight checks
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        log_error "Failed to create output directory: $OUTPUT_DIR"
        echo -e "  ${MUTED}Check permissions and try again.${NC}"
        echo
        read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
        return 1
    fi
    chmod +x "$script_path" 2>/dev/null

    echo "=== Execution started at $(date) ===" > "$log_file"

    echo -e "  ${DARK_GRAY}$(printf '%*s' "$W" '' | tr ' ' '-')${NC}"
    echo

    # Launch in background
    (
        cd "$OUTPUT_DIR" || exit 1
        if [ -n "$script_timeout" ]; then
            timeout "$script_timeout" "$script_path"
        else
            "$script_path"
        fi
    ) 2>&1 | tee -a "$log_file" &

    SCRIPT_PID=$!

    echo -e "  ${INFO}[i] Script running  (PID: ${SCRIPT_PID})${NC}"
    echo -e "  ${MUTED}    Press 'q' to cancel, or wait for completion...${NC}"
    echo

    # Monitor loop
    while kill -0 "$SCRIPT_PID" 2>/dev/null; do
        if read -t 0.1 -n 1 KEY 2>/dev/null; then
            if [[ "$KEY" == "q" ]] || [[ "$KEY" == "Q" ]]; then
                echo
                echo -e "  ${WARNING}[~] Cancelling script...${NC}"

                kill -TERM "$SCRIPT_PID" 2>/dev/null

                local count=0
                while kill -0 "$SCRIPT_PID" 2>/dev/null && [ $count -lt 30 ]; do
                    sleep 0.1
                    (( count++ ))
                done

                if kill -0 "$SCRIPT_PID" 2>/dev/null; then
                    echo -e "  ${MUTED}[>] Force killing unresponsive script...${NC}"
                    kill -KILL "$SCRIPT_PID" 2>/dev/null
                fi

                wait "$SCRIPT_PID" 2>/dev/null
                echo -e "  ${FAILURE}[!] Script cancelled by user.${NC}"
                echo
                read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
                return 1
            fi
        fi
        sleep 1
    done

    wait "$SCRIPT_PID"
    local exit_code=$?

    echo "=== Execution completed at $(date) with exit code $exit_code ===" >> "$log_file"

    # Result banner
    echo
    echo -e "  ${DARK_GRAY}$(printf '%*s' "$W" '' | tr ' ' '-')${NC}"
    echo

    if [ "$exit_code" -eq 124 ]; then
        echo -e "  ${FAILURE}[!] Script timed out after ${script_timeout} seconds.${NC}"
        echo -e "  ${MUTED}    Results may be incomplete. Check log:${NC}"
        echo -e "  ${MUTED}    ${log_file}${NC}"
    elif [ "$exit_code" -eq 0 ]; then
        echo -e "  ${SUCCESS}[+] Script completed successfully.${NC}"
    else
        echo -e "  ${FAILURE}[!] Script completed with errors (exit code: ${exit_code}).${NC}"
        echo -e "  ${MUTED}    Check log: ${log_file}${NC}"
    fi

    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"

    trap - INT
}

#  SCRIPT ROUTER
run_script() {
    local choice="$1"
    case $choice in
        1) execute_script "$SCRIPT_DIR/detect_suspicious_net_linux.sh" ;;
        2) execute_script "$SCRIPT_DIR/secure_system.sh"               ;;
        3) execute_script "$SCRIPT_DIR/revert_security.sh"             ;;
        4) execute_script "$SCRIPT_DIR/system_info.sh"                 ;;
        5) execute_script "$SCRIPT_DIR/forensic_collect.sh"            ;;
        6) execute_script "$SCRIPT_DIR/web_recon.sh"                   ;;
        7) execute_script "$SCRIPT_DIR/malware_analysis.sh"            ;;
        8) execute_script "$SCRIPT_DIR/lateral_movement_detect.sh"     ;;
        9) execute_script "$SCRIPT_DIR/log_analysis.sh"                ;;
        10) execute_script "$SCRIPT_DIR/cloud_exposure_audit.sh"       ;;
        11) execute_script "$SCRIPT_DIR/data_exfil_detect.sh"          ;;
        0) return ;;
        *)
            log_error "Invalid choice: '${choice}'"
            return 1
            ;;
    esac
}