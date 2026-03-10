#!/bin/bash
# /modules/run_modules.sh
# Security modules execution handler

# PATH SETUP
MODULES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$MODULES_DIR")"

source "$PROJECT_ROOT/lib/init.sh"

# MODULE MENU
show_modules_menu() {
    clear
    show_banner
    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')
    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "SECURITY MODULES"
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
    echo -e "  ${AMBER}Automation${NC}"
    echo -e "  ${GREEN} 12.${NC}  Run All Security Modules"
    echo
    echo -e "  ${RED}  0.${NC}  Back to Main Menu"
    echo
    echo -e "${BORDER}${border}${NC}"
}

# EXECUTE MODULE
execute_module() {
    mkdir -p "$LOG_DIR" "$OUTPUT_DIR"
    local module_path="$1"
    shift
    local module_args=("$@")
    local module_name
    module_name=$(basename "$module_path")

    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    local log_file="${LOG_DIR}/${module_name}_${timestamp}.log"
    touch "$log_file" 2>/dev/null || {
        log_error "Cannot create log file: $log_file"
        return 1
    }
    local module_pid=""
    local module_timeout

    trap 'handle_ctrl_c' INT

    handle_ctrl_c() {
        echo
        echo -e "  ${WARNING}[~] Interrupted by Ctrl+C${NC}"
        if [ -n "$module_pid" ] && kill -0 "$module_pid" 2>/dev/null; then
            echo -e "  ${MUTED}[>] Stopping module...${NC}"

            kill -TERM "$module_pid" 2>/dev/null
            sleep 1
            kill -KILL "$module_pid" 2>/dev/null
            wait "$module_pid" 2>/dev/null
        fi
        echo -e "  ${FAILURE}[!] Module cancelled.${NC}"
        echo
        read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
        trap - INT
        return 1
    }

# MODULE TIMEOUT CONFIG

    case "$module_name" in

        detect_suspicious_net_linux.sh)
            module_timeout=800
            ;;

        forensic_collect.sh)
            module_timeout=400
            ;;

        malware_analysis.sh)
            module_timeout=600
            ;;

        lateral_movement_detect.sh)
            module_timeout=300
            ;;

        log_analysis.sh)
            module_timeout=300
            ;;

        cloud_exposure_audit.sh)
            module_timeout=200
            ;;

        data_exfil_detect.sh)
            module_timeout=300
            ;;

        *)
            module_timeout=200
            ;;
    esac

# RUN HEADER
    clear
    show_banner
    local W=60
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${ACCENT}[>] RUNNING: %-$((W-14))s${NC}  ${BORDER}|${NC}\n" "$module_name"
    echo -e "${BORDER}${border}${NC}"
    echo
    kv "  Module"  "$module_path"
    kv "  Log"     "$log_file"
    kv "  Timeout" "${module_timeout}s"
    echo

# MODULE WARNINGS
    case "$module_name" in

        detect_suspicious_net_linux.sh)
            echo -e "  ${WARNING}[~] This module may take several minutes."
            ;;

        malware_analysis.sh)
            echo -e "  ${WARNING}[~] Performs static & dynamic analysis."
            ;;

        lateral_movement_detect.sh)
            echo -e "  ${WARNING}[~] Analyses authentication logs."
            ;;

        log_analysis.sh)
            echo -e "  ${WARNING}[~] Parses system logs for threat indicators."
            ;;

        cloud_exposure_audit.sh)
            echo -e "  ${WARNING}[~] Probes cloud metadata services."
            ;;

        data_exfil_detect.sh)
            echo -e "  ${WARNING}[~] Scans for data exfiltration patterns."
            ;;
    esac
    echo

# PRE-FLIGHT CHECKS
    mkdir -p "$OUTPUT_DIR" || {
        log_error "Failed to create output directory: $OUTPUT_DIR"
        return 1
    }
    chmod +x "$module_path" 2>/dev/null
    echo "=== Execution started at $(date) ===" > "$log_file"
    echo -e "  ${DARK_GRAY}$(printf '%*s' "$W" '' | tr ' ' '-')${NC}"
    echo


# START MODULE
    (
        cd "$OUTPUT_DIR" || {
            echo "Failed to enter OUTPUT_DIR" >> "$log_file"
            exit 1
        }

        if [ -n "$module_timeout" ]; then
            timeout "$module_timeout" "$module_path" "${module_args[@]}"
        else
            "$module_path" "${module_args[@]}"
        fi

    ) > >(tee -a "$log_file") 2>&1 &

    module_pid=$!

    echo -e "  ${INFO}[i] Module running (PID: $module_pid)"
    echo -e "  ${MUTED}    Press 'q' to cancel"
    echo

# MONITOR LOOP
    while kill -0 "$module_pid" 2>/dev/null; do
        if read -t 0.1 -n 1 key 2>/dev/null; then
            if [[ "$key" == "q" || "$key" == "Q" ]]; then
                echo
                echo -e "  ${WARNING}[~] Cancelling module..."

                kill -TERM "$module_pid" 2>/dev/null
                sleep 1

                kill -KILL "$module_pid" 2>/dev/null

                wait "$module_pid" 2>/dev/null

                echo -e "  ${FAILURE}[!] Module cancelled by user"
                echo
                read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
                return 1
            fi
        fi
        sleep 1
    done

# MODULE RESULT
    wait "$module_pid"
    local exit_code=$?

    echo "=== Execution completed at $(date) (exit: $exit_code) ===" >> "$log_file"
    echo
    echo -e "  ${DARK_GRAY}$(printf '%*s' "$W" '' | tr ' ' '-')${NC}"
    echo

    if [ "$exit_code" -eq 124 ]; then
        echo -e "  ${FAILURE}[!] Module timed out after ${module_timeout}s"
        echo -e "  ${MUTED}Log: ${log_file}"

    elif [ "$exit_code" -eq 0 ]; then

        echo -e "  ${SUCCESS}[+] Module completed successfully"

    else

        echo -e "  ${FAILURE}[!] Module finished with errors (exit: $exit_code)"
        echo -e "  ${MUTED}Log: ${log_file}"
    fi

    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"

    trap - INT
}

run_all_modules() {
    clear
    show_banner
    echo
    echo -e "  ${ACCENT}[>] Running ALL security modules sequentially"
    echo -e "  ${WARNING}[~] This may take a long time"
    echo
    echo -e "  ${PROMPT}Starting in 3 seconds... Press Ctrl+C to cancel.${NC}"
    sleep 3

    execute_module "$MODULES_DIR/analysis/detect_suspicious_net_linux.sh"
    execute_module "$MODULES_DIR/system_security/secure_system.sh"
    execute_module "$MODULES_DIR/system_security/revert_security.sh"
    execute_module "$MODULES_DIR/forensics/system_info.sh"
    execute_module "$MODULES_DIR/forensics/forensic_collect.sh"

    # Web recon requires a target
    DEFAULT_TARGET="example.com"
    target="$DEFAULT_TARGET"

    execute_module "$MODULES_DIR/reconnaissance/web_recon.sh" "$target"
    execute_module "$MODULES_DIR/threat_detection/malware_analysis.sh"
    execute_module "$MODULES_DIR/threat_detection/lateral_movement_detect.sh"
    execute_module "$MODULES_DIR/analysis/log_analysis.sh"
    execute_module "$MODULES_DIR/analysis/cloud_exposure_audit.sh"
    execute_module "$MODULES_DIR/threat_detection/data_exfil_detect.sh"
    echo
    echo -e "  ${SUCCESS}[+] All modules completed."
    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"
}

# MODULE ROUTER
run_modules() {
    local choice="$1"
    case $choice in
        1) execute_module "$MODULES_DIR/analysis/detect_suspicious_net_linux.sh" ;;
        2) execute_module "$MODULES_DIR/system_security/secure_system.sh" ;;
        3) execute_module "$MODULES_DIR/system_security/revert_security.sh" ;;
        4) execute_module "$MODULES_DIR/forensics/system_info.sh" ;;
        5) execute_module "$MODULES_DIR/forensics/forensic_collect.sh" ;;
        6)
            echo
            echo -e "  ${ACCENT}Web Reconnaissance Target Setup${NC}"
            echo -e "  ${DARK_GRAY}---------------------------------${NC}"
            echo
            DEFAULT_TARGET="example.com"
            echo -e "  ${INFO}[i] Examples:"
            echo -e "      example.com"
            echo -e "      https://example.com"
            echo -e "      subdomain.example.com"
            echo
            echo -e "  ${INFO}[i] Press Enter to use default target: ${ACCENT}${DEFAULT_TARGET}${NC}"
            echo
            read -rp "$(echo -e "  ${PROMPT}[?] Target domain or URL [${DEFAULT_TARGET}]: ${NC}")" target
            target="${target:-$DEFAULT_TARGET}"
            echo
            echo -e "  ${SUCCESS}[+] Target selected: ${ACCENT}$target${NC}"
            echo
            read -rp "$(echo -e "  ${PROMPT}Press Enter to start reconnaissance...${NC}")"
            echo
            execute_module "$MODULES_DIR/reconnaissance/web_recon.sh" "$target";;
        7) execute_module "$MODULES_DIR/threat_detection/malware_analysis.sh" ;;
        8) execute_module "$MODULES_DIR/threat_detection/lateral_movement_detect.sh" ;;
        9) execute_module "$MODULES_DIR/analysis/log_analysis.sh" ;;
        10) execute_module "$MODULES_DIR/analysis/cloud_exposure_audit.sh" ;;
        11) execute_module "$MODULES_DIR/threat_detection/data_exfil_detect.sh" ;;
        12) run_all_modules ;;
        0) return ;;
        *)
            log_error "Invalid choice: '${choice}'"
            return 1
            ;;
    esac
}