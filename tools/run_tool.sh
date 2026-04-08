#!/usr/bin/env bash
# tools/run_tool.sh
# Networking & Cybersecurity Toolkit — Tools Hub
# Provides a unified menu for all advanced security tools

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

#  helpers 

_tool_header() {
    local title="$1"
    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '-')
    echo
    echo -e "  ${BORDER}${border}${NC}"
    printf "  ${BORDER}│${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}│${NC}\n" "$title"
    echo -e "  ${BORDER}${border}${NC}"
    echo
}

_require_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        log_error "'${tool}' is not installed or not in PATH."
        log_info  "Install it first, then re-run this option."
        return 1
    fi
}

_pause() {
    echo
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

#  sub-menus 

_menu_network_analysis() {
    while true; do
        clear; show_banner
        _tool_header "Network Analysis"
        echo -e "  ${GREEN}  1.${NC}  Wireshark (packet capture / GUI)"
        echo -e "  ${GREEN}  2.${NC}  Snort IDS (intrusion detection)"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/network_analysis/wireshark.sh"    ; _pause ;;
            2) bash "$TOOLS_DIR/network_analysis/snort_ids.sh"    ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

_menu_vuln_scan() {
    while true; do
        clear; show_banner
        _tool_header "Vulnerability Scanning"
        echo -e "  ${GREEN}  1.${NC}  OpenVAS Scan"
        echo -e "  ${GREEN}  2.${NC}  Kube-Hunter (Kubernetes)"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/vulnerability_scanning/openvas_scan.sh"    ; _pause ;;
            2) bash "$TOOLS_DIR/vulnerability_scanning/kubehunter_scan.sh" ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

_menu_static_analysis() {
    while true; do
        clear; show_banner
        _tool_header "Static Analysis"
        echo -e "  ${GREEN}  1.${NC}  Semgrep Scan"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/static_analysis/semgrep_scan.sh" ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

_menu_web_security() {
    while true; do
        clear; show_banner
        _tool_header "Web Security"
        echo -e "  ${GREEN}  1.${NC}  Burp Suite Scan"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/web_security/burpsuite_scan.sh" ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

_menu_threat_intel() {
    while true; do
        clear; show_banner
        _tool_header "Threat Intelligence"
        echo -e "  ${GREEN}  1.${NC}  MISP Lookup"
        echo -e "  ${GREEN}  2.${NC}  OpenCTI Lookup"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/threat_intelligence/misp_lookup.sh"   ; _pause ;;
            2) bash "$TOOLS_DIR/threat_intelligence/opencti_lookup.sh" ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

_menu_re() {
    while true; do
        clear; show_banner
        _tool_header "Reverse Engineering"
        echo -e "  ${GREEN}  1.${NC}  Ghidra Launcher"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/reverse_engineering/ghidra_launcher.sh" ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

_menu_dfir() {
    while true; do
        clear; show_banner
        _tool_header "DFIR — Digital Forensics & Incident Response"
        echo -e "  ${GREEN}  1.${NC}  TheHive Case Manager"
        echo -e "  ${GREEN}  2.${NC}  IRIS Incident Response"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/dfir/thehive_case.sh" ; _pause ;;
            2) bash "$TOOLS_DIR/dfir/iris_ir.sh"      ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

_menu_soc() {
    while true; do
        clear; show_banner
        _tool_header "SOC Platform"
        echo -e "  ${GREEN}  1.${NC}  Security Onion Integration"
        echo -e "  ${RED}  0.${NC}  Back"
        echo
        read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ch
        case $ch in
            1) bash "$TOOLS_DIR/soc_platform/securityonion_integration.sh" ; _pause ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}

#  main menu 

show_tools_menu() {
    local W=50
    local border
    border=$(printf '%*s' "$W" '' | tr ' ' '=')

    echo -e "${BORDER}${border}${NC}"
    printf "${BORDER}|${NC}  ${TITLE}%-$((W-4))s${NC}  ${BORDER}|${NC}\n" "TOOLS HUB"
    echo -e "${BORDER}${border}${NC}"
    echo
    echo -e "  ${LABEL}NETWORK${NC}"
    echo -e "  ${GREEN}  1.${NC}  Network Analysis     (Wireshark, Snort)"
    echo
    echo -e "  ${LABEL}SCANNING${NC}"
    echo -e "  ${GREEN}  2.${NC}  Vulnerability Scan   (OpenVAS, Kube-Hunter)"
    echo -e "  ${GREEN}  3.${NC}  Static Analysis      (Semgrep)"
    echo -e "  ${GREEN}  4.${NC}  Web Security         (Burp Suite)"
    echo
    echo -e "  ${LABEL}INTELLIGENCE${NC}"
    echo -e "  ${GREEN}  5.${NC}  Threat Intelligence  (MISP, OpenCTI)"
    echo
    echo -e "  ${LABEL}ADVANCED${NC}"
    echo -e "  ${GREEN}  6.${NC}  Reverse Engineering  (Ghidra)"
    echo -e "  ${GREEN}  7.${NC}  DFIR                 (TheHive, IRIS)"
    echo -e "  ${GREEN}  8.${NC}  SOC Platform         (Security Onion)"
    echo
    echo -e "  ${RED}  0.${NC}  Back to Main Menu"
    echo
    echo -e "${BORDER}${border}${NC}"
}

run_tools_hub() {
    while true; do
        clear
        show_banner
        show_tools_menu
        read -rp "$(echo -e "  ${PROMPT}[?] Enter your choice: ${NC}")" choice
        echo
        case $choice in
            1) _menu_network_analysis ;;
            2) _menu_vuln_scan        ;;
            3) _menu_static_analysis  ;;
            4) _menu_web_security     ;;
            5) _menu_threat_intel     ;;
            6) _menu_re               ;;
            7) _menu_dfir             ;;
            8) _menu_soc              ;;
            0) break ;;
            *) log_error "Invalid choice." ; sleep 1 ;;
        esac
    done
}