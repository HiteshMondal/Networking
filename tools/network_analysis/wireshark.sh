#!/usr/bin/env bash
# tools/network_analysis/wireshark.sh
# Wireshark / tshark packet capture & analysis helper

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/wireshark"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$PROJECT_ROOT/logs/wireshark.log"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  interface picker 

_pick_interface() {
    echo -e "  ${LABEL}Available interfaces:${NC}"
    echo
    local ifaces=()
    while IFS= read -r iface; do
        ifaces+=("$iface")
    done < <(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')

    local i=1
    for iface in "${ifaces[@]}"; do
        printf "  ${GREEN}%3d.${NC}  %s\n" "$i" "$iface"
        (( i++ ))
    done

    echo
    read -rp "$(echo -e "  ${PROMPT}[?] Select interface number: ${NC}")" idx
    SELECTED_IFACE="${ifaces[$((idx-1))]}"
    log_success "Selected: $SELECTED_IFACE"
}

#  capture with tshark 

_tshark_capture() {
    if ! command -v tshark &>/dev/null; then
        log_error "tshark not found. Install wireshark-common / tshark."
        return 1
    fi

    _pick_interface
    local cap_file="$OUTPUT_DIR/capture_$(date '+%Y%m%d_%H%M%S').pcap"

    read -rp "$(echo -e "  ${PROMPT}[?] Capture duration in seconds (0 = until Ctrl-C): ${NC}")" duration
    read -rp "$(echo -e "  ${PROMPT}[?] BPF filter (leave blank for none): ${NC}")" bpf_filter

    local tshark_args=(-i "$SELECTED_IFACE" -w "$cap_file")
    [[ "$duration" -gt 0 ]] && tshark_args+=(-a "duration:${duration}")
    [[ -n "$bpf_filter" ]] && tshark_args+=("$bpf_filter")

    log_info "Starting capture on $SELECTED_IFACE → $cap_file"
    _log "tshark capture: iface=$SELECTED_IFACE filter='$bpf_filter' duration=${duration}s"

    tshark "${tshark_args[@]}" 2>&1 | tee -a "$LOG_FILE" || true

    log_success "Capture saved: $cap_file"
}

#  read & analyse pcap 

_tshark_analyse() {
    if ! command -v tshark &>/dev/null; then
        log_error "tshark not found."
        return 1
    fi

    read -rp "$(echo -e "  ${PROMPT}[?] Path to .pcap file: ${NC}")" pcap_file
    [[ ! -f "$pcap_file" ]] && log_error "File not found: $pcap_file" && return 1

    echo
    echo -e "  ${LABEL}Analysis options:${NC}"
    echo -e "  ${GREEN}  1.${NC}  Protocol hierarchy"
    echo -e "  ${GREEN}  2.${NC}  Top talkers (IP endpoints)"
    echo -e "  ${GREEN}  3.${NC}  DNS queries"
    echo -e "  ${GREEN}  4.${NC}  HTTP requests"
    echo -e "  ${GREEN}  5.${NC}  Custom display filter"
    echo
    read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" ac

    case $ac in
        1) tshark -r "$pcap_file" -qz "io,phs" 2>&1 | tee -a "$LOG_FILE" ;;
        2) tshark -r "$pcap_file" -qz "conv,ip" 2>&1 | tee -a "$LOG_FILE" ;;
        3) tshark -r "$pcap_file" -Y "dns" -T fields \
               -e frame.time -e ip.src -e dns.qry.name 2>&1 | tee -a "$LOG_FILE" ;;
        4) tshark -r "$pcap_file" -Y "http.request" -T fields \
               -e frame.time -e ip.src -e http.host -e http.request.uri 2>&1 | tee -a "$LOG_FILE" ;;
        5)
            read -rp "$(echo -e "  ${PROMPT}[?] Display filter: ${NC}")" df
            tshark -r "$pcap_file" -Y "$df" 2>&1 | tee -a "$LOG_FILE"
            ;;
        *) log_error "Invalid choice." ;;
    esac
}

#  launch Wireshark GUI 

_wireshark_gui() {
    if ! command -v wireshark &>/dev/null; then
        log_error "Wireshark GUI not found. Install 'wireshark'."
        log_info  "Falling back to tshark for CLI capture."
        _tshark_capture
        return
    fi

    # Allow non-root GUI launch safely via xhost or DISPLAY check
    if [[ -z "${DISPLAY:-}" ]]; then
        log_warn "No DISPLAY detected. Launching tshark capture instead."
        _tshark_capture
        return
    fi

    log_info "Launching Wireshark GUI..."
    _log "Wireshark GUI launched"
    wireshark &>/dev/null &
    disown
    log_success "Wireshark started (background PID: $!)"
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}Wireshark / tshark${NC}"
echo
echo -e "  ${GREEN}  1.${NC}  Launch Wireshark GUI"
echo -e "  ${GREEN}  2.${NC}  Capture packets (tshark)"
echo -e "  ${GREEN}  3.${NC}  Analyse existing .pcap"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _wireshark_gui    ;;
    2) _tshark_capture   ;;
    3) _tshark_analyse   ;;
    0) exit 0            ;;
    *) log_error "Invalid choice." ;;
esac