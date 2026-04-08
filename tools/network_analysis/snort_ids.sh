#!/usr/bin/env bash
# tools/network_analysis/snort_ids.sh
# Snort IDS — start/stop daemon, run one-shot alert mode, view alerts

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

SNORT_CONF="$TOOLS_DIR/configs/snort.conf"
OUTPUT_DIR="$PROJECT_ROOT/output/snort"
LOG_DIR="$PROJECT_ROOT/logs"
SNORT_LOG="$LOG_DIR/snort.log"
SNORT_PID="$LOG_DIR/snort.pid"

mkdir -p "$OUTPUT_DIR"
touch "$SNORT_LOG"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$SNORT_LOG"; }

#  pre-flight 

_check_snort() {
    if ! command -v snort &>/dev/null; then
        log_error "Snort is not installed or not in PATH."
        log_info  "Install via: apt install snort  |  dnf install snort  |  pacman -S snort"
        return 1
    fi
    log_success "Snort found: $(snort --version 2>&1 | head -1)"
}

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
}

#  modes 

_start_daemon() {
    _check_snort || return 1

    if [[ -f "$SNORT_PID" ]] && kill -0 "$(cat "$SNORT_PID")" 2>/dev/null; then
        log_warn "Snort is already running (PID $(cat "$SNORT_PID"))."
        return
    fi

    _pick_interface

    log_info "Starting Snort IDS daemon on $SELECTED_IFACE..."
    snort -D -i "$SELECTED_IFACE" \
          -c "$SNORT_CONF"        \
          -l "$OUTPUT_DIR"        \
          -A fast                 \
          --pid-path "$LOG_DIR"   \
          2>>"$SNORT_LOG" &

    echo $! > "$SNORT_PID"
    _log "Snort daemon started: iface=$SELECTED_IFACE PID=$!"
    log_success "Snort daemon started (PID: $!). Alerts → $OUTPUT_DIR"
}

_stop_daemon() {
    if [[ ! -f "$SNORT_PID" ]]; then
        log_warn "No PID file found. Snort may not be running."
        return
    fi

    local pid
    pid=$(cat "$SNORT_PID")

    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        rm -f "$SNORT_PID"
        _log "Snort daemon stopped (PID $pid)"
        log_success "Snort stopped."
    else
        log_warn "Stale PID file. Removing."
        rm -f "$SNORT_PID"
    fi
}

_oneshot_alert() {
    _check_snort || return 1
    _pick_interface

    read -rp "$(echo -e "  ${PROMPT}[?] Packet count (0 = indefinite): ${NC}")" pkt_count
    local count_arg=""
    [[ "$pkt_count" -gt 0 ]] && count_arg="-n $pkt_count"

    log_info "Running Snort in alert mode (Ctrl-C to stop)..."
    # shellcheck disable=SC2086
    snort -i "$SELECTED_IFACE" \
          -c "$SNORT_CONF"     \
          -l "$OUTPUT_DIR"     \
          -A console           \
          $count_arg           \
          2>&1 | tee -a "$SNORT_LOG"
}

_analyse_pcap() {
    _check_snort || return 1

    read -rp "$(echo -e "  ${PROMPT}[?] Path to .pcap file: ${NC}")" pcap_file
    [[ ! -f "$pcap_file" ]] && log_error "File not found." && return 1

    local report="$OUTPUT_DIR/snort_pcap_$(date '+%Y%m%d_%H%M%S').log"
    log_info "Running Snort against pcap: $pcap_file"
    snort -r "$pcap_file" \
          -c "$SNORT_CONF" \
          -A fast          \
          -l "$OUTPUT_DIR" \
          2>&1 | tee "$report"
    log_success "Analysis complete. Report: $report"
    _log "pcap analysis: $pcap_file → $report"
}

_view_alerts() {
    local alert_file="$OUTPUT_DIR/alert"
    if [[ ! -f "$alert_file" ]]; then
        log_warn "No alert file found at $alert_file"
        log_info "Run Snort first to generate alerts."
        return
    fi
    echo
    echo -e "  ${LABEL}Last 50 Snort alerts:${NC}"
    echo
    tail -50 "$alert_file"
}

_status() {
    if [[ -f "$SNORT_PID" ]] && kill -0 "$(cat "$SNORT_PID")" 2>/dev/null; then
        kv "  Snort status" "${SUCCESS}Running${NC} (PID: $(cat "$SNORT_PID"))"
    else
        kv "  Snort status" "${FAILURE}Not running${NC}"
    fi
    kv "  Config" "$SNORT_CONF"
    kv "  Alert dir" "$OUTPUT_DIR"
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}Snort IDS${NC}"
echo
_status
echo
echo -e "  ${GREEN}  1.${NC}  Start Snort daemon"
echo -e "  ${GREEN}  2.${NC}  Stop Snort daemon"
echo -e "  ${GREEN}  3.${NC}  One-shot alert mode (console)"
echo -e "  ${GREEN}  4.${NC}  Analyse pcap file"
echo -e "  ${GREEN}  5.${NC}  View recent alerts"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _start_daemon  ;;
    2) _stop_daemon   ;;
    3) _oneshot_alert ;;
    4) _analyse_pcap  ;;
    5) _view_alerts   ;;
    0) exit 0         ;;
    *) log_error "Invalid choice." ;;
esac