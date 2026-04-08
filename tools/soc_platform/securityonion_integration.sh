#!/usr/bin/env bash
# tools/soc_platform/securityonion_integration.sh
# Security Onion — SOC dashboard, alert query, and Hunt/Kibana integration

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/securityonion"
LOG_FILE="$PROJECT_ROOT/logs/securityonion.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  config 
SO_HOST="${SO_HOST:-https://securityonion.local}"
SO_USER="${SO_USER:-}"
SO_PASS="${SO_PASS:-}"
SO_VERIFY_SSL="${SO_VERIFY_SSL:-true}"

# Security Onion REST API (so-api) — available in SO 2.3+
SO_API_KEY="${SO_API_KEY:-}"
SO_API_URL="${SO_API_URL:-${SO_HOST}:9822}"

_ssl_flag() { [[ "$SO_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

_so_api() {
    local method="$1" endpoint="$2" data="${3:-}"
    local args=(-sf -X "$method"
        -H "Authorization: Bearer $SO_API_KEY"
        -H "Content-Type: application/json"
    )
    [[ "$SO_VERIFY_SSL" == "false" ]] && args+=(-k)
    [[ -n "$data" ]] && args+=(-d "$data")
    curl "${args[@]}" "${SO_API_URL}${endpoint}" 2>>"$LOG_FILE"
}

_pretty() { command -v jq &>/dev/null && jq '.' || cat; }

#  auth check 

_check_api() {
    if [[ -z "$SO_API_KEY" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] Security Onion API key: ${NC}")" SO_API_KEY
        echo
    fi

    local rc
    # shellcheck disable=SC2046
    rc=$(curl -sf $(_ssl_flag) \
         -H "Authorization: Bearer $SO_API_KEY" \
         "${SO_API_URL}/api/status" \
         -o /dev/null -w "%{http_code}" 2>/dev/null) || true

    if [[ "$rc" == "200" ]]; then
        log_success "Connected to Security Onion API: $SO_API_URL"
        return 0
    else
        log_warn "SO REST API not reachable (HTTP $rc) — falling back to SSH mode."
        return 1
    fi
}

#  SSH helpers (direct node access) 

_require_ssh() {
    read -rp "$(echo -e "  ${PROMPT}[?] Security Onion manager IP/hostname: ${NC}")" SO_SSH_HOST
    read -rp "$(echo -e "  ${PROMPT}[?] SSH user [analyst]: ${NC}")" SO_SSH_USER
    SO_SSH_USER="${SO_SSH_USER:-analyst}"
}

_ssh_run() {
    local cmd="$1"
    ssh -o StrictHostKeyChecking=accept-new "${SO_SSH_USER}@${SO_SSH_HOST}" "$cmd" 2>>"$LOG_FILE"
}

#  features 

_show_status() {
    if _check_api 2>/dev/null; then
        log_info "Fetching SO status..."
        _so_api GET "/api/status" | _pretty
    else
        _require_ssh
        log_info "Checking SO services via SSH..."
        _ssh_run "sudo so-status 2>/dev/null || sudo systemctl list-units 'so-*' --no-pager" \
            | tee "$OUTPUT_DIR/so_status_$(date '+%Y%m%d_%H%M%S').txt"
    fi
    _log "status check"
}

_query_alerts() {
    _check_api || { _require_ssh; _query_alerts_ssh; return; }

    read -rp "$(echo -e "  ${PROMPT}[?] Hours back to query [24]: ${NC}")" hours
    hours="${hours:-24}"
    read -rp "$(echo -e "  ${PROMPT}[?] Severity filter (low/medium/high/all) [all]: ${NC}")" sev
    sev="${sev:-all}"

    local payload="{\"hours\": ${hours}, \"severity\": \"${sev}\"}"
    log_info "Querying alerts (last ${hours}h, severity=${sev})..."
    _so_api POST "/api/alerts" "$payload" \
    | python3 -c "
import sys, json
alerts = json.load(sys.stdin)
if isinstance(alerts, dict):
    alerts = alerts.get('alerts', [])
print(f\"  {'Time':<22} {'Sev':<8} {'Source IP':<18} {'Rule'}\")
print('  ' + '-'*80)
for a in alerts[:50]:
    ts  = a.get('timestamp','?')[:19]
    sv  = a.get('severity','?')
    src = a.get('src_ip','?')
    rule = a.get('rule_name', a.get('alert',{}).get('signature','?'))[:45]
    print(f'  {ts:<22} {sv:<8} {src:<18} {rule}')
" 2>/dev/null || log_warn "Could not parse alert response." ; \
    _log "alert query: hours=$hours sev=$sev"
}

_query_alerts_ssh() {
    read -rp "$(echo -e "  ${PROMPT}[?] Hours back [24]: ${NC}")" hours
    hours="${hours:-24}"
    log_info "Querying Elasticsearch via SSH for alerts (last ${hours}h)..."
    local out_file="$OUTPUT_DIR/alerts_$(date '+%Y%m%d_%H%M%S').json"
    _ssh_run "sudo so-query alerts ${hours}h 2>/dev/null || \
        curl -sk 'http://localhost:9200/so-*/_search?size=50' -d '{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"now-${hours}h\"}}}}'" \
        | tee "$out_file" | _pretty
    log_success "Saved: $out_file"
}

_hunt_query() {
    log_info "Security Onion Hunt (Kibana / SOC interface)"
    echo
    echo -e "  ${LABEL}Hunt URL:${NC}  ${SO_HOST}/hunt"
    echo
    echo -e "  Open the URL above in your browser to use the Hunt interface."
    echo -e "  Alternatively, run a raw Elasticsearch query:"
    echo
    read -rp "$(echo -e "  ${PROMPT}[?] Enter Lucene/KQL query (blank to skip): ${NC}")" kql
    [[ -z "$kql" ]] && return

    read -rp "$(echo -e "  ${PROMPT}[?] Index pattern [so-*]: ${NC}")" idx
    idx="${idx:-so-*}"

    _require_ssh

    log_info "Running Elasticsearch query via SSH..."
    local esc_kql
    esc_kql=$(python3 -c "import sys,json; print(json.dumps(sys.argv[1]))" "$kql")
    local payload="{\"query\":{\"query_string\":{\"query\":${esc_kql}}},\"size\":50}"
    local out_file="$OUTPUT_DIR/hunt_$(date '+%Y%m%d_%H%M%S').json"

    _ssh_run "curl -sk 'http://localhost:9200/${idx}/_search' -H 'Content-Type: application/json' -d '${payload}'" \
        | tee "$out_file" | _pretty
    log_success "Results saved: $out_file"
    _log "hunt query: $kql → $out_file"
}

_pcap_export() {
    _require_ssh
    read -rp "$(echo -e "  ${PROMPT}[?] Source IP: ${NC}")" src_ip
    read -rp "$(echo -e "  ${PROMPT}[?] Destination IP: ${NC}")" dst_ip
    read -rp "$(echo -e "  ${PROMPT}[?] Start time (YYYY-MM-DD HH:MM): ${NC}")" start_dt
    read -rp "$(echo -e "  ${PROMPT}[?] End time   (YYYY-MM-DD HH:MM): ${NC}")" end_dt

    local remote_pcap="/tmp/so_export_$(date '+%Y%m%d_%H%M%S').pcap"
    local local_pcap="$OUTPUT_DIR/$(basename "$remote_pcap")"

    log_info "Requesting PCAP export from Security Onion..."
    _ssh_run "sudo so-pcap --src '${src_ip}' --dst '${dst_ip}' \
              --start '${start_dt}' --end '${end_dt}' \
              --out '${remote_pcap}' 2>/dev/null \
              || sudo tcpdump -r /nsm/pcap/*.pcap \
                 -w '${remote_pcap}' \
                 host ${src_ip} and host ${dst_ip} 2>/dev/null" || true

    log_info "Downloading pcap..."
    scp "${SO_SSH_USER}@${SO_SSH_HOST}:${remote_pcap}" "$local_pcap" && \
        log_success "PCAP saved: $local_pcap" || \
        log_warn "Could not download pcap. Check SO permissions."
    _log "pcap export: src=$src_ip dst=$dst_ip → $local_pcap"
}

_open_browser() {
    local url="$SO_HOST"
    echo -e "  ${LABEL}Security Onion URL:${NC}  $url"
    echo
    if command -v xdg-open &>/dev/null && [[ -n "${DISPLAY:-}" ]]; then
        xdg-open "$url" &>/dev/null &
        log_success "Opened in browser."
    elif command -v firefox &>/dev/null && [[ -n "${DISPLAY:-}" ]]; then
        firefox "$url" &>/dev/null &
        log_success "Firefox launched."
    else
        log_info "No browser available. Navigate to: $url"
    fi
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}Security Onion — SOC Platform Integration${NC}"
echo
kv "  SO host"    "$SO_HOST"
kv "  API URL"    "$SO_API_URL"
echo

echo -e "  ${GREEN}  1.${NC}  Show Security Onion status"
echo -e "  ${GREEN}  2.${NC}  Query recent alerts"
echo -e "  ${GREEN}  3.${NC}  Hunt / Elasticsearch query"
echo -e "  ${GREEN}  4.${NC}  Export PCAP (SSH)"
echo -e "  ${GREEN}  5.${NC}  Open SO in browser"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _show_status   ;;
    2) _query_alerts  ;;
    3) _hunt_query    ;;
    4) _pcap_export   ;;
    5) _open_browser  ;;
    0) exit 0         ;;
    *) log_error "Invalid choice." ;;
esac