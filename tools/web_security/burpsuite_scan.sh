#!/usr/bin/env bash
# tools/web_security/burpsuite_scan.sh
# Burp Suite — launch GUI, manage proxy, and trigger REST API scans

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/burpsuite"
LOG_FILE="$PROJECT_ROOT/logs/burpsuite.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  Burp Suite Enterprise / Pro REST API defaults 
BURP_API_URL="${BURP_API_URL:-http://127.0.0.1:1337}"
BURP_API_KEY="${BURP_API_KEY:-}"       # Set or will prompt

#  locate Burp Suite jar / binary 

_find_burp() {
    # Common install locations
    local candidates=(
        /usr/bin/burpsuite
        /opt/BurpSuitePro/burpsuite_pro.jar
        /opt/BurpSuiteCommunity/burpsuite_community.jar
        /usr/share/burpsuite/burpsuite.jar
        "$HOME/BurpSuitePro/burpsuite_pro.jar"
        "$HOME/BurpSuiteCommunity/burpsuite_community.jar"
    )
    for c in "${candidates[@]}"; do
        [[ -f "$c" || -x "$c" ]] && echo "$c" && return 0
    done
    return 1
}

#  launch GUI 

_launch_gui() {
    if [[ -z "${DISPLAY:-}" ]]; then
        log_error "No DISPLAY set. Cannot launch Burp Suite GUI in headless environment."
        return 1
    fi

    local burp_path
    if burp_path=$(_find_burp 2>/dev/null); then
        log_info "Found Burp Suite: $burp_path"
        if [[ "$burp_path" == *.jar ]]; then
            java -jar "$burp_path" &>/dev/null &
        else
            "$burp_path" &>/dev/null &
        fi
        disown
        log_success "Burp Suite launched (PID: $!)"
        _log "GUI launched: $burp_path"
    else
        log_error "Burp Suite not found."
        log_info  "Download from: https://portswigger.net/burp"
        log_info  "Or install via: apt install burpsuite  (Kali)"
    fi
}

#  REST API: Burp Suite Enterprise / Pro 

_api_check() {
    if [[ -z "$BURP_API_KEY" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] Burp API key: ${NC}")" BURP_API_KEY
        echo
    fi

    if ! curl -sf -H "Authorization: $BURP_API_KEY" \
         "${BURP_API_URL}/api/v0.1/sites" &>/dev/null; then
        log_error "Cannot reach Burp Suite REST API at $BURP_API_URL"
        log_info  "Ensure Burp Suite Enterprise is running with REST API enabled."
        return 1
    fi
}

_api_scan() {
    _api_check || return 1

    read -rp "$(echo -e "  ${PROMPT}[?] Target URL to scan: ${NC}")" target_url
    [[ -z "$target_url" ]] && log_error "No URL entered." && return 1

    local scan_name="toolkit_$(date '+%Y%m%d_%H%M%S')"
    local payload
    payload=$(cat <<EOF
{
  "scan_configurations": [{"name":"Crawl and Audit - Fast","type":"NamedConfiguration"}],
  "urls": ["${target_url}"],
  "name": "${scan_name}"
}
EOF
)

    log_info "Starting Burp Suite API scan: $target_url"
    local response
    response=$(curl -sf -X POST \
        -H "Authorization: $BURP_API_KEY" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "${BURP_API_URL}/api/v0.1/scan") || {
        log_error "API request failed."
        return 1
    }

    local scan_id
    scan_id=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan_id',''))" 2>/dev/null || true)
    [[ -z "$scan_id" ]] && log_error "No scan_id in response: $response" && return 1

    log_success "Scan started. ID: $scan_id"
    _log "API scan: url=$target_url scan_id=$scan_id"
    echo
    log_info "Poll status: curl -H 'Authorization: $BURP_API_KEY' ${BURP_API_URL}/api/v0.1/scan/${scan_id}"
}

_api_list_scans() {
    _api_check || return 1
    log_info "Fetching scan list..."
    curl -sf -H "Authorization: $BURP_API_KEY" \
         "${BURP_API_URL}/api/v0.1/scan" \
    | python3 -c "
import sys, json
scans = json.load(sys.stdin)
print(f\"  {'ID':<8} {'Status':<15} {'URL'}\")
print('  ' + '-'*60)
for s in scans:
    sid    = str(s.get('scan_id','?'))
    status = s.get('scan_status','?')
    urls   = ', '.join(s.get('urls',[]))
    print(f'  {sid:<8} {status:<15} {urls}')
" 2>/dev/null || log_warn "Could not parse scan list."
}

#  proxy helper 

_proxy_guide() {
    echo
    echo -e "  ${LABEL}Burp Suite Proxy Setup${NC}"
    echo
    echo -e "  ${AMBER}Default proxy:${NC}   127.0.0.1:8080"
    echo
    echo -e "  ${LABEL}Configure browser:${NC}"
    echo -e "  Firefox → Settings → Network → Manual proxy → HTTP: 127.0.0.1:8080"
    echo
    echo -e "  ${LABEL}Export CA cert for HTTPS interception:${NC}"
    echo -e "  Navigate to http://burp/ in the proxied browser → CA Certificate"
    echo
    echo -e "  ${LABEL}Useful curl example:${NC}"
    echo -e "  ${MUTED}curl -x http://127.0.0.1:8080 --proxy-insecure https://target.example.com${NC}"
    echo
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}Burp Suite — Web Application Security Testing${NC}"
echo
kv "  API endpoint" "$BURP_API_URL"
echo
echo -e "  ${GREEN}  1.${NC}  Launch Burp Suite GUI"
echo -e "  ${GREEN}  2.${NC}  Start scan via REST API (Enterprise/Pro)"
echo -e "  ${GREEN}  3.${NC}  List active scans (REST API)"
echo -e "  ${GREEN}  4.${NC}  Proxy setup guide"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _launch_gui      ;;
    2) _api_scan        ;;
    3) _api_list_scans  ;;
    4) _proxy_guide     ;;
    0) exit 0           ;;
    *) log_error "Invalid choice." ;;
esac