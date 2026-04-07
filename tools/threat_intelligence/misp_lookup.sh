#!/usr/bin/env bash
# tools/threat_intelligence/misp_lookup.sh
# MISP — query attributes (IPs, domains, hashes, CVEs) via REST API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/misp"
LOG_FILE="$PROJECT_ROOT/logs/misp.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  config 
# Override via environment or settings.conf
MISP_URL="${MISP_URL:-https://misp.local}"
MISP_KEY="${MISP_KEY:-}"           # Automation key — prompt if blank
MISP_VERIFY_SSL="${MISP_VERIFY_SSL:-true}"

_ssl_flag() {
    [[ "$MISP_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""
}

#  auth check 

_check_auth() {
    if [[ -z "$MISP_KEY" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] MISP automation key: ${NC}")" MISP_KEY
        echo
    fi

    local rc
    # shellcheck disable=SC2046
    rc=$(curl -sf $(_ssl_flag) \
         -H "Authorization: $MISP_KEY" \
         -H "Accept: application/json"  \
         "${MISP_URL}/users/view/me"    \
         -o /dev/null -w "%{http_code}" 2>/dev/null) || true

    if [[ "$rc" != "200" ]]; then
        log_error "Authentication failed (HTTP $rc). Check MISP_URL and MISP_KEY."
        return 1
    fi
    log_success "Authenticated to MISP: $MISP_URL"
}

#  helpers 

_misp_post() {
    local endpoint="$1" payload="$2"
    # shellcheck disable=SC2046
    curl -sf $(_ssl_flag)                        \
         -X POST                                 \
         -H "Authorization: $MISP_KEY"           \
         -H "Accept: application/json"           \
         -H "Content-Type: application/json"     \
         -d "$payload"                           \
         "${MISP_URL}${endpoint}" 2>>"$LOG_FILE"
}

_pretty() {
    if command -v jq &>/dev/null; then
        jq '.'
    else
        cat
    fi
}

#  lookups 

_search_value() {
    local value="$1" type="$2"
    local label="${type:-any}"
    log_info "Searching MISP for: $value (type: $label)"
    _log "search: value=$value type=$type"

    local payload
    if [[ -n "$type" ]]; then
        payload="{\"returnFormat\":\"json\",\"value\":\"${value}\",\"type\":\"${type}\",\"limit\":50}"
    else
        payload="{\"returnFormat\":\"json\",\"value\":\"${value}\",\"limit\":50}"
    fi

    local out_file="$OUTPUT_DIR/misp_$(date '+%Y%m%d_%H%M%S')_${value//\//_}.json"
    _misp_post "/attributes/restSearch" "$payload" | _pretty | tee "$out_file"
    echo
    log_success "Result saved: $out_file"
    _log "result: $out_file"
}

_lookup_ip() {
    read -rp "$(echo -e "  ${PROMPT}[?] IP address: ${NC}")" ip
    _search_value "$ip" "ip-dst|ip-src|ip-dst|ip-src|ip-src/ip"
}

_lookup_domain() {
    read -rp "$(echo -e "  ${PROMPT}[?] Domain: ${NC}")" domain
    _search_value "$domain" "domain|hostname"
}

_lookup_hash() {
    read -rp "$(echo -e "  ${PROMPT}[?] Hash (MD5/SHA1/SHA256): ${NC}")" hash
    # Detect hash type by length
    local htype
    case ${#hash} in
        32) htype="md5"    ;;
        40) htype="sha1"   ;;
        64) htype="sha256" ;;
        *)  htype=""       ;;
    esac
    _search_value "$hash" "$htype"
}

_lookup_cve() {
    read -rp "$(echo -e "  ${PROMPT}[?] CVE ID (e.g. CVE-2024-1234): ${NC}")" cve
    _search_value "$cve" "vulnerability"
}

_lookup_email() {
    read -rp "$(echo -e "  ${PROMPT}[?] Email address: ${NC}")" email
    _search_value "$email" "email-src|email-dst"
}

_lookup_free() {
    read -rp "$(echo -e "  ${PROMPT}[?] Value to search (any type): ${NC}")" val
    _search_value "$val" ""
}

_recent_events() {
    log_info "Fetching recent MISP events (last 7 days)..."
    local payload="{\"returnFormat\":\"json\",\"last\":\"7d\",\"limit\":20}"
    _misp_post "/events/restSearch" "$payload" \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
events = data.get('response', [])
print(f\"  {'Event ID':<10} {'Date':<12} {'Info'}\")
print('  ' + '-'*60)
for e in events:
    ev = e.get('Event', e)
    print(f\"  {ev.get('id','?'):<10} {ev.get('date','?'):<12} {ev.get('info','?')[:60]}\")
" 2>/dev/null || log_warn "Could not parse events response."
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}MISP Threat Intelligence Lookup${NC}"
echo
kv "  MISP URL"   "$MISP_URL"
kv "  SSL verify" "$MISP_VERIFY_SSL"
echo

_check_auth || exit 1
echo

echo -e "  ${GREEN}  1.${NC}  IP address lookup"
echo -e "  ${GREEN}  2.${NC}  Domain / hostname lookup"
echo -e "  ${GREEN}  3.${NC}  File hash lookup (MD5/SHA1/SHA256)"
echo -e "  ${GREEN}  4.${NC}  CVE lookup"
echo -e "  ${GREEN}  5.${NC}  Email lookup"
echo -e "  ${GREEN}  6.${NC}  Free-text search"
echo -e "  ${GREEN}  7.${NC}  Recent events (last 7 days)"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _lookup_ip      ;;
    2) _lookup_domain  ;;
    3) _lookup_hash    ;;
    4) _lookup_cve     ;;
    5) _lookup_email   ;;
    6) _lookup_free    ;;
    7) _recent_events  ;;
    0) exit 0          ;;
    *) log_error "Invalid choice." ;;
esac