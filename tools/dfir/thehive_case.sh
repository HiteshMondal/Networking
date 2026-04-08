#!/usr/bin/env bash
# tools/dfir/thehive_case.sh
# TheHive — create & manage incident response cases via REST API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/thehive"
LOG_FILE="$PROJECT_ROOT/logs/thehive.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
THEHIVE_KEY="${THEHIVE_KEY:-}"
THEHIVE_ORG="${THEHIVE_ORG:-}"
THEHIVE_VERIFY_SSL="${THEHIVE_VERIFY_SSL:-true}"

_ssl_flag() { [[ "$THEHIVE_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

_hive() {
    local method="$1" endpoint="$2" data="${3:-}"
    local curl_args=(-sf -X "$method"
        -H "Authorization: Bearer $THEHIVE_KEY"
        -H "Content-Type: application/json"
    )
    # shellcheck disable=SC2046
    [[ "$THEHIVE_VERIFY_SSL" == "false" ]] && curl_args+=(-k)
    [[ -n "$data" ]] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" "${THEHIVE_URL}${endpoint}" 2>>"$LOG_FILE"
}

_pretty() { command -v jq &>/dev/null && jq '.' || cat; }

_check_auth() {
    if [[ -z "$THEHIVE_KEY" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] TheHive API key: ${NC}")" THEHIVE_KEY
        echo
    fi

    local rc
    # shellcheck disable=SC2046
    rc=$(curl -sf $(_ssl_flag) \
         -H "Authorization: Bearer $THEHIVE_KEY" \
         "${THEHIVE_URL}/api/v1/user/current" \
         -o /dev/null -w "%{http_code}" 2>/dev/null) || true

    if [[ "$rc" != "200" ]]; then
        log_error "Cannot authenticate to TheHive (HTTP $rc)."
        log_info  "Check THEHIVE_URL=$THEHIVE_URL and THEHIVE_KEY."
        return 1
    fi
    log_success "Connected to TheHive: $THEHIVE_URL"
}

_list_cases() {
    log_info "Fetching open cases..."
    _hive POST "/api/v1/case/_search" \
        '{"query":[{"_name":"listCase"},{"_name":"filter","_not":{"_field":"status","_value":"Resolved"}}],"ranges":["0-30"]}' \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
if not isinstance(data, list):
    print('  Unexpected response format.')
    sys.exit(0)
print(f\"  {'ID':<26} {'Sev':<5} {'Status':<12} {'Title'}\")
print('  ' + '-'*70)
for c in data:
    cid    = c.get('_id', '?')[:24]
    sev    = str(c.get('severity','?'))
    status = c.get('status','?')
    title  = c.get('title','?')[:40]
    print(f'  {cid:<26} {sev:<5} {status:<12} {title}')
" 2>/dev/null || log_warning "Could not parse case list."
}

clear; show_banner
echo -e "  ${LABEL}TheHive — Incident Response Case Manager${NC}"
echo
kv "  TheHive URL" "$THEHIVE_URL"
echo
_check_auth || exit 1
echo
_list_cases