#!/usr/bin/env bash
# tools/dfir/iris_ir.sh
# IRIS (dfir-iris) — incident response & case management via REST API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/iris"
LOG_FILE="$PROJECT_ROOT/logs/iris.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

IRIS_URL="${IRIS_URL:-https://localhost}"
IRIS_TOKEN="${IRIS_TOKEN:-}"
IRIS_VERIFY_SSL="${IRIS_VERIFY_SSL:-true}"

_ssl_flag() { [[ "$IRIS_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

_iris() {
    local method="$1" endpoint="$2" data="${3:-}"
    local curl_args=(-sf -X "$method"
        -H "Authorization: Bearer $IRIS_TOKEN"
        -H "Content-Type: application/json"
    )
    [[ "$IRIS_VERIFY_SSL" == "false" ]] && curl_args+=(-k)
    [[ -n "$data" ]] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" "${IRIS_URL}${endpoint}" 2>>"$LOG_FILE"
}

_pretty() { command -v jq &>/dev/null && jq '.' || cat; }

_check_auth() {
    if [[ -z "$IRIS_TOKEN" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] IRIS API token: ${NC}")" IRIS_TOKEN
        echo
    fi

    local rc
    # shellcheck disable=SC2046
    rc=$(curl -sf $(_ssl_flag) \
         -H "Authorization: Bearer $IRIS_TOKEN" \
         "${IRIS_URL}/api/v2/users/me" \
         -o /dev/null -w "%{http_code}" 2>/dev/null) || true

    if [[ "$rc" != "200" ]]; then
        log_error "Cannot authenticate to IRIS (HTTP $rc)."
        log_info  "Check IRIS_URL=$IRIS_URL and IRIS_TOKEN."
        return 1
    fi
    log_success "Authenticated to IRIS: $IRIS_URL"
}

_list_cases() {
    log_info "Fetching case list..."
    _iris GET "/api/v2/cases" | python3 -c "
import sys, json
data = json.load(sys.stdin)
cases = data.get('data', {}).get('cases', [])
print(f\"  {'Case ID':<10} {'Status':<12} {'Name'}\")
print('  ' + '-'*60)
for c in cases:
    cid    = str(c.get('case_id','?'))
    status = c.get('case_close_date') and 'Closed' or 'Open'
    name   = c.get('case_name','?')[:50]
    print(f'  {cid:<10} {status:<12} {name}')
" 2>/dev/null || log_warning "Could not parse case list."
}

clear; show_banner
echo -e "  ${LABEL}IRIS — Incident Response Platform${NC}"
echo
kv "  IRIS URL" "$IRIS_URL"
echo
_check_auth || exit 1
echo
_list_cases