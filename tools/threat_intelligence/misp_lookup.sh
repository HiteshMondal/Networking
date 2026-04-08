#!/usr/bin/env bash
# tools/threat_intelligence/misp_lookup.sh
# MISP — query attributes (IPs, domains, hashes, CVEs) via REST API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/misp"
LOG_FILE="$PROJECT_ROOT/logs/misp.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

MISP_URL="${MISP_URL:-https://misp.local}"
MISP_KEY="${MISP_KEY:-}"
MISP_VERIFY_SSL="${MISP_VERIFY_SSL:-true}"

_ssl_flag() {
    [[ "$MISP_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""
}

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
    command -v jq &>/dev/null && jq '.' || cat
}

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

_lookup_free() {
    read -rp "$(echo -e "  ${PROMPT}[?] Value to search (IP, domain, hash, CVE, email, etc.): ${NC}")" val
    _search_value "$val" ""
}

clear; show_banner
echo -e "  ${LABEL}MISP Threat Intelligence Lookup${NC}"
echo
kv "  MISP URL"   "$MISP_URL"
kv "  SSL verify" "$MISP_VERIFY_SSL"
echo
_check_auth || exit 1
echo
_lookup_free