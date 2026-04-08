#!/usr/bin/env bash
# tools/threat_intelligence/opencti_lookup.sh
# OpenCTI — query indicators, observables, and threat actors via GraphQL API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/opencti"
LOG_FILE="$PROJECT_ROOT/logs/opencti.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

OPENCTI_URL="${OPENCTI_URL:-http://localhost:8080}"
OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"
OPENCTI_VERIFY_SSL="${OPENCTI_VERIFY_SSL:-true}"

_ssl_flag() { [[ "$OPENCTI_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

_gql() {
    local query="$1"
    local payload
    payload=$(python3 -c "import json,sys; print(json.dumps({'query': sys.argv[1]}))" "$query")
    # shellcheck disable=SC2046
    curl -sf $(_ssl_flag) \
         -X POST \
         -H "Authorization: Bearer $OPENCTI_TOKEN" \
         -H "Content-Type: application/json" \
         -d "$payload" \
         "${OPENCTI_URL}/graphql" 2>>"$LOG_FILE"
}

_pretty() {
    command -v jq &>/dev/null && jq '.' || cat
}

_check_auth() {
    if [[ -z "$OPENCTI_TOKEN" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] OpenCTI API token: ${NC}")" OPENCTI_TOKEN
        echo
    fi

    local result
    result=$(_gql '{ me { name email } }' 2>/dev/null) || true

    if echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['me']['name'])" 2>/dev/null; then
        log_success "Authenticated to OpenCTI: $OPENCTI_URL"
    else
        log_error "Authentication failed. Check OPENCTI_URL and OPENCTI_TOKEN."
        return 1
    fi
}

_search_observable() {
    local value="$1" obs_type="${2:-}"
    local type_filter=""
    [[ -n "$obs_type" ]] && type_filter=", filters: [{key: \"entity_type\", values: [\"${obs_type}\"]}]"

    local query
    query=$(cat <<GQL
{
  stixCyberObservables(search: "${value}" ${type_filter}, first: 20) {
    edges {
      node {
        id
        entity_type
        observable_value
        created_at
        objectLabel { edges { node { value } } }
      }
    }
  }
}
GQL
)
    log_info "Searching observables: $value"
    _log "observable search: $value type=$obs_type"

    local out_file="$OUTPUT_DIR/opencti_obs_$(date '+%Y%m%d_%H%M%S').json"
    _gql "$query" | _pretty | tee "$out_file"
    echo
    log_success "Saved: $out_file"
}

_lookup_free() {
    read -rp "$(echo -e "  ${PROMPT}[?] Value to search (IP, domain, hash, URL, etc.): ${NC}")" val
    _search_observable "$val" ""
}

clear; show_banner
echo -e "  ${LABEL}OpenCTI Threat Intelligence Platform${NC}"
echo
kv "  OpenCTI URL" "$OPENCTI_URL"
echo
_check_auth || exit 1
echo
_lookup_free