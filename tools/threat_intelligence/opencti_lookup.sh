#!/usr/bin/env bash
# tools/threat_intelligence/opencti_lookup.sh
# OpenCTI — query indicators, observables, and threat actors via GraphQL API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/opencti"
LOG_FILE="$PROJECT_ROOT/logs/opencti.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  config 
OPENCTI_URL="${OPENCTI_URL:-http://localhost:8080}"
OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"
OPENCTI_VERIFY_SSL="${OPENCTI_VERIFY_SSL:-true}"

_ssl_flag() { [[ "$OPENCTI_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

#  GraphQL query helper 

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

#  auth check 

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

#  lookups 

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

_search_indicator() {
    local pattern="$1"
    local query
    query=$(cat <<GQL
{
  indicators(search: "${pattern}", first: 20) {
    edges {
      node {
        id
        name
        pattern
        valid_from
        valid_until
        confidence
        x_opencti_score
      }
    }
  }
}
GQL
)
    log_info "Searching indicators: $pattern"
    _log "indicator search: $pattern"

    local out_file="$OUTPUT_DIR/opencti_ind_$(date '+%Y%m%d_%H%M%S').json"
    _gql "$query" | _pretty | tee "$out_file"
    echo
    log_success "Saved: $out_file"
}

_lookup_ip() {
    read -rp "$(echo -e "  ${PROMPT}[?] IP address: ${NC}")" ip
    _search_observable "$ip" "IPv4-Addr"
}

_lookup_domain() {
    read -rp "$(echo -e "  ${PROMPT}[?] Domain: ${NC}")" domain
    _search_observable "$domain" "Domain-Name"
}

_lookup_hash() {
    read -rp "$(echo -e "  ${PROMPT}[?] Hash: ${NC}")" hash
    _search_observable "$hash" "StixFile"
}

_lookup_url() {
    read -rp "$(echo -e "  ${PROMPT}[?] URL: ${NC}")" url
    _search_observable "$url" "Url"
}

_lookup_indicator() {
    read -rp "$(echo -e "  ${PROMPT}[?] Indicator pattern/name: ${NC}")" pat
    _search_indicator "$pat"
}

_recent_reports() {
    log_info "Fetching recent threat reports (last 30)..."
    local query
    query=$(cat <<GQL
{
  reports(first: 30, orderBy: created_at, orderMode: desc) {
    edges {
      node {
        id
        name
        created_at
        confidence
        objectLabel { edges { node { value } } }
      }
    }
  }
}
GQL
)
    _gql "$query" | python3 -c "
import sys, json
data = json.load(sys.stdin)
reports = data.get('data',{}).get('reports',{}).get('edges',[])
print(f\"  {'Date':<13} {'Conf':<6} {'Name'}\")
print('  ' + '-'*70)
for e in reports:
    n = e['node']
    date = n.get('created_at','?')[:10]
    conf = str(n.get('confidence','?'))
    name = n.get('name','?')[:60]
    print(f'  {date:<13} {conf:<6} {name}')
" 2>/dev/null || log_warn "Could not parse reports."
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}OpenCTI Threat Intelligence Platform${NC}"
echo
kv "  OpenCTI URL" "$OPENCTI_URL"
echo

_check_auth || exit 1
echo

echo -e "  ${GREEN}  1.${NC}  IP address lookup"
echo -e "  ${GREEN}  2.${NC}  Domain lookup"
echo -e "  ${GREEN}  3.${NC}  File hash lookup"
echo -e "  ${GREEN}  4.${NC}  URL lookup"
echo -e "  ${GREEN}  5.${NC}  Indicator search"
echo -e "  ${GREEN}  6.${NC}  Recent threat reports"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _lookup_ip        ;;
    2) _lookup_domain    ;;
    3) _lookup_hash      ;;
    4) _lookup_url       ;;
    5) _lookup_indicator ;;
    6) _recent_reports   ;;
    0) exit 0            ;;
    *) log_error "Invalid choice." ;;
esac