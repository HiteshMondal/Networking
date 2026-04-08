#!/usr/bin/env bash
# tools/threat_intelligence/opencti_lookup.sh
# OpenCTI — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OPENCTI_URL="${OPENCTI_URL:-http://localhost:8080}"
OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"
OPENCTI_VERIFY_SSL="${OPENCTI_VERIFY_SSL:-true}"

_check_opencti() {
    local curl_ok=false token_set=false

    command -v curl   &>/dev/null && curl_ok=true
    [[ -n "$OPENCTI_TOKEN" ]] && token_set=true

    echo -e "  ${LABEL}Configuration:${NC}"
    echo
    kv "  OpenCTI URL"   "$OPENCTI_URL"
    kv "  Token set"     "$( $token_set && echo "${SUCCESS}yes${NC}" || echo "${FAILURE}no${NC}" )"
    kv "  SSL verify"    "$OPENCTI_VERIFY_SSL"
    echo

    if ! $curl_ok; then
        log_error "curl is not installed — required to talk to the OpenCTI API."
        echo -e "  ${CYAN}Install:${NC}  sudo apt install curl"
        return
    fi

    if $token_set; then
        log_info "Testing connection to $OPENCTI_URL ..."
        local ssl_flag; [[ "$OPENCTI_VERIFY_SSL" == "false" ]] && ssl_flag="-k" || ssl_flag=""
        local payload='{"query":"{ me { name } }"}'
        local rc
        # shellcheck disable=SC2086
        rc=$(curl -sf $ssl_flag \
             -X POST \
             -H "Authorization: Bearer $OPENCTI_TOKEN" \
             -H "Content-Type: application/json" \
             -d "$payload" \
             "${OPENCTI_URL}/graphql" \
             -o /dev/null -w "%{http_code}" 2>/dev/null) || true

        if [[ "$rc" == "200" ]]; then
            log_success "Connected to OpenCTI successfully."
        else
            log_warning "Could not connect to OpenCTI (HTTP $rc). Check URL and token."
        fi
    else
        log_warning "OPENCTI_TOKEN is not set — connection test skipped."
    fi

    echo
    echo -e "  ${LABEL}How to use the OpenCTI GraphQL API:${NC}"
    echo
    echo -e "  ${CYAN}Search observables (IP, domain, hash, URL):${NC}"
    echo -e "    curl -s -X POST \\"
    echo -e "         -H \"Authorization: Bearer \$OPENCTI_TOKEN\" \\"
    echo -e "         -H \"Content-Type: application/json\" \\"
    echo -e "         -d '{\"query\":\"{ stixCyberObservables(search: \\\"8.8.8.8\\\", first: 10) { edges { node { observable_value entity_type } } } }\"}' \\"
    echo -e "         \"\${OPENCTI_URL}/graphql\" | jq ."
    echo
    echo -e "  ${CYAN}Set credentials (add to your shell profile or .env):${NC}"
    echo -e "    export OPENCTI_URL=\"http://your-opencti-host:8080\""
    echo -e "    export OPENCTI_TOKEN=\"your-api-token\""
    echo
    echo -e "  ${CYAN}OpenCTI Web UI:${NC}"
    echo -e "    Open $OPENCTI_URL in your browser"
    echo
    echo -e "  ${CYAN}Python client:${NC}"
    echo -e "    pip3 install pycti --break-system-packages"
    echo -e "    python3 -c \"from pycti import OpenCTIApiClient; ...\""
    echo
    echo -e "  ${MUTED}Docs: https://docs.opencti.io/latest/development/api-usage/${NC}"
}

clear; show_banner
echo -e "  ${LABEL}OpenCTI — Threat Intelligence Platform${NC}"
echo
_check_opencti
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"