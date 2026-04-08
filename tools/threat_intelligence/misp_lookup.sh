#!/usr/bin/env bash
# tools/threat_intelligence/misp_lookup.sh
# MISP — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

MISP_URL="${MISP_URL:-https://misp.local}"
MISP_KEY="${MISP_KEY:-}"
MISP_VERIFY_SSL="${MISP_VERIFY_SSL:-true}"

_check_misp() {
    local curl_ok=false misp_configured=false

    command -v curl &>/dev/null && curl_ok=true
    [[ -n "$MISP_KEY" ]] && misp_configured=true

    echo -e "  ${LABEL}Configuration:${NC}"
    echo
    kv "  MISP URL"    "$MISP_URL"
    kv "  API key set" "$( [[ -n "$MISP_KEY" ]] && echo "${SUCCESS}yes${NC}" || echo "${FAILURE}no${NC}" )"
    kv "  SSL verify"  "$MISP_VERIFY_SSL"
    echo

    if ! $curl_ok; then
        log_error "curl is not installed — required to talk to the MISP API."
        echo -e "  ${CYAN}Install:${NC}  sudo apt install curl"
        return
    fi

    if $misp_configured; then
        log_info "Testing connection to $MISP_URL ..."
        local ssl_flag; [[ "$MISP_VERIFY_SSL" == "false" ]] && ssl_flag="-k" || ssl_flag=""
        local rc
        # shellcheck disable=SC2086
        rc=$(curl -sf $ssl_flag \
             -H "Authorization: $MISP_KEY" \
             -H "Accept: application/json" \
             "${MISP_URL}/users/view/me" \
             -o /dev/null -w "%{http_code}" 2>/dev/null) || true

        if [[ "$rc" == "200" ]]; then
            log_success "Connected to MISP successfully."
        else
            log_warning "Could not connect to MISP (HTTP $rc). Check URL and key."
        fi
    else
        log_warning "MISP_KEY is not set — connection test skipped."
    fi

    echo
    echo -e "  ${LABEL}How to use the MISP REST API:${NC}"
    echo
    echo -e "  ${CYAN}Search for an attribute (IP, domain, hash, etc.):${NC}"
    echo -e "    curl -s -H \"Authorization: \$MISP_KEY\" \\"
    echo -e "         -H \"Accept: application/json\" \\"
    echo -e "         -H \"Content-Type: application/json\" \\"
    echo -e "         -X POST \\"
    echo -e "         -d '{\"returnFormat\":\"json\",\"value\":\"8.8.8.8\",\"limit\":10}' \\"
    echo -e "         \"\${MISP_URL}/attributes/restSearch\" | jq ."
    echo
    echo -e "  ${CYAN}Set credentials (add to your shell profile or .env):${NC}"
    echo -e "    export MISP_URL=\"https://your-misp-host\""
    echo -e "    export MISP_KEY=\"your-automation-api-key\""
    echo
    echo -e "  ${CYAN}MISP Web UI:${NC}"
    echo -e "    Open $MISP_URL in your browser"
    echo
    echo -e "  ${MUTED}Docs: https://www.misp-project.org/openapi/${NC}"
}

clear; show_banner
echo -e "  ${LABEL}MISP — Threat Intelligence Platform${NC}"
echo
_check_misp
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"