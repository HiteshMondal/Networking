#!/usr/bin/env bash
# tools/dfir/thehive_case.sh
# TheHive — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
THEHIVE_KEY="${THEHIVE_KEY:-}"
THEHIVE_VERIFY_SSL="${THEHIVE_VERIFY_SSL:-true}"

_check_thehive() {
    local curl_ok=false key_set=false

    command -v curl &>/dev/null && curl_ok=true
    [[ -n "$THEHIVE_KEY" ]] && key_set=true

    echo -e "  ${LABEL}Configuration:${NC}"
    echo
    kv "  TheHive URL" "$THEHIVE_URL"
    kv "  API key set" "$( $key_set && echo "${SUCCESS}yes${NC}" || echo "${FAILURE}no${NC}" )"
    kv "  SSL verify"  "$THEHIVE_VERIFY_SSL"
    echo

    if ! $curl_ok; then
        log_error "curl is not installed — required to talk to the TheHive API."
        echo -e "  ${CYAN}Install:${NC}  sudo apt install curl"
        return
    fi

    if $key_set; then
        log_info "Testing connection to $THEHIVE_URL ..."
        local ssl_flag; [[ "$THEHIVE_VERIFY_SSL" == "false" ]] && ssl_flag="-k" || ssl_flag=""
        local rc
        # shellcheck disable=SC2086
        rc=$(curl -sf $ssl_flag \
             -H "Authorization: Bearer $THEHIVE_KEY" \
             "${THEHIVE_URL}/api/v1/user/current" \
             -o /dev/null -w "%{http_code}" 2>/dev/null) || true

        if [[ "$rc" == "200" ]]; then
            log_success "Connected to TheHive successfully."
        else
            log_warning "Could not connect to TheHive (HTTP $rc). Check URL and key."
        fi
    else
        log_warning "THEHIVE_KEY is not set — connection test skipped."
    fi

    echo
    echo -e "  ${LABEL}How to use TheHive:${NC}"
    echo
    echo -e "  ${CYAN}Web UI:${NC}"
    echo -e "    Open $THEHIVE_URL in your browser"
    echo
    echo -e "  ${CYAN}List open cases via API:${NC}"
    echo -e "    curl -s -H \"Authorization: Bearer \$THEHIVE_KEY\" \\"
    echo -e "         -H \"Content-Type: application/json\" \\"
    echo -e "         -X POST \\"
    echo -e "         -d '{\"query\":[{\"_name\":\"listCase\"}],\"ranges\":[\"0-20\"]}' \\"
    echo -e "         \"\${THEHIVE_URL}/api/v1/case/_search\" | jq ."
    echo
    echo -e "  ${CYAN}Create a case via API:${NC}"
    echo -e "    curl -s -H \"Authorization: Bearer \$THEHIVE_KEY\" \\"
    echo -e "         -H \"Content-Type: application/json\" \\"
    echo -e "         -X POST \\"
    echo -e "         -d '{\"title\":\"My Case\",\"severity\":2,\"tlp\":2}' \\"
    echo -e "         \"\${THEHIVE_URL}/api/v1/case\" | jq ."
    echo
    echo -e "  ${CYAN}Set credentials (add to your shell profile):${NC}"
    echo -e "    export THEHIVE_URL=\"http://your-thehive-host:9000\""
    echo -e "    export THEHIVE_KEY=\"your-api-key\""
    echo
    echo -e "  ${LABEL}Install TheHive (Docker — quickest):${NC}"
    echo
    echo -e "    docker run --rm -p 9000:9000 strangebee/thehive:latest"
    echo
    echo -e "  ${MUTED}Docs: https://docs.strangebee.com/thehive/${NC}"
}

clear; show_banner
echo -e "  ${LABEL}TheHive — Incident Response Case Manager${NC}"
echo
_check_thehive
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"