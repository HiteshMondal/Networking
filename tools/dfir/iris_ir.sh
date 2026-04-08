#!/usr/bin/env bash
# tools/dfir/iris_ir.sh
# IRIS — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

IRIS_URL="${IRIS_URL:-https://localhost}"
IRIS_TOKEN="${IRIS_TOKEN:-}"
IRIS_VERIFY_SSL="${IRIS_VERIFY_SSL:-true}"

_check_iris() {
    local curl_ok=false token_set=false

    command -v curl &>/dev/null && curl_ok=true
    [[ -n "$IRIS_TOKEN" ]] && token_set=true

    echo -e "  ${LABEL}Configuration:${NC}"
    echo
    kv "  IRIS URL"    "$IRIS_URL"
    kv "  Token set"   "$( $token_set && echo "${SUCCESS}yes${NC}" || echo "${FAILURE}no${NC}" )"
    kv "  SSL verify"  "$IRIS_VERIFY_SSL"
    echo

    if ! $curl_ok; then
        log_error "curl is not installed — required to talk to the IRIS API."
        echo -e "  ${CYAN}Install:${NC}  sudo apt install curl"
        return
    fi

    if $token_set; then
        log_info "Testing connection to $IRIS_URL ..."
        local ssl_flag; [[ "$IRIS_VERIFY_SSL" == "false" ]] && ssl_flag="-k" || ssl_flag=""
        local rc
        # shellcheck disable=SC2086
        rc=$(curl -sf $ssl_flag \
             -H "Authorization: Bearer $IRIS_TOKEN" \
             "${IRIS_URL}/api/v2/users/me" \
             -o /dev/null -w "%{http_code}" 2>/dev/null) || true

        if [[ "$rc" == "200" ]]; then
            log_success "Connected to IRIS successfully."
        else
            log_warning "Could not connect to IRIS (HTTP $rc). Check URL and token."
        fi
    else
        log_warning "IRIS_TOKEN is not set — connection test skipped."
    fi

    echo
    echo -e "  ${LABEL}How to use IRIS:${NC}"
    echo
    echo -e "  ${CYAN}Web UI:${NC}"
    echo -e "    Open $IRIS_URL in your browser"
    echo
    echo -e "  ${CYAN}List cases via API:${NC}"
    echo -e "    curl -s -H \"Authorization: Bearer \$IRIS_TOKEN\" \\"
    echo -e "         \"\${IRIS_URL}/api/v2/cases\" | jq ."
    echo
    echo -e "  ${CYAN}Create a case via API:${NC}"
    echo -e "    curl -s -X POST \\"
    echo -e "         -H \"Authorization: Bearer \$IRIS_TOKEN\" \\"
    echo -e "         -H \"Content-Type: application/json\" \\"
    echo -e "         -d '{\"case_name\":\"IR-001\",\"case_description\":\"Phishing incident\",\"case_customer\":1,\"case_soc_id\":\"SOC-001\"}' \\"
    echo -e "         \"\${IRIS_URL}/api/v2/cases\" | jq ."
    echo
    echo -e "  ${CYAN}Set credentials (add to your shell profile):${NC}"
    echo -e "    export IRIS_URL=\"https://your-iris-host\""
    echo -e "    export IRIS_TOKEN=\"your-api-token\""
    echo
    echo -e "  ${LABEL}Install IRIS (Docker — quickest):${NC}"
    echo
    echo -e "    git clone https://github.com/dfir-iris/iris-web.git"
    echo -e "    cd iris-web"
    echo -e "    cp .env.model .env   # edit as needed"
    echo -e "    docker compose up -d"
    echo
    echo -e "  ${MUTED}Docs: https://docs.dfir-iris.org/${NC}"
}

clear; show_banner
echo -e "  ${LABEL}IRIS — Incident Response Platform${NC}"
echo
_check_iris
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"