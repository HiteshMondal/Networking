#!/usr/bin/env bash
# tools/soc_platform/securityonion_integration.sh
# Security Onion — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

SO_HOST="${SO_HOST:-https://securityonion.local}"
SO_API_KEY="${SO_API_KEY:-}"
SO_API_URL="${SO_API_URL:-${SO_HOST}:9822}"
SO_VERIFY_SSL="${SO_VERIFY_SSL:-true}"

_check_securityonion() {
    local curl_ok=false so_cli_ok=false key_set=false

    command -v curl      &>/dev/null && curl_ok=true
    command -v so-status &>/dev/null && so_cli_ok=true
    [[ -n "$SO_API_KEY" ]] && key_set=true

    echo -e "  ${LABEL}Environment:${NC}"
    echo
    kv "  SO host"       "$SO_HOST"
    kv "  SO API URL"    "$SO_API_URL"
    kv "  API key set"   "$( $key_set  && echo "${SUCCESS}yes${NC}"      || echo "${FAILURE}no${NC}" )"
    kv "  so-status CLI" "$( $so_cli_ok && echo "${SUCCESS}available${NC}" || echo "${MUTED}not found${NC}" )"
    echo

    # Local SO node check
    if $so_cli_ok; then
        log_success "Running on a Security Onion node — so-* commands are available."
        echo
        echo -e "  ${LABEL}Useful local commands:${NC}"
        echo
        echo -e "  ${CYAN}Check service status:${NC}"
        echo -e "    sudo so-status"
        echo
        echo -e "  ${CYAN}Restart all SO services:${NC}"
        echo -e "    sudo so-restart"
        echo
        echo -e "  ${CYAN}Run a hunt query (Kibana/OpenSearch):${NC}"
        echo -e "    sudo so-hunt"
        echo
        echo -e "  ${CYAN}View alerts:${NC}"
        echo -e "    sudo so-alert-log"
        return
    fi

    # Remote API check
    if ! $curl_ok; then
        log_error "curl is not installed — required to query the Security Onion API."
        echo -e "  ${CYAN}Install:${NC}  sudo apt install curl"
        return
    fi

    if $key_set; then
        log_info "Testing connection to Security Onion API at $SO_API_URL ..."
        local ssl_flag; [[ "$SO_VERIFY_SSL" == "false" ]] && ssl_flag="-k" || ssl_flag=""
        local rc
        # shellcheck disable=SC2086
        rc=$(curl -sf $ssl_flag \
             -H "Authorization: Bearer $SO_API_KEY" \
             "${SO_API_URL}/api/status" \
             -o /dev/null -w "%{http_code}" 2>/dev/null) || true

        if [[ "$rc" == "200" ]]; then
            log_success "Connected to Security Onion API successfully."
        else
            log_warning "Could not reach SO API (HTTP $rc). Check SO_API_URL and SO_API_KEY."
        fi
    else
        log_warning "SO_API_KEY is not set — connection test skipped."
    fi

    echo
    echo -e "  ${LABEL}How to access Security Onion:${NC}"
    echo
    echo -e "  ${CYAN}Web UI (SOC Console):${NC}"
    echo -e "    Open $SO_HOST in your browser"
    echo
    echo -e "  ${CYAN}Query alerts via API:${NC}"
    echo -e "    curl -s -H \"Authorization: Bearer \$SO_API_KEY\" \\"
    echo -e "         \"\${SO_API_URL}/api/alerts\" | jq ."
    echo
    echo -e "  ${CYAN}SSH into the SO manager:${NC}"
    echo -e "    ssh analyst@<so-manager-ip>"
    echo -e "    sudo so-status"
    echo
    echo -e "  ${CYAN}Set credentials (add to your shell profile):${NC}"
    echo -e "    export SO_HOST=\"https://your-so-host\""
    echo -e "    export SO_API_KEY=\"your-api-key\""
    echo
    echo -e "  ${LABEL}Install Security Onion:${NC}"
    echo
    echo -e "    https://docs.securityonion.net/en/2.4/installation.html"
    echo -e "    (Requires a dedicated VM or bare-metal node — not a package install)"
    echo
    echo -e "  ${MUTED}Docs: https://docs.securityonion.net/${NC}"
}

clear; show_banner
echo -e "  ${LABEL}Security Onion — SOC Platform${NC}"
echo
_check_securityonion
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"