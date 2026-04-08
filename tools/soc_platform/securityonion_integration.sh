#!/usr/bin/env bash
# tools/soc_platform/securityonion_integration.sh
# Security Onion — SOC dashboard, alert query, and Hunt/Kibana integration

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/securityonion"
LOG_FILE="$PROJECT_ROOT/logs/securityonion.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

SO_HOST="${SO_HOST:-https://securityonion.local}"
SO_USER="${SO_USER:-}"
SO_PASS="${SO_PASS:-}"
SO_VERIFY_SSL="${SO_VERIFY_SSL:-true}"
SO_API_KEY="${SO_API_KEY:-}"
SO_API_URL="${SO_API_URL:-${SO_HOST}:9822}"

_ssl_flag() { [[ "$SO_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

_so_api() {
    local method="$1" endpoint="$2" data="${3:-}"
    local args=(-sf -X "$method"
        -H "Authorization: Bearer $SO_API_KEY"
        -H "Content-Type: application/json"
    )
    [[ "$SO_VERIFY_SSL" == "false" ]] && args+=(-k)
    [[ -n "$data" ]] && args+=(-d "$data")
    curl "${args[@]}" "${SO_API_URL}${endpoint}" 2>>"$LOG_FILE"
}

_pretty() { command -v jq &>/dev/null && jq '.' || cat; }

_check_api() {
    if [[ -z "$SO_API_KEY" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] Security Onion API key: ${NC}")" SO_API_KEY
        echo
    fi

    local rc
    # shellcheck disable=SC2046
    rc=$(curl -sf $(_ssl_flag) \
         -H "Authorization: Bearer $SO_API_KEY" \
         "${SO_API_URL}/api/status" \
         -o /dev/null -w "%{http_code}" 2>/dev/null) || true

    if [[ "$rc" == "200" ]]; then
        log_success "Connected to Security Onion API: $SO_API_URL"
        return 0
    else
        log_warning "SO REST API not reachable (HTTP $rc) — falling back to SSH mode."
        return 1
    fi
}

_require_ssh() {
    read -rp "$(echo -e "  ${PROMPT}[?] Security Onion manager IP/hostname: ${NC}")" SO_SSH_HOST
    read -rp "$(echo -e "  ${PROMPT}[?] SSH user [analyst]: ${NC}")" SO_SSH_USER
    SO_SSH_USER="${SO_SSH_USER:-analyst}"
}

_ssh_run() {
    local cmd="$1"
    ssh -o StrictHostKeyChecking=accept-new "${SO_SSH_USER}@${SO_SSH_HOST}" "$cmd" 2>>"$LOG_FILE"
}

_show_status() {
    if _check_api 2>/dev/null; then
        log_info "Fetching SO status..."
        _so_api GET "/api/status" | _pretty
    else
        _require_ssh
        log_info "Checking SO services via SSH..."
        _ssh_run "sudo so-status 2>/dev/null || sudo systemctl list-units 'so-*' --no-pager" \
            | tee "$OUTPUT_DIR/so_status_$(date '+%Y%m%d_%H%M%S').txt"
    fi
    _log "status check"
}

clear; show_banner
echo -e "  ${LABEL}Security Onion — SOC Platform Integration${NC}"
echo
kv "  SO host"  "$SO_HOST"
kv "  API URL"  "$SO_API_URL"
echo
_show_status