#!/usr/bin/env bash
# tools/static_analysis/semgrep_scan.sh
# Semgrep — static analysis / SAST against a target codebase

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

CUSTOM_RULES="$TOOLS_DIR/configs/semgrep_rules.yaml"
OUTPUT_DIR="$PROJECT_ROOT/output/semgrep"
LOG_FILE="$PROJECT_ROOT/logs/semgrep.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

_check_semgrep() {
    if ! command -v semgrep &>/dev/null; then
        log_error "Semgrep not found."
        log_info  "Install: pip3 install semgrep --break-system-packages"
        return 1
    fi
    log_success "Semgrep: $(semgrep --version 2>&1 | head -1)"
}

_scan() {
    local target="$1"
    local rule_arg="$2"
    local label="$3"
    local report_file="$OUTPUT_DIR/semgrep_$(date '+%Y%m%d_%H%M%S').json"

    log_info "Running Semgrep [$label] on: $target"
    _log "semgrep: rules=$rule_arg target=$target"

    semgrep --config "$rule_arg" \
            "$target"            \
            --json               \
            --no-error-on-empty-scan \
            --output "$report_file" \
            2>&1 | tee -a "$LOG_FILE" || true

    if command -v jq &>/dev/null && [[ -s "$report_file" ]]; then
        local total errors warnings info
        total=$(jq '.results | length' "$report_file" 2>/dev/null || echo "?")
        errors=$(jq '[.results[] | select(.extra.severity=="ERROR")] | length' "$report_file" 2>/dev/null || echo "?")
        warnings=$(jq '[.results[] | select(.extra.severity=="WARNING")] | length' "$report_file" 2>/dev/null || echo "?")
        info=$(jq '[.results[] | select(.extra.severity=="INFO")] | length' "$report_file" 2>/dev/null || echo "?")

        echo
        echo -e "  ${LABEL}Summary${NC}"
        kv "  Total findings" "$total"
        kv "  Errors"         "${RED}${errors}${NC}"
        kv "  Warnings"       "${AMBER}${warnings}${NC}"
        kv "  Info"           "${CYAN}${info}${NC}"
        echo
        echo -e "  ${LABEL}Top findings:${NC}"
        jq -r '.results[] | "  [\(.extra.severity)] \(.path):\(.start.line) — \(.check_id)"' \
            "$report_file" 2>/dev/null | head -20 || true
    fi

    log_success "Report saved: $report_file"
    _log "Scan complete: $report_file (findings: ${total:-?})"
}

_scan_auto() {
    _check_semgrep || return 1

    read -rp "$(echo -e "  ${PROMPT}[?] Target path (file or directory): ${NC}")" target
    [[ ! -e "$target" ]] && log_error "Path not found: $target" && return 1

    _scan "$target" "auto" "auto-detect"
}

clear; show_banner
echo -e "  ${LABEL}Semgrep — Static Analysis / SAST${NC}"
echo
_scan_auto