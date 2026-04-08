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

#  pre-flight 

_check_semgrep() {
    if ! command -v semgrep &>/dev/null; then
        log_error "Semgrep not found."
        log_info  "Install: pip3 install semgrep --break-system-packages"
        return 1
    fi
    log_success "Semgrep: $(semgrep --version 2>&1 | head -1)"
}

#  scan runners 

_scan() {
    local target="$1"
    local rule_arg="$2"
    local label="$3"
    local report_file="$OUTPUT_DIR/semgrep_$(date '+%Y%m%d_%H%M%S').json"
    local sarif_file="${report_file%.json}.sarif"

    log_info "Running Semgrep [$label] on: $target"
    _log "semgrep: rules=$rule_arg target=$target"

    # JSON report (machine-readable)
    semgrep --config "$rule_arg" \
            "$target"            \
            --json               \
            --no-error-on-empty-scan \
            --output "$report_file" \
            2>&1 | tee -a "$LOG_FILE" || true

    # Human-readable summary from JSON
    if command -v jq &>/dev/null && [[ -s "$report_file" ]]; then
        local total errors warnings info
        total=$(jq '.results | length' "$report_file" 2>/dev/null || echo "?")
        errors=$(jq '[.results[] | select(.extra.severity=="ERROR")] | length' "$report_file" 2>/dev/null || echo "?")
        warnings=$(jq '[.results[] | select(.extra.severity=="WARNING")] | length' "$report_file" 2>/dev/null || echo "?")
        info=$(jq '[.results[] | select(.extra.severity=="INFO")] | length' "$report_file" 2>/dev/null || echo "?")

        echo
        echo -e "  ${LABEL}Summary${NC}"
        kv "  Total findings"   "$total"
        kv "  Errors"           "${RED}${errors}${NC}"
        kv "  Warnings"         "${AMBER}${warnings}${NC}"
        kv "  Info"             "${CYAN}${info}${NC}"
        echo
        echo -e "  ${LABEL}Top findings:${NC}"
        jq -r '.results[] | "  [\(.extra.severity)] \(.path):\(.start.line) — \(.check_id)"' \
            "$report_file" 2>/dev/null | head -20 || true
    fi

    log_success "Report saved: $report_file"
    _log "Scan complete: $report_file (findings: ${total:-?})"
}

#  scan modes 

_scan_custom_rules() {
    _check_semgrep || return 1

    read -rp "$(echo -e "  ${PROMPT}[?] Target path (file or directory): ${NC}")" target
    [[ ! -e "$target" ]] && log_error "Path not found: $target" && return 1

    _scan "$target" "$CUSTOM_RULES" "custom rules"
}

_scan_auto() {
    _check_semgrep || return 1

    read -rp "$(echo -e "  ${PROMPT}[?] Target path (file or directory): ${NC}")" target
    [[ ! -e "$target" ]] && log_error "Path not found: $target" && return 1

    _scan "$target" "auto" "auto-detect"
}

_scan_registry() {
    _check_semgrep || return 1

    echo
    echo -e "  ${LABEL}Common registry rulesets:${NC}"
    echo -e "  ${GREEN}  1.${NC}  p/security-audit"
    echo -e "  ${GREEN}  2.${NC}  p/owasp-top-ten"
    echo -e "  ${GREEN}  3.${NC}  p/secrets"
    echo -e "  ${GREEN}  4.${NC}  p/ci"
    echo -e "  ${GREEN}  5.${NC}  Custom ruleset URL"
    echo
    read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" rc

    local ruleset
    case $rc in
        1) ruleset="p/security-audit" ;;
        2) ruleset="p/owasp-top-ten"  ;;
        3) ruleset="p/secrets"        ;;
        4) ruleset="p/ci"             ;;
        5)
            read -rp "$(echo -e "  ${PROMPT}[?] Enter ruleset URL or registry ID: ${NC}")" ruleset
            ;;
        *) log_error "Invalid choice." ; return 1 ;;
    esac

    read -rp "$(echo -e "  ${PROMPT}[?] Target path: ${NC}")" target
    [[ ! -e "$target" ]] && log_error "Path not found: $target" && return 1

    _scan "$target" "$ruleset" "$ruleset"
}

_view_last_report() {
    local latest
    latest=$(find "$OUTPUT_DIR" -name '*.json' | sort -r | head -1)
    if [[ -z "$latest" ]]; then
        log_warn "No reports found in $OUTPUT_DIR"
        return
    fi
    echo -e "  ${LABEL}Latest: $latest${NC}"
    echo
    if command -v jq &>/dev/null; then
        jq -r '.results[] | "[\(.extra.severity)] \(.path):\(.start.line)\n  Rule: \(.check_id)\n  \(.extra.message)\n"' \
            "$latest" 2>/dev/null | head -60 || cat "$latest" | head -60
    else
        cat "$latest" | head -60
    fi
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}Semgrep — Static Analysis / SAST${NC}"
echo
echo -e "  ${GREEN}  1.${NC}  Scan with toolkit custom rules"
echo -e "  ${GREEN}  2.${NC}  Scan with auto-detect rules"
echo -e "  ${GREEN}  3.${NC}  Scan with Semgrep registry ruleset"
echo -e "  ${GREEN}  4.${NC}  View last report"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _scan_custom_rules ;;
    2) _scan_auto         ;;
    3) _scan_registry     ;;
    4) _view_last_report  ;;
    0) exit 0             ;;
    *) log_error "Invalid choice." ;;
esac