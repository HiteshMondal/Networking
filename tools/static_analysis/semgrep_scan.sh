#!/usr/bin/env bash
# tools/static_analysis/semgrep_scan.sh
# Semgrep — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

CUSTOM_RULES="$TOOLS_DIR/configs/semgrep_rules.yaml"

_check_semgrep() {
    if command -v semgrep &>/dev/null; then
        log_success "Semgrep is installed."
        echo
        kv "  semgrep"      "$(command -v semgrep)"
        kv "  version"      "$(semgrep --version 2>&1 | head -1)"
        kv "  custom rules" "$CUSTOM_RULES"
        echo
        echo -e "  ${LABEL}How to run:${NC}"
        echo
        echo -e "  ${CYAN}Auto-detect language and rules:${NC}"
        echo -e "    semgrep --config auto /path/to/code"
        echo
        echo -e "  ${CYAN}Use toolkit custom rules:${NC}"
        echo -e "    semgrep --config ${CUSTOM_RULES} /path/to/code"
        echo
        echo -e "  ${CYAN}Scan with a specific ruleset (e.g. OWASP):${NC}"
        echo -e "    semgrep --config p/owasp-top-ten /path/to/code"
        echo
        echo -e "  ${CYAN}Output as JSON:${NC}"
        echo -e "    semgrep --config auto /path/to/code --json --output report.json"
        echo
        echo -e "  ${CYAN}Scan current directory:${NC}"
        echo -e "    semgrep --config auto ."
        echo
        echo -e "  ${MUTED}Browse public rules: https://semgrep.dev/r${NC}"
    else
        log_error "Semgrep is NOT installed."
        echo
        echo -e "  ${LABEL}Install Instructions:${NC}"
        echo
        echo -e "  ${CYAN}pip (all distros):${NC}"
        echo -e "    pip3 install semgrep --break-system-packages"
        echo
        echo -e "  ${CYAN}Homebrew (macOS / Linuxbrew):${NC}"
        echo -e "    brew install semgrep"
        echo
        echo -e "  ${CYAN}Docker:${NC}"
        echo -e "    docker run --rm -v \"\${PWD}:/src\" semgrep/semgrep semgrep --config auto /src"
        echo
        echo -e "  ${MUTED}Docs: https://semgrep.dev/docs/getting-started${NC}"
    fi
}

clear; show_banner
echo -e "  ${LABEL}Semgrep — Static Analysis / SAST${NC}"
echo
_check_semgrep
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"