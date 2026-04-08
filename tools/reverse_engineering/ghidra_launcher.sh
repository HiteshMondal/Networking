#!/usr/bin/env bash
# tools/reverse_engineering/ghidra_launcher.sh
# Ghidra — installation check & usage instructions

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

_find_ghidra() {
    local candidates=(
        "${GHIDRA_HOME:-}"
        /opt/ghidra
        /usr/share/ghidra
        "$HOME/ghidra"
        /usr/local/ghidra
    )
    for d in "${candidates[@]}"; do
        [[ -n "$d" && -x "${d}/ghidraRun" ]] && echo "$d" && return 0
    done
    command -v ghidraRun &>/dev/null && dirname "$(command -v ghidraRun)" && return 0
    # Wider filesystem search (max depth 4 to avoid long scans)
    local found
    found=$(find /opt "$HOME" /usr/local -maxdepth 4 -name "ghidraRun" -type f 2>/dev/null | head -1)
    [[ -n "$found" ]] && dirname "$found" && return 0
    return 1
}

_check_java() {
    if command -v java &>/dev/null; then
        local jver
        jver=$(java -version 2>&1 | head -1)
        kv "  Java" "$jver"
        return 0
    else
        kv "  Java" "${FAILURE}not found${NC}"
        return 1
    fi
}

_check_ghidra() {
    local ghidra_home=""
    ghidra_home=$(_find_ghidra 2>/dev/null) || true

    echo -e "  ${LABEL}Environment:${NC}"
    echo
    _check_java || true

    if [[ -n "$ghidra_home" ]]; then
        kv "  Ghidra home" "$ghidra_home"
        echo
        log_success "Ghidra is installed."
        echo
        echo -e "  ${LABEL}How to run:${NC}"
        echo
        echo -e "  ${CYAN}GUI (interactive):${NC}"
        echo -e "    ${ghidra_home}/ghidraRun"
        echo
        echo -e "  ${CYAN}Headless analysis (no GUI):${NC}"
        echo -e "    ${ghidra_home}/support/analyzeHeadless \\"
        echo -e "        /tmp/myproject MyProject \\"
        echo -e "        -import /path/to/binary \\"
        echo -e "        -postScript MyScript.java"
        echo
        echo -e "  ${CYAN}Set GHIDRA_HOME for convenience (add to shell profile):${NC}"
        echo -e "    export GHIDRA_HOME=\"${ghidra_home}\""
        echo -e "    alias ghidra=\"\$GHIDRA_HOME/ghidraRun\""
        echo
        echo -e "  ${MUTED}Docs: https://ghidra-sre.org/CheatSheet.html${NC}"
    else
        kv "  Ghidra home" "${FAILURE}not found${NC}"
        echo
        log_error "Ghidra is NOT installed."
        echo
        echo -e "  ${LABEL}Install Instructions:${NC}"
        echo
        echo -e "  ${CYAN}1. Install Java 17+ (required):${NC}"
        echo -e "    sudo apt install default-jdk          # Debian / Ubuntu"
        echo -e "    sudo dnf install java-17-openjdk      # RHEL / Fedora"
        echo -e "    sudo pacman -S jdk17-openjdk          # Arch"
        echo
        echo -e "  ${CYAN}2. Download Ghidra:${NC}"
        echo -e "    https://ghidra-sre.org/"
        echo
        echo -e "  ${CYAN}3. Extract and run:${NC}"
        echo -e "    unzip ghidra_*.zip -d /opt/ghidra"
        echo -e "    /opt/ghidra/ghidra_*/ghidraRun"
        echo
        echo -e "  ${CYAN}4. (Optional) set GHIDRA_HOME in your shell profile:${NC}"
        echo -e "    export GHIDRA_HOME=/opt/ghidra/ghidra_*"
    fi
}

clear; show_banner
echo -e "  ${LABEL}Ghidra — Reverse Engineering Framework${NC}"
echo
_check_ghidra
echo
read -rp "$(echo -e "  ${MUTED}Press Enter to return to menu...${NC}")"