#!/usr/bin/env bash
# tools/reverse_engineering/ghidra_launcher.sh
# Ghidra — NSA reverse engineering framework launcher

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-"$(cd "$TOOLS_DIR/.." && pwd)"}"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/ghidra"
LOG_FILE="$PROJECT_ROOT/logs/ghidra.log"
GHIDRA_PROJECTS_DIR="$OUTPUT_DIR/projects"
mkdir -p "$OUTPUT_DIR" "$GHIDRA_PROJECTS_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

_find_ghidra_home() {
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

    if command -v ghidraRun &>/dev/null; then
        dirname "$(command -v ghidraRun)"
        return 0
    fi

    return 1
}

_check_java() {
    if ! command -v java &>/dev/null; then
        log_error "Java not found. Ghidra requires Java 17+."
        log_info  "Install: apt install default-jdk  |  dnf install java-17-openjdk"
        return 1
    fi
    local jver
    jver=$(java -version 2>&1 | head -1)
    log_info "Java: $jver"
}

_install_guide() {
    echo
    echo -e "  ${LABEL}Ghidra Installation${NC}"
    echo
    echo -e "  1. Download from: ${CYAN}https://ghidra-sre.org/${NC}"
    echo -e "  2. Extract: ${MUTED}unzip ghidra_*.zip -d /opt/ghidra${NC}"
    echo -e "  3. Set GHIDRA_HOME: ${MUTED}export GHIDRA_HOME=/opt/ghidra/ghidra_*${NC}"
    echo -e "     (add to /etc/environment or your shell profile)"
    echo -e "  4. Java 17+ required: ${MUTED}apt install default-jdk${NC}"
    echo
}

_launch_gui() {
    _check_java || return 1

    if [[ -z "${DISPLAY:-}" ]]; then
        log_error "No DISPLAY detected. Cannot launch Ghidra GUI in headless environment."
        return 1
    fi

    local ghidra_home
    if ! ghidra_home=$(_find_ghidra_home 2>/dev/null); then
        log_error "Ghidra not found."
        _install_guide
        return 1
    fi

    log_info "Launching Ghidra from: $ghidra_home"
    _log "GUI launch: $ghidra_home"
    "$ghidra_home/ghidraRun" &>/dev/null &
    disown
    log_success "Ghidra launched (PID: $!)."
}

clear; show_banner
echo -e "  ${LABEL}Ghidra — Reverse Engineering Framework${NC}"
echo

ghidra_home=""
if ghidra_home=$(_find_ghidra_home 2>/dev/null); then
    kv "  Ghidra home" "$ghidra_home"
else
    kv "  Ghidra home" "${FAILURE}Not found${NC}"
fi
echo

_launch_gui