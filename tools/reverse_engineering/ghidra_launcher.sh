#!/usr/bin/env bash
# tools/reverse_engineering/ghidra_launcher.sh
# Ghidra — NSA reverse engineering framework launcher & headless analysis helper

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/ghidra"
LOG_FILE="$PROJECT_ROOT/logs/ghidra.log"
GHIDRA_PROJECTS_DIR="$OUTPUT_DIR/projects"
mkdir -p "$OUTPUT_DIR" "$GHIDRA_PROJECTS_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  locate Ghidra 

_find_ghidra_home() {
    local candidates=(
        "$GHIDRA_HOME"                    # user-exported env var
        /opt/ghidra
        /usr/share/ghidra
        "$HOME/ghidra"
        /usr/local/ghidra
    )

    for d in "${candidates[@]}"; do
        [[ -x "${d}/ghidraRun" ]] && echo "$d" && return 0
    done

    # Last resort: find in PATH
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

#  GUI launch 

_launch_gui() {
    _check_java || return 1

    if [[ -z "${DISPLAY:-}" ]]; then
        log_error "No DISPLAY detected. Cannot launch Ghidra GUI in headless mode."
        log_info  "Use option 3 for headless analysis instead."
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

#  headless analysis 

_headless_analyse() {
    _check_java || return 1

    local ghidra_home
    if ! ghidra_home=$(_find_ghidra_home 2>/dev/null); then
        log_error "Ghidra not found."
        _install_guide
        return 1
    fi

    local analyzeHeadless="$ghidra_home/support/analyzeHeadless"
    if [[ ! -x "$analyzeHeadless" ]]; then
        log_error "analyzeHeadless script not found at: $analyzeHeadless"
        return 1
    fi

    read -rp "$(echo -e "  ${PROMPT}[?] Binary to analyse (full path): ${NC}")" binary
    [[ ! -f "$binary" ]] && log_error "File not found: $binary" && return 1

    local bin_name
    bin_name=$(basename "$binary")
    local project_name="toolkit_${bin_name}_$(date '+%Y%m%d_%H%M%S')"
    local report_file="$OUTPUT_DIR/${project_name}_report.txt"

    log_info "Running headless analysis on: $binary"
    log_info "Project: $GHIDRA_PROJECTS_DIR/$project_name"
    _log "headless: binary=$binary project=$project_name"

    "$analyzeHeadless" \
        "$GHIDRA_PROJECTS_DIR" "$project_name" \
        -import "$binary" \
        -postScript ExportFunctionInfoScript.java "$report_file" \
        2>&1 | tee -a "$LOG_FILE" || {
        log_warn "Post-script may not be available. Running basic import only."
        "$analyzeHeadless" \
            "$GHIDRA_PROJECTS_DIR" "$project_name" \
            -import "$binary" \
            2>&1 | tee -a "$LOG_FILE"
    }

    log_success "Headless analysis complete."
    [[ -f "$report_file" ]] && log_success "Report: $report_file"
    log_info "Project saved: $GHIDRA_PROJECTS_DIR/$project_name"
    _log "headless complete: $project_name"
}

#  strings extraction (no Ghidra required) 

_extract_strings() {
    read -rp "$(echo -e "  ${PROMPT}[?] Binary path: ${NC}")" binary
    [[ ! -f "$binary" ]] && log_error "File not found: $binary" && return 1

    local min_len=4
    read -rp "$(echo -e "  ${PROMPT}[?] Minimum string length [${min_len}]: ${NC}")" ml
    [[ -n "$ml" ]] && min_len="$ml"

    local out_file="$OUTPUT_DIR/strings_$(basename "$binary")_$(date '+%Y%m%d_%H%M%S').txt"

    if command -v strings &>/dev/null; then
        strings -n "$min_len" "$binary" | tee "$out_file"
    else
        # POSIX fallback: grep printable ASCII sequences
        grep -aoP "[[:print:]]{${min_len},}" "$binary" | tee "$out_file" || true
    fi

    log_success "Strings saved: $out_file"
    _log "strings: $binary → $out_file"
}

#  file type / metadata 

_file_info() {
    read -rp "$(echo -e "  ${PROMPT}[?] Binary path: ${NC}")" binary
    [[ ! -f "$binary" ]] && log_error "File not found: $binary" && return 1

    echo
    if command -v file &>/dev/null; then
        echo -e "  ${LABEL}file:${NC}"
        file "$binary"
        echo
    fi

    if command -v xxd &>/dev/null; then
        echo -e "  ${LABEL}Magic bytes (first 16):${NC}"
        xxd "$binary" | head -1
        echo
    fi

    if command -v sha256sum &>/dev/null; then
        echo -e "  ${LABEL}Hashes:${NC}"
        md5sum    "$binary" 2>/dev/null | awk '{print "  MD5:    "$1}' || true
        sha1sum   "$binary" 2>/dev/null | awk '{print "  SHA1:   "$1}' || true
        sha256sum "$binary"             | awk '{print "  SHA256: "$1}'
        echo
    fi

    if command -v readelf &>/dev/null && file "$binary" 2>/dev/null | grep -q ELF; then
        echo -e "  ${LABEL}ELF header:${NC}"
        readelf -h "$binary" 2>/dev/null | grep -E "Class|Data|Type|Machine|Entry" | sed 's/^/  /'
        echo
        echo -e "  ${LABEL}Dynamic imports:${NC}"
        readelf -d "$binary" 2>/dev/null | grep NEEDED | sed 's/^/  /' | head -20
        echo
    fi
}

#  install guide 

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

#  menu 

clear; show_banner

echo -e "  ${LABEL}Ghidra — Reverse Engineering Framework${NC}"
echo

local ghidra_home=""
if ghidra_home=$(_find_ghidra_home 2>/dev/null); then
    kv "  Ghidra home" "$ghidra_home"
else
    kv "  Ghidra home" "${FAILURE}Not found${NC}"
fi
echo

echo -e "  ${GREEN}  1.${NC}  Launch Ghidra GUI"
echo -e "  ${GREEN}  2.${NC}  Headless binary analysis"
echo -e "  ${GREEN}  3.${NC}  Extract strings from binary"
echo -e "  ${GREEN}  4.${NC}  Binary file info & hashes"
echo -e "  ${GREEN}  5.${NC}  Installation guide"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _launch_gui        ;;
    2) _headless_analyse  ;;
    3) _extract_strings   ;;
    4) _file_info         ;;
    5) _install_guide     ;;
    0) exit 0             ;;
    *) log_error "Invalid choice." ;;
esac