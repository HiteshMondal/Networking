#!/bin/bash
# /lib/functions.sh
# Shared utility functions for the Networking & Cybersecurity Toolkit

# ── Double-source guard ──────────────────────────────────
[[ -n "$_FUNCTIONS_LOADED" ]] && return 0
export _FUNCTIONS_LOADED=1

# ── Source colors if not already loaded ─────────────────
[[ -z "$_COLORS_LOADED" ]] && source "$(dirname "${BASH_SOURCE[0]}")/colors.sh"

# ════════════════════════════════════════════════════════
#  LOGGING
# ════════════════════════════════════════════════════════

log_success() { echo -e "${SUCCESS}[✔] $*${NC}"; }
log_error()   { echo -e "${FAILURE}[✘] $*${NC}" >&2; }
log_warning() { echo -e "${WARNING}[⚠] $*${NC}"; }
log_info()    { echo -e "${INFO}[ℹ] $*${NC}"; }
log_debug()   { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${MUTED}[DBG] $*${NC}"; }
log_step()    { echo -e "${ACCENT}[→] $*${NC}"; }

# Write to log file with timestamp (if LOG_DIR is set)
log_to_file() {
    local level="$1"; shift
    if [[ -n "$LOG_DIR" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" >> "$LOG_DIR/main.log"
    fi
}

# Combined console + file log
log() {
    local level="${1:-INFO}"; shift
    case "$level" in
        SUCCESS) log_success "$*" ;;
        ERROR)   log_error   "$*" ;;
        WARNING) log_warning "$*" ;;
        INFO)    log_info    "$*" ;;
        DEBUG)   log_debug   "$*" ;;
        STEP)    log_step    "$*" ;;
    esac
    log_to_file "$level" "$*"
}

#  DISPLAY HELPERS

show_banner() {
    clear
    echo -e "${NC}"
    echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}${NC}                                                                ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}${NC}  ${RED}🚀${YELLOW} Networking ${GREEN}&${BLUE} Cybersecurity ${MAGENTA}Automation Toolkit${NC} ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}${NC}  ${BLUE}🔒${WHITE} Professional ${CYAN}Security ${GREEN}& ${YELLOW}Network Analysis Suite${NC} ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}${NC}                                                                ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${NC}"
}

# Draw a horizontal separator
separator() {
    local char="${1:─}"
    local width="${2:-60}"
    printf '%s\n' "$(printf "%.0s${char}" $(seq 1 $width))"
}

# Section heading with top/bottom borders
header() {
    local title="$1"
    local color="${2:-$BOLD_CYAN}"
    local width=64
    local pad=$(( (width - ${#title} - 2) / 2 ))
    echo
    echo -e "${color}╔$(printf '═%.0s' $(seq 1 $((width-2))))╗${NC}"
    printf "${color}║%${pad}s %s %${pad}s║${NC}\n" "" "$title" ""
    echo -e "${color}╚$(printf '═%.0s' $(seq 1 $((width-2))))╝${NC}"
    echo
}

# Subsection heading
section() {
    local title="$1"
    echo
    echo -e "${YELLOW}${BOLD}▶ ${title}${NC}"
    echo -e "${DARK_GRAY}$(printf '─%.0s' $(seq 1 55))${NC}"
}

# Print a key-value pair
kv() {
    local key="$1"
    local val="$2"
    printf "  ${LABEL}%-24s${NC} ${VALUE}%s${NC}\n" "$key:" "$val"
}

# Print a status line: ✔/✘/○ + label
status_line() {
    local state="$1"   # ok | fail | neutral
    local label="$2"
    case "$state" in
        ok)      echo -e "  ${SUCCESS}✔${NC} $label" ;;
        fail)    echo -e "  ${FAILURE}✘${NC} $label" ;;
        neutral) echo -e "  ${MUTED}○${NC} $label" ;;
        warn)    echo -e "  ${WARNING}⚠${NC} $label" ;;
    esac
}

# Simple spinner while a command runs
spinner() {
    local pid=$1
    local msg="${2:-Working...}"
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}${spin:$((i % ${#spin})):1}${NC}  ${MUTED}${msg}${NC}"
        (( i++ ))
        sleep 0.1
    done
    printf "\r${SUCCESS}✔${NC}  ${msg}\n"
}

# Countdown pause
countdown() {
    local secs="${1:-3}"
    for (( i=secs; i>0; i-- )); do
        printf "\r${MUTED}Continuing in %d...${NC}" "$i"
        sleep 1
    done
    printf "\r%-30s\r" ""
}

# Press-Enter-to-continue prompt
pause() {
    echo
    read -rp "$(echo -e "${MUTED}  Press Enter to continue...${NC}")"
}

# Confirm (yes/no) prompt; returns 0 for yes, 1 for no
confirm() {
    local msg="${1:-Are you sure?}"
    local reply
    read -rp "$(echo -e "${WARNING}  ${msg} [yes/no]: ${NC}")" reply
    [[ "$reply" == "yes" ]]
}

# ════════════════════════════════════════════════════════
#  INPUT SANITIZATION
# ════════════════════════════════════════════════════════

# Validate that input is a safe filename (no path traversal)
sanitize_filename() {
    local input="$1"
    # Strip leading slashes, dots, and path components
    local safe
    safe="$(basename "$input")"
    # Remove characters that are dangerous in filenames
    safe="${safe//[^a-zA-Z0-9._-]/}"
    echo "$safe"
}

# Validate IP address format
is_valid_ip() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    [[ "$ip" =~ $regex ]] || return 1
    IFS='.' read -ra o <<< "$ip"
    for octet in "${o[@]}"; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

# Validate a hostname or domain
is_valid_host() {
    local host="$1"
    [[ "$host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$ ]]
}

# Validate CIDR notation
is_valid_cidr() {
    local cidr="$1"
    local ip="${cidr%/*}"
    local prefix="${cidr#*/}"
    is_valid_ip "$ip" && [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix >= 0 && prefix <= 32 ))
}

# Validate integer range
is_integer() {
    local val="$1" lo="${2:-}" hi="${3:-}"
    [[ "$val" =~ ^-?[0-9]+$ ]] || return 1
    [[ -n "$lo" && "$val" -lt "$lo" ]] && return 1
    [[ -n "$hi" && "$val" -gt "$hi" ]] && return 1
    return 0
}

# Prompt until a valid value is received
prompt_valid() {
    local prompt="$1"
    local validator="$2"   # name of validation function
    local result
    while true; do
        read -rp "$(echo -e "  ${PROMPT}${prompt}:${NC} ")" result
        if $validator "$result"; then
            echo "$result"
            return 0
        fi
        log_warning "Invalid input: '$result'. Please try again."
    done
}

# ════════════════════════════════════════════════════════
#  OS / ENVIRONMENT
# ════════════════════════════════════════════════════════

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release 2>/dev/null
        echo "${PRETTY_NAME:-$NAME}"
    elif [[ "$(uname)" == "Darwin" ]]; then
        echo "macOS $(sw_vers -productVersion 2>/dev/null)"
    else
        echo "$(uname -s) $(uname -r)"
    fi
}

# Check if a command exists
cmd_exists() { command -v "$1" &>/dev/null; }

# Require a command or exit with message
require_cmd() {
    local cmd="$1"
    local install_hint="${2:-}"
    if ! cmd_exists "$cmd"; then
        log_error "Required command '$cmd' not found."
        [[ -n "$install_hint" ]] && log_info "Install with: $install_hint"
        return 1
    fi
}

# Check if running as root
is_root() { [[ "$EUID" -eq 0 ]]; }

# Require root or prompt sudo
require_root() {
    if ! is_root; then
        log_warning "This operation requires root privileges."
        return 1
    fi
}

# ════════════════════════════════════════════════════════
#  REPORTING / OUTPUT
# ════════════════════════════════════════════════════════

# Save output to timestamped file in OUTPUT_DIR
save_output() {
    local name="$1"
    local content="$2"
    if [[ -n "$OUTPUT_DIR" ]]; then
        local file="$OUTPUT_DIR/${name}_$(date '+%Y%m%d_%H%M%S').txt"
        echo "$content" > "$file"
        log_success "Output saved to: $file"
    fi
}

# Append a section to the current session report
append_report() {
    local section="$1"
    local content="$2"
    if [[ -n "$SESSION_REPORT" ]]; then
        {
            echo "══════════════════════════════════"
            echo "  $section"
            echo "══════════════════════════════════"
            echo "$content"
            echo
        } >> "$SESSION_REPORT"
    fi
}

# ════════════════════════════════════════════════════════
#  NETWORK UTILITIES
# ════════════════════════════════════════════════════════

# Get default gateway IP
get_gateway() {
    ip route show default 2>/dev/null | awk '{print $3}' | head -1
}

# Get primary non-loopback IPv4
get_local_ip() {
    ip -4 addr show scope global 2>/dev/null \
        | grep -oP 'inet \K[\d.]+' | head -1
}

# Get public IP (with timeout)
get_public_ip() {
    local ip
    ip=$(curl -s --max-time 4 https://ifconfig.me 2>/dev/null \
      || curl -s --max-time 4 https://icanhazip.com 2>/dev/null)
    echo "${ip:-unavailable}"
}

# Resolve hostname to IP
resolve_host() {
    local host="$1"
    if cmd_exists dig; then
        dig +short "$host" 2>/dev/null | grep -m1 '\.'
    elif cmd_exists nslookup; then
        nslookup "$host" 2>/dev/null | awk '/^Address: / {print $2}' | head -1
    fi
}

# Millisecond ping latency to a host
ping_latency() {
    local host="${1:-8.8.8.8}"
    ping -c 3 -W 2 "$host" 2>/dev/null \
        | grep -oP 'avg = \K[0-9.]+' \
        || ping -c 3 -W 2 "$host" 2>/dev/null \
        | grep -oP 'rtt min/avg.* = [0-9.]+/\K[0-9.]+'
}

# Check if a port is open (TCP)
port_open() {
    local host="$1" port="$2"
    timeout 2 bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null
}