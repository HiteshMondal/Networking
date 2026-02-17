#!/bin/bash
# /lib/functions.sh
# Shared utility functions for the Networking & Cybersecurity Toolkit

# Double-source guard
# NOT exported on purpose: if exported, child processes (bash script.sh)
# inherit the variable and the guard fires, skipping the whole file and
# leaving all functions undefined in that child.
[[ -n "$_FUNCTIONS_LOADED" ]] && return 0
_FUNCTIONS_LOADED=1

# Source colors if not already loaded
[[ -z "$_COLORS_LOADED" ]] && source "$(dirname "${BASH_SOURCE[0]}")/colors.sh"

#  LOGGING

log_success() { echo -e "${SUCCESS}[✔] $*${NC}"; }
log_error()   { echo -e "${FAILURE}[✘] $*${NC}" >&2; }
log_warning() { echo -e "${WARNING}[⚠] $*${NC}"; }
log_info()    { echo -e "${INFO}[ℹ] $*${NC}"; }
log_debug()   { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${MUTED}[DBG] $*${NC}"; }
log_step()    { echo -e "${ACCENT}[→] $*${NC}"; }

# Write to log file with timestamp.
# FIX: previously only checked [[ -n "$LOG_DIR" ]], which silently failed
# if the directory didn't exist yet. Now checks -d as well.
log_to_file() {
    local level="$1"; shift
    if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
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
    echo -e "${NC}"
    echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}${NC}                                                                ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}${NC}  ${RED}🚀${YELLOW} Networking ${GREEN}&${BLUE} Cybersecurity ${MAGENTA}Automation Toolkit${NC} ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}${NC}  ${BLUE}🔒${WHITE} Professional ${CYAN}Security ${GREEN}& ${YELLOW}Network Analysis Suite${NC} ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}${NC}                                                                ${CYAN}${BOLD}${NC}"
    echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${NC}"
}

# Draw a horizontal separator.
separator() {
    local char="${1:-─}"
    local width="${2:-60}"
    printf '%s\n' "$(printf "%.0s${char}" $(seq 1 "$width"))"
}

# Section heading with box border.
# FIX: integer division of (width - title_len - 2) / 2 truncates for
# odd-length titles, causing the right ║ to land one column early.
# Now left_pad and right_pad are computed separately so right_pad
# absorbs the remainder and the closing ║ always stays in column.
header() {
    local title="$1"
    local color="${2:-$BOLD_CYAN}"
    local width=64
    local inner=$(( width - 2 ))               # characters between ╔ and ╗
    local title_len=${#title}
    local total_pad=$(( inner - title_len - 2 )) # 2 spaces around title
    local left_pad=$(( total_pad / 2 ))
    local right_pad=$(( total_pad - left_pad ))  # absorbs odd remainder
    echo
    echo -e "${color}╔$(printf '═%.0s' $(seq 1 "$inner"))╗${NC}"
    printf "${color}║%${left_pad}s %s %${right_pad}s║${NC}\n" "" "$title" ""
    echo -e "${color}╚$(printf '═%.0s' $(seq 1 "$inner"))╝${NC}"
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

# Print a status line: ✔/✘/○/⚠ + label
status_line() {
    local state="$1"
    local label="$2"
    case "$state" in
        ok)      echo -e "  ${SUCCESS}✔${NC} $label" ;;
        fail)    echo -e "  ${FAILURE}✘${NC} $label" ;;
        neutral) echo -e "  ${MUTED}○${NC} $label" ;;
        warn)    echo -e "  ${WARNING}⚠${NC} $label" ;;
    esac
}

# Simple spinner while a background PID is running.
# Usage:  some_command & spinner $! "message"
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

# Count-down then clear the line
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

#  INPUT SANITIZATION

# Strip path traversal components and dangerous filename characters.
sanitize_filename() {
    local input="$1"
    local safe
    safe="$(basename "$input")"
    safe="${safe//[^a-zA-Z0-9._-]/}"
    echo "$safe"
}

# Validate an IPv4 address (dotted decimal, each octet 0-255).
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

# Validate a hostname or FQDN.
#   • requires each label to start and end with an alnum
#   • allows hyphens only in the middle of a label
#   • forbids consecutive dots
#   • accepts a single-label name (e.g. "localhost")
is_valid_host() {
    local host="$1"
    # Each dot-separated label: starts with alnum, ends with alnum,
    # may contain hyphens in the middle.
    local label='[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
    [[ "$host" =~ ^${label}(\.${label})*\.?$ ]]
}

# Validate CIDR notation (e.g. 192.168.1.0/24)
is_valid_cidr() {
    local cidr="$1"
    local ip="${cidr%/*}"
    local prefix="${cidr#*/}"
    is_valid_ip "$ip" && [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix >= 0 && prefix <= 32 ))
}

# Validate an integer, optionally within [lo, hi].
is_integer() {
    local val="$1" lo="${2:-}" hi="${3:-}"
    [[ "$val" =~ ^-?[0-9]+$ ]] || return 1
    [[ -n "$lo" && "$val" -lt "$lo" ]] && return 1
    [[ -n "$hi" && "$val" -gt "$hi" ]] && return 1
    return 0
}

# Prompt repeatedly until the validator function returns 0.
# Usage: result=$(prompt_valid "Enter IP" is_valid_ip)
prompt_valid() {
    local prompt="$1"
    local validator="$2"
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

#  OS / ENVIRONMENT

# Return a human-readable OS name.
detect_os() {
    if [[ -f /etc/os-release ]]; then
        local pretty name
        pretty=$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null \
                 | cut -d= -f2- | tr -d '"')
        name=$(grep -m1 '^NAME=' /etc/os-release 2>/dev/null \
               | cut -d= -f2- | tr -d '"')
        echo "${pretty:-${name:-unknown}}"
    elif [[ "$(uname)" == "Darwin" ]]; then
        echo "macOS $(sw_vers -productVersion 2>/dev/null)"
    else
        echo "$(uname -s) $(uname -r)"
    fi
}

# Return 0 if the named command is on PATH.
cmd_exists() { command -v "$1" &>/dev/null; }

# Warn and return 1 if a required command is absent.
require_cmd() {
    local cmd="$1"
    local install_hint="${2:-}"
    if ! cmd_exists "$cmd"; then
        log_error "Required command '$cmd' not found."
        [[ -n "$install_hint" ]] && log_info "Install with: $install_hint"
        return 1
    fi
}

# Return 0 if running as root (EUID == 0).
is_root() { [[ "$EUID" -eq 0 ]]; }

# Warn and return 1 if not root.
require_root() {
    if ! is_root; then
        log_warning "This operation requires root privileges."
        return 1
    fi
}

#  REPORTING / OUTPUT

# Write content to a timestamped file in OUTPUT_DIR.
save_output() {
    local name="$1"
    local content="$2"
    if [[ -n "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR"
        local file="$OUTPUT_DIR/${name}_$(date '+%Y%m%d_%H%M%S').txt"
        echo "$content" > "$file"
        log_success "Output saved to: $file"
    fi
}

# Append a labelled section to the session report file.
append_report() {
    local section_name="$1"
    local content="$2"
    if [[ -n "$SESSION_REPORT" ]]; then
        {
            echo "══════════════════════════════════"
            echo "  $section_name"
            echo "══════════════════════════════════"
            echo "$content"
            echo
        } >> "$SESSION_REPORT"
    fi
}

#  NETWORK UTILITIES

# Return the default gateway IP address.
get_gateway() {
    ip route show default 2>/dev/null | awk '{print $3}' | head -1
}

# Return the primary non-loopback global IPv4 address.
get_local_ip() {
    ip -4 addr show scope global 2>/dev/null \
        | grep -oP 'inet \K[\d.]+' | head -1
}

# Return this host's public IP via an external service (4s timeout).
get_public_ip() {
    local ip
    ip=$(curl -s --max-time 4 https://ifconfig.me 2>/dev/null \
      || curl -s --max-time 4 https://icanhazip.com 2>/dev/null)
    echo "${ip:-unavailable}"
}

# Resolve a hostname to its first A record.
resolve_host() {
    local host="$1"
    if cmd_exists dig; then
        dig +short "$host" 2>/dev/null | grep -m1 '\.'
    elif cmd_exists nslookup; then
        nslookup "$host" 2>/dev/null | awk '/^Address: / {print $2}' | head -1
    fi
}

# Return average RTT in milliseconds for a host.
ping_latency() {
    local host="${1:-8.8.8.8}"
    local output
    output=$(ping -c 3 -W 2 "$host" 2>/dev/null)
    # Linux format:  rtt min/avg/max/mdev = 1.2/3.4/5.6/0.7 ms
    # macOS format:  round-trip min/avg/max/stddev = 1.2/3.4/5.6/0.7 ms
    echo "$output" \
        | grep -oP 'avg = \K[0-9.]+' \
        || echo "$output" \
        | grep -oP 'rtt min/avg.* = [0-9.]+/\K[0-9.]+'
}

# Return 0 if TCP port is open on host (2s timeout).
port_open() {
    local host="$1" port="$2"
    timeout 2 bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null
}