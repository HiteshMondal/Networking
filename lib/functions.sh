#!/bin/bash
# /lib/functions.sh
# Shared utility functions for the Networking & Cybersecurity Toolkit
# Used ASCII as it is compatible for all types of terminals
# Double-source guard (NOT exported — prevents child process re-source issues)
[[ -n "${_FUNCTIONS_LOADED:-}" ]] && return 0
_FUNCTIONS_LOADED=1

# Source colors if not already loaded
[[ -z "$_COLORS_LOADED" ]] && source "$(dirname "${BASH_SOURCE[0]}")/colors.sh"

#  LOGGING
log_success() { echo -e "${SUCCESS}[+] $*${NC}"; }
log_error()   { echo -e "${FAILURE}[!] $*${NC}" >&2; }
log_warning() { echo -e "${WARNING}[~] $*${NC}"; }
log_info()    { echo -e "${INFO}[i] $*${NC}"; }
log_debug()   { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${MUTED}[D] $*${NC}"; }
log_step()    { echo -e "${ACCENT}[>] $*${NC}"; }

# Write to log file with timestamp.
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
    clear
    local W=70
    local inner=$(( W - 2 ))

    local top   mid_blank bot
    top=$(echo -e "${BORDER}┏$(printf '━%.0s' $(seq 1 $inner))┓${NC}")
    bot=$(echo -e "${BORDER}┗$(printf '━%.0s' $(seq 1 $inner))┛${NC}")
    mid_blank="${BORDER}┃${NC}$(printf '%*s' $inner '')${BORDER}┃${NC}"

    local rule
    rule="${BORDER}┃${NC}${CORNFLOWER}  $(printf '─%.0s' $(seq 1 $(( inner - 4 )))  )  ${NC}${BORDER}┃${NC}"

    local title_text="  Networking & Cybersecurity Automation Toolkit"
    local sub_text="  Professional Security & Network Analysis Suite"

    local title_line sub_line
    title_line="${BORDER}┃${NC}  ${BOLD}${AQUA}$(printf "%-$((inner-4))s" "$title_text")${NC}  ${BORDER}┃${NC}"
    sub_line="${BORDER}┃${NC}  ${MUTED}$(printf "%-$((inner-4))s" "$sub_text")${NC}  ${BORDER}┃${NC}"

    echo
    echo -e "$top"
    echo -e "$mid_blank"
    echo -e "$title_line"
    echo -e "$rule"
    echo -e "$sub_line"
    echo -e "$mid_blank"
    echo -e "$bot"
    echo
}

# Section divider
# print_divider [label] [style: thin|thick|double]
print_divider() {
    local label="${1:-}"
    local style="${2:-thin}"
    local W=66
    local char line

    case "$style" in
        thick)  char='━' ;;
        double) char='═' ;;
        *)      char='─' ;;
    esac

    line=$(printf "${char}%.0s" $(seq 1 $W))
    echo
    echo -e "${BORDER}${line}${NC}"
    if [[ -n "$label" ]]; then
        printf "${BORDER}${char}${NC} ${TITLE}%-$((W-3))s${NC}${BORDER}${char}${NC}\n" \
            " $label"
        echo -e "${BORDER}${line}${NC}"
    fi
    echo
}

# Header box
header() {
    local title="$1"
    local color="${2:-$CORNFLOWER}"
    local W=68
    local inner=$(( W - 4 ))
    local title_len=${#title}
    local total_pad=$(( inner - title_len ))
    local left_pad=$(( total_pad / 2 ))
    local right_pad=$(( total_pad - left_pad ))

    local top mid bot
    top="${color}  ╔$(printf '═%.0s' $(seq 1 $(( inner + 2 )) )  )╗${NC}"
    mid="${color}  ║${NC}$(printf '%*s' $left_pad '')${BOLD}${TITLE}${title}${NC}$(printf '%*s' $right_pad '')${color}  ║${NC}"
    bot="${color}  ╚$(printf '═%.0s' $(seq 1 $(( inner + 2 )) )  )╝${NC}"

    echo
    echo -e "$top"
    echo -e "$mid"
    echo -e "$bot"
    echo
}

# Section heading
section() {
    local title="$1"
    local rule
    rule=$(printf '┄%.0s' $(seq 1 58))
    echo
    echo -e "${AMBER}${BOLD}  ◆ ${title}${NC}"
    echo -e "${DARK_GRAY}  ${rule}${NC}"
}

# Key/value pair — pale-cyan key, charcoal pipe separator, near-white value
#
#   Operating System          │  Ubuntu 24.04.1 LTS
kv() {
    local key="$1"
    local val="$2"
    printf "  ${LABEL}%-26s${NC}${DARK_GRAY}  │  ${NC}${VALUE}%s${NC}\n" "$key" "$val"
}

# Status line
status_line() {
    local state="$1"
    local label="$2"
    case "$state" in
        ok)      echo -e "  ${SUCCESS}✔${NC}  ${VALUE}$label${NC}" ;;
        fail)    echo -e "  ${FAILURE}✘${NC}  ${VALUE}$label${NC}" ;;
        neutral) echo -e "  ${MUTED}○${NC}  ${MUTED}$label${NC}"  ;;
        warn)    echo -e "  ${WARNING}⚠${NC}  ${VALUE}$label${NC}" ;;
    esac
}

# Progress bar
progress_bar() {
    local val="${1:-0}"
    local max="${2:-100}"
    local label="${3:-}"
    local width=36
    local filled=$(( val * width / max ))
    local empty=$(( width - filled ))
    local bar_filled bar_empty
    bar_filled=$(printf '█%.0s' $(seq 1 $filled) 2>/dev/null || printf '%*s' "$filled" '' | tr ' ' '█')
    bar_empty=$(printf '░%.0s'  $(seq 1 $empty)  2>/dev/null || printf '%*s' "$empty"  '' | tr ' ' '░')
    printf "  ${LABEL}%-20s${NC} [${SUCCESS}%s${DARK_GRAY}%s${NC}] ${GOLD}%s/%s${NC}\n" \
        "$label" "$bar_filled" "$bar_empty" "$val" "$max"
}

# Spinner
spinner() {
    local pid=$1
    local msg="${2:-Working...}"
    local -a frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CORNFLOWER}%s${NC}  ${MUTED}%s${NC}   " "${frames[$((i % ${#frames[@]}))]}" "$msg"
        (( i++ ))
        sleep 0.08
    done
    printf "\r  ${SUCCESS}✔${NC}  ${VALUE}%s${NC}\n" "$msg"
}

# Countdown
countdown() {
    local secs="${1:-3}"
    for (( i=secs; i>0; i-- )); do
        printf "\r  ${MUTED}Continuing in %d...${NC}   " "$i"
        sleep 1
    done
    printf "\r%-40s\r" ""
}

# Pause
pause() {
    echo
    echo -e "  ${DARK_GRAY}$(printf '╌%.0s' $(seq 1 58))${NC}"
    read -rp "$(echo -e "  ${MUTED}Press Enter to continue...${NC}  ")"
}

# Confirm
confirm() {
    local msg="${1:-Are you sure?}"
    local reply
    read -rp "$(echo -e "  ${WARNING}[?] ${msg} [yes/no]: ${NC}")" reply
    [[ "$reply" == "yes" ]]
}

# Horizontal rule
separator() {
    local char="${1:--}"
    local width="${2:-66}"
    printf '%*s\n' "$width" '' | tr ' ' "$char"
}

#  INPUT SANITIZATION
sanitize_filename() {
    local input="$1"
    local safe
    safe="$(basename "$input")"
    safe="${safe//[^a-zA-Z0-9._-]/}"
    echo "$safe"
}

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

is_valid_host() {
    local host="$1"
    local label='[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
    [[ "$host" =~ ^${label}(\.${label})*\.?$ ]]
}

is_valid_cidr() {
    local cidr="$1"
    local ip="${cidr%/*}"
    local prefix="${cidr#*/}"
    is_valid_ip "$ip" && [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix >= 0 && prefix <= 32 ))
}

is_integer() {
    local val="$1" lo="${2:-}" hi="${3:-}"
    [[ "$val" =~ ^-?[0-9]+$ ]] || return 1
    [[ -n "$lo" && "$val" -lt "$lo" ]] && return 1
    [[ -n "$hi" && "$val" -gt "$hi" ]] && return 1
    return 0
}

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

cmd_exists()  { command -v "$1" &>/dev/null; }

require_cmd() {
    local cmd="$1"
    local install_hint="${2:-}"
    if ! cmd_exists "$cmd"; then
        log_error "Required command '$cmd' not found."
        [[ -n "$install_hint" ]] && log_info "Install with: $install_hint"
        return 1
    fi
}

is_root()     { [[ "$EUID" -eq 0 ]]; }

require_root() {
    if ! is_root; then
        log_warning "This operation requires root privileges."
        return 1
    fi
}

#  REPORTING / OUTPUT
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

append_report() {
    local section_name="$1"
    local content="$2"
    if [[ -n "$SESSION_REPORT" ]]; then
        {
            echo "======================================"
            echo "  $section_name"
            echo "======================================"
            echo "$content"
            echo
        } >> "$SESSION_REPORT"
    fi
}

#  NETWORK UTILITIES
get_gateway() {
    ip route show default 2>/dev/null | awk '{print $3}' | head -1
}

get_local_ip() {
    ip -4 addr show scope global 2>/dev/null \
        | grep -oP 'inet \K[\d.]+' | head -1
}

get_public_ip() {
    local ip
    ip=$(curl -s --max-time 4 https://ifconfig.me 2>/dev/null \
      || curl -s --max-time 4 https://icanhazip.com 2>/dev/null)
    echo "${ip:-unavailable}"
}

resolve_host() {
    local host="$1"
    if cmd_exists dig; then
        dig +short "$host" 2>/dev/null | grep -m1 '\.'
    elif cmd_exists nslookup; then
        nslookup "$host" 2>/dev/null | awk '/^Address: / {print $2}' | head -1
    fi
}

ping_latency() {
    local host="${1:-8.8.8.8}"
    local output
    output=$(ping -c 3 -W 2 "$host" 2>/dev/null)
    echo "$output" \
        | grep -oP 'avg = \K[0-9.]+' \
        || echo "$output" \
        | grep -oP 'rtt min/avg.* = [0-9.]+/\K[0-9.]+'
}

port_open() {
    local host="$1" port="$2"
    timeout 2 bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null
}