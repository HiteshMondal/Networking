#!/bin/bash

# /lib/colors.sh
# Centralized color definitions

# ── Regular Colors ───────────────────────────────────────
export BLACK='\033[0;30m'
export RED='\033[1;31m'
export GREEN='\033[1;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[1;34m'
export MAGENTA='\033[1;35m'
export CYAN='\033[1;36m'
export WHITE='\033[1;37m'
export NC='\033[0m'
export BOLD='\033[1m'

# ── Bold Colors ──────────────────────────────────────────
export BOLD='\033[1m'
export BOLD_RED='\033[1;31m'
export BOLD_GREEN='\033[1;32m'
export BOLD_YELLOW='\033[1;33m'
export BOLD_BLUE='\033[1;34m'
export BOLD_MAGENTA='\033[1;35m'
export BOLD_CYAN='\033[1;36m'
export BOLD_WHITE='\033[1;37m'

# ── Dim / Italic / Underline ─────────────────────────────
export DIM='\033[2m'
export ITALIC='\033[3m'
export UNDERLINE='\033[4m'
export BLINK='\033[5m'
export REVERSE='\033[7m'
export STRIKETHROUGH='\033[9m'

# ── Background Colors ────────────────────────────────────
export BG_BLACK='\033[40m'
export BG_RED='\033[41m'
export BG_GREEN='\033[42m'
export BG_YELLOW='\033[43m'
export BG_BLUE='\033[44m'
export BG_MAGENTA='\033[45m'
export BG_CYAN='\033[46m'
export BG_WHITE='\033[47m'

# ── 256-color Accents ────────────────────────────────────
export ORANGE='\033[38;5;214m'
export PURPLE='\033[38;5;141m'
export TEAL='\033[38;5;87m'
export PINK='\033[38;5;213m'
export LIME='\033[38;5;154m'
export GOLD='\033[38;5;220m'
export GRAY='\033[38;5;245m'
export DARK_GRAY='\033[38;5;238m'

# ── Semantic Aliases ─────────────────────────────────────
export SUCCESS="$BOLD_GREEN"
export FAILURE="$BOLD_RED"
export WARNING="$BOLD_YELLOW"
export INFO="$BOLD_CYAN"
export PROMPT="$BOLD_YELLOW"
export SECTION="$CYAN"
export HEADER="$BOLD_BLUE"
export LABEL="$GREEN"
export VALUE="$WHITE"
export MUTED="$GRAY"
export ACCENT="$ORANGE"

# Guard against double-sourcing
export _COLORS_LOADED=1
