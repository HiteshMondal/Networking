#!/bin/bash

# /lib/colors.sh
# Centralized color & style definitions — Dark Operator palette
# Double-source guard (NOT exported — prevents child process re-source issues)
[[ -n "$_COLORS_LOADED" ]] && return 0
_COLORS_LOADED=1

#  RESET
export NC='\033[0m'

#  TEXT STYLES
export BOLD='\033[1m'
export DIM='\033[2m'
export ITALIC='\033[3m'
export UNDERLINE='\033[4m'
export BLINK='\033[5m'
export REVERSE='\033[7m'
export STRIKETHROUGH='\033[9m'

#  STANDARD COLORS
export BLACK='\033[0;30m'
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export MAGENTA='\033[0;35m'
export CYAN='\033[0;36m'
export WHITE='\033[0;37m'

#  BOLD COLORS
export BOLD_BLACK='\033[1;30m'
export BOLD_RED='\033[1;31m'
export BOLD_GREEN='\033[1;32m'
export BOLD_YELLOW='\033[1;33m'
export BOLD_BLUE='\033[1;34m'
export BOLD_MAGENTA='\033[1;35m'
export BOLD_CYAN='\033[1;36m'
export BOLD_WHITE='\033[1;37m'

#  BACKGROUND COLORS
export BG_BLACK='\033[40m'
export BG_RED='\033[41m'
export BG_GREEN='\033[42m'
export BG_YELLOW='\033[43m'
export BG_BLUE='\033[44m'
export BG_MAGENTA='\033[45m'
export BG_CYAN='\033[46m'
export BG_WHITE='\033[47m'

#  256-COLOR ACCENTS — Dark Operator palette
#  Structure: electric blues as chrome, mint greens for success,
#  amber/gold for highlights, coral for errors, pale cyan for data.
export ORANGE='\033[38;5;214m'       # warm orange — warnings, accents
export PURPLE='\033[38;5;141m'       # lavender purple
export TEAL='\033[38;5;43m'          # medium teal — upgraded from 87 (ice)
export PINK='\033[38;5;207m'         # hot pink
export LIME='\033[38;5;154m'         # lime
export GOLD='\033[38;5;220m'         # bright gold — prompts, highlights
export GRAY='\033[38;5;242m'         # mid gray — muted text
export DARK_GRAY='\033[38;5;238m'    # charcoal — dividers, dim elements
export LIGHT_GRAY='\033[38;5;250m'   # silver
export STEEL='\033[38;5;39m'         # electric blue — chrome, borders (upgraded from 68)
export AMBER='\033[38;5;178m'        # amber — section headings

#  EXTENDED PALETTE — new colors added for richer visual hierarchy
export AQUA='\033[38;5;51m'          # aqua — banner title
export ELECTRIC='\033[38;5;45m'      # cyan-blue — info messages
export MINT='\033[38;5;77m'          # mint green — success
export CORAL='\033[38;5;203m'        # coral red — errors
export PALE_CYAN='\033[38;5;80m'     # pale cyan — label keys in kv()
export NEAR_WHITE='\033[38;5;252m'   # near white — values, body text
export CORNFLOWER='\033[38;5;33m'    # cornflower blue — header box borders, inner rules
export CHARCOAL='\033[38;5;238m'     # charcoal — fine dividers (alias for DARK_GRAY)
export LAVENDER='\033[38;5;141m'     # lavender — highlight callouts

#  SEMANTIC ALIASES
#  Use these throughout the toolkit — intent is clear at a glance.
export SUCCESS="$MINT"               # [+] operation succeeded   — mint green
export FAILURE="$CORAL"              # [!] operation failed/error — coral red
export WARNING="$ORANGE"             # [~] warning / caution      — warm orange
export INFO="$ELECTRIC"              # [i] informational output   — cyan-blue
export PROMPT="$GOLD"                # user-facing prompt text    — bright gold
export SECTION="$CYAN"               # section / subsection labels
export HEADER="$BOLD_BLUE"           # top-level header decoration
export LABEL="$PALE_CYAN"            # key in key/value pairs     — pale cyan
export VALUE="$NEAR_WHITE"           # value in key/value pairs   — near white
export MUTED="$GRAY"                 # de-emphasised / secondary  — mid gray
export ACCENT="$ORANGE"              # highlighted step / action  — warm orange
export BORDER="$STEEL"               # box / divider borders      — electric blue
export TITLE="$BOLD_WHITE"           # prominent title text
export HIGHLIGHT="$LAVENDER"         # special callout / notice   — lavender