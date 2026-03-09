#!/usr/bin/env bash

# Prevent double loading
[[ -n "$_LIB_INIT_LOADED" ]] && return
_LIB_INIT_LOADED=1

# Resolve project root only if not already defined
if [[ -z "$PROJECT_ROOT" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
fi

export PROJECT_ROOT

# Load configuration
source "$PROJECT_ROOT/config/settings.conf"

# Ensure directories exist
mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Load libraries
source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/lib/logging.sh"