#!/bin/bash

#  Double-source guard 
[[ -n "${_LOGGING_LOADED:-}" ]] && return 0
_LOGGING_LOADED=1

#  Hard dependency 
: "${PROJECT_ROOT:?[logging.sh] PROJECT_ROOT must be set before sourcing}"
: "${LOG_DIR:="${PROJECT_ROOT}/logs"}"

#  Level ordering 
# Numeric weight per level — records below LOG_LEVEL are silently dropped.
declare -A _LOG_LEVEL_WEIGHT=(
    [DEBUG]=0 [INFO]=1 [SUCCESS]=2 [WARNING]=3 [ERROR]=4 [CRITICAL]=5
)
# Resolve once at source time from settings.conf's LOG_LEVEL export.
_LOG_MIN_WEIGHT="${_LOG_LEVEL_WEIGHT[${LOG_LEVEL:-INFO}]:-1}"

#  Session ID (unique per toolkit invocation) 
if [[ -z "${TOOLKIT_SESSION_ID:-}" ]]; then
    export TOOLKIT_SESSION_ID="sess_$(date '+%Y%m%d_%H%M%S')_$$"
fi

#  Cached values (avoid forking on every log line) 
_LOG_HOST="$(hostname 2>/dev/null || echo unknown)"
_LOG_USER="$(whoami  2>/dev/null || echo unknown)"

#  Internal helpers 

# _json_escape <string>
# Escapes a raw string for safe embedding inside a JSON double-quoted value.
_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"     # \ → \\  (must be first to avoid double-escaping)
    s="${s//\"/\\\"}"     # " → \"
    s="${s//$'\n'/\\n}"   # newline → \n
    s="${s//$'\r'/\\r}"   # CR      → \r
    s="${s//$'\t'/\\t}"   # tab     → \t
    printf '%s' "$s"
}

# _iso8601
# Emits current UTC time as a proper ISO-8601 string with Z suffix.
# Fallback appends +00:00 when -u flag is unavailable (busybox date).
_iso8601() {
    date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
        || date '+%Y-%m-%dT%H:%M:%S+00:00'
}

# _log_json <level> <message> [key=value ...]
# Core emitter — assembles one JSON record and appends it to both the
# module log (STRUCTURED_LOG_FILE) and the global audit trail (toolkit.jsonl).
# Silently returns early if <level>'s weight is below _LOG_MIN_WEIGHT.
_log_json() {
    local level="$1"
    local message="$2"
    shift 2

    #  Level filter 
    local weight="${_LOG_LEVEL_WEIGHT[$level]:-1}"
    [[ "$weight" -lt "$_LOG_MIN_WEIGHT" ]] && return 0

    #  Build data object from key=value pairs 
    local data_pairs="" sep=""
    for kv in "$@"; do
        local key="${kv%%=*}"
        local val="${kv#*=}"
        data_pairs+="${sep}\"$(_json_escape "$key")\":\"$(_json_escape "$val")\""
        sep=","
    done

    #  Assemble JSON record using printf -v (no subshell) 
    local record
    printf -v record \
        '{"timestamp":"%s","session":"%s","level":"%s","module":"%s","host":"%s","user":"%s","message":"%s","data":{%s}}' \
        "$(_iso8601)" \
        "$(_json_escape "${TOOLKIT_SESSION_ID}")" \
        "${level}" \
        "$(_json_escape "${LOG_MODULE:-main}")" \
        "$(_json_escape "${_LOG_HOST}")" \
        "$(_json_escape "${_LOG_USER}")" \
        "$(_json_escape "${message}")" \
        "${data_pairs}"

    #  Write to disk 
    mkdir -p "$LOG_DIR" 2>/dev/null

    if [[ -n "${STRUCTURED_LOG_FILE:-}" ]]; then
        printf '%s\n' "$record" >> "$STRUCTURED_LOG_FILE"
    fi

    # Global audit trail — honours ENABLE_AUDIT_LOG from settings.conf
    if [[ "${ENABLE_AUDIT_LOG:-true}" == "true" ]]; then
        printf '%s\n' "$record" >> "${LOG_DIR}/toolkit.jsonl"
    fi
}

#  Public lifecycle API 

# log_init <module_id>
# Call once at the top of each script.
#   • Sets LOG_MODULE and STRUCTURED_LOG_FILE for this run
#   • Emits a START record with PID and session ID
#   • Registers log_end as an EXIT trap automatically, composing with any
#     existing trap rather than clobbering it
#
# Example:  log_init "malware_analysis"
log_init() {
    local module_id="$1"
    if [[ -z "$module_id" ]]; then
        echo "[logging.sh] log_init requires a module_id argument" >&2
        return 1
    fi

    export LOG_MODULE="$module_id"

    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    export STRUCTURED_LOG_FILE="${LOG_DIR}/${module_id}_${timestamp}.jsonl"

    mkdir -p "$LOG_DIR"
    : > "$STRUCTURED_LOG_FILE"   # create/truncate without a subshell

    _log_json "INFO" "Module execution started" \
        "module=${module_id}" \
        "session=${TOOLKIT_SESSION_ID}" \
        "pid=$$"

    # Register log_end as EXIT trap.  Compose with any pre-existing trap so we
    # don't silently discard a caller's cleanup handler.
    local _prev_trap
    _prev_trap=$(trap -p EXIT | sed "s/^trap -- '//;s/' EXIT$//")
    if [[ -n "$_prev_trap" ]]; then
        # shellcheck disable=SC2064
        trap "${_prev_trap}; log_end \$?" EXIT
    else
        trap 'log_end $?' EXIT
    fi
}

# log_end [exit_code]
# Emits a STOP record with the final exit status.
# Called automatically by the EXIT trap set in log_init — you rarely need to
# call this manually, but you can: log_end $?
log_end() {
    local exit_code="${1:-0}"
    local status="success"
    [[ "$exit_code" -ne 0 ]] && status="error"

    _log_json "INFO" "Module execution completed" \
        "exit_code=${exit_code}" \
        "status=${status}"
}

#  Level wrappers 

log_debug()    { _log_json "DEBUG"    "$1" "${@:2}"; }
log_info()     { _log_json "INFO"     "$1" "${@:2}"; }
log_success()  { _log_json "SUCCESS"  "$1" "${@:2}"; }
log_warning()  { _log_json "WARNING"  "$1" "${@:2}"; }
log_error()    { _log_json "ERROR"    "$1" "${@:2}"; }
log_critical() { _log_json "CRITICAL" "$1" "${@:2}"; }

#  Semantic helpers 

# log_section <title>
# Emits a visual section separator — useful for grouping phases of a long
# script.  Appears as a distinct INFO record with type=section in the dashboard
# so the UI can render phase boundaries.
#
# Example:  log_section "Static Analysis Phase"
log_section() {
    local title="$1"
    _log_json "INFO" "=== ${title} ===" \
        "type=section" \
        "section_title=${title}"
}

# log_finding <severity> <title> <detail>
# Emits a structured security finding.
#
# The severity drives the JSON log level automatically:
#   critical | high  →  CRITICAL
#   medium           →  WARNING
#   low | info       →  INFO
#
# All finding records carry type=finding and are aggregated by the dashboard's
# /api/findings endpoint, sorted by severity weight.
#
# severity: critical | high | medium | low | info
#
# Example:
#   log_finding "high"     "UPX packer detected"   "/tmp/payload — entropy 7.9"
#   log_finding "medium"   "World-writable cron"   "/etc/cron.d/job is 777"
#   log_finding "critical" "Root shell left open"  "PID 4412 — /bin/bash -i"
log_finding() {
    local severity="$1"
    local title="$2"
    local detail="$3"

    local level
    case "${severity,,}" in        # match case-insensitively
        critical|high) level="CRITICAL" ;;
        medium)        level="WARNING"  ;;
        low|info|*)    level="INFO"     ;;
    esac

    _log_json "$level" "FINDING [${severity^^}]: ${title}" \
        "type=finding" \
        "finding_severity=${severity,,}" \
        "finding_title=${title}" \
        "finding_detail=${detail}"
}

# log_metric <name> <value> [unit]
# Records a numeric measurement for trend analysis and dashboard aggregation.
# Stored in the data object; query via jq from toolkit.jsonl.
#
# Example:
#   log_metric "files_scanned"    "142"  "count"
#   log_metric "entropy"          "7.9"  "bits"
#   log_metric "scan_duration"    "47"   "seconds"
log_metric() {
    local name="$1"
    local value="$2"
    local unit="${3:-count}"
    _log_json "INFO" "METRIC: ${name}=${value} ${unit}" \
        "type=metric" \
        "metric_name=${name}" \
        "metric_value=${value}" \
        "metric_unit=${unit}"
}

# log_audit <action> <target> [key=value ...]
# Records a security-auditable action.
#
# Audit records bypass LOG_LEVEL filtering — they are ALWAYS written,
# regardless of the configured minimum level.  This matches the behaviour
# of syslog AUTH facility and auditd.
#
# Example:
#   log_audit "read"    "/etc/passwd"
#   log_audit "execute" "/usr/bin/strace"  "pid=9812"
#   log_audit "modify"  "/etc/hosts.allow" "change=added_rule"
log_audit() {
    local action="$1"
    local target="$2"
    shift 2

    # Temporarily suppress the level filter for audit records
    local _saved_min="$_LOG_MIN_WEIGHT"
    _LOG_MIN_WEIGHT=0

    _log_json "INFO" "AUDIT: ${action} → ${target}" \
        "type=audit" \
        "audit_action=${action}" \
        "audit_target=${target}" \
        "$@"

    _LOG_MIN_WEIGHT="$_saved_min"
}