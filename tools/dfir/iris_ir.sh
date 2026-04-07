#!/usr/bin/env bash
# tools/dfir/iris_ir.sh
# IRIS (dfir-iris) — incident response & case management via REST API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/iris"
LOG_FILE="$PROJECT_ROOT/logs/iris.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  config 
IRIS_URL="${IRIS_URL:-https://localhost}"
IRIS_TOKEN="${IRIS_TOKEN:-}"
IRIS_VERIFY_SSL="${IRIS_VERIFY_SSL:-true}"

_ssl_flag() { [[ "$IRIS_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

_iris() {
    local method="$1" endpoint="$2" data="${3:-}"
    local curl_args=(-sf -X "$method"
        -H "Authorization: Bearer $IRIS_TOKEN"
        -H "Content-Type: application/json"
    )
    [[ "$IRIS_VERIFY_SSL" == "false" ]] && curl_args+=(-k)
    [[ -n "$data" ]] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" "${IRIS_URL}${endpoint}" 2>>"$LOG_FILE"
}

_pretty() { command -v jq &>/dev/null && jq '.' || cat; }
_jq_val() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null || echo "?"; }

#  auth check 

_check_auth() {
    if [[ -z "$IRIS_TOKEN" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] IRIS API token: ${NC}")" IRIS_TOKEN
        echo
    fi

    local rc
    # shellcheck disable=SC2046
    rc=$(curl -sf $(_ssl_flag) \
         -H "Authorization: Bearer $IRIS_TOKEN" \
         "${IRIS_URL}/api/v2/users/me" \
         -o /dev/null -w "%{http_code}" 2>/dev/null) || true

    if [[ "$rc" != "200" ]]; then
        log_error "Cannot authenticate to IRIS (HTTP $rc)."
        log_info  "Check IRIS_URL=$IRIS_URL and IRIS_TOKEN."
        return 1
    fi
    log_success "Authenticated to IRIS: $IRIS_URL"
}

#  cases 

_list_cases() {
    log_info "Fetching case list..."
    _iris GET "/api/v2/cases" | python3 -c "
import sys, json
data = json.load(sys.stdin)
cases = data.get('data', {}).get('cases', [])
print(f\"  {'Case ID':<10} {'Status':<12} {'Name'}\")
print('  ' + '-'*60)
for c in cases:
    cid    = str(c.get('case_id','?'))
    status = c.get('case_close_date') and 'Closed' or 'Open'
    name   = c.get('case_name','?')[:50]
    print(f'  {cid:<10} {status:<12} {name}')
" 2>/dev/null || log_warn "Could not parse case list."
}

_create_case() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case name: ${NC}")" name
    read -rp "$(echo -e "  ${PROMPT}[?] Case description: ${NC}")" desc
    read -rp "$(echo -e "  ${PROMPT}[?] Customer name: ${NC}")" customer

    # Severity: 1=Unspecified 2=Low 3=Medium 4=High 5=Critical
    echo -e "  ${LABEL}Severity:${NC}  1=Unspecified  2=Low  3=Medium  4=High  5=Critical"
    read -rp "$(echo -e "  ${PROMPT}[?] Severity [3]: ${NC}")" sev
    sev="${sev:-3}"

    local payload
    payload=$(cat <<EOF
{
  "case_name":           "${name}",
  "case_description":    "${desc}",
  "case_customer":       "${customer}",
  "case_severity_id":    ${sev},
  "case_classification_id": 1
}
EOF
)
    log_info "Creating IRIS case: $name"
    _log "create case: name=$name sev=$sev"

    local result
    result=$(_iris POST "/api/v2/cases" "$payload") || {
        log_error "Failed to create case."
        return 1
    }

    echo "$result" | _pretty
    local cid
    cid=$(echo "$result" | _jq_val "d.get('data',{}).get('case_id','?')")
    log_success "Case created. ID: $cid"
    _log "case created: $cid"
}

#  IOCs 

_add_ioc() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case ID: ${NC}")" case_id
    [[ -z "$case_id" ]] && log_error "No case ID." && return 1

    echo -e "  ${LABEL}IOC types:${NC}  ip  domain  url  email  hash  filename  other"
    read -rp "$(echo -e "  ${PROMPT}[?] IOC type: ${NC}")" ioc_type
    read -rp "$(echo -e "  ${PROMPT}[?] IOC value: ${NC}")" ioc_value
    read -rp "$(echo -e "  ${PROMPT}[?] Description (optional): ${NC}")" ioc_desc

    # TLP: 1=WHITE 2=GREEN 3=AMBER 4=RED
    echo -e "  ${LABEL}TLP:${NC}  1=WHITE  2=GREEN  3=AMBER  4=RED"
    read -rp "$(echo -e "  ${PROMPT}[?] TLP [3]: ${NC}")" tlp
    tlp="${tlp:-3}"

    local payload
    payload=$(cat <<EOF
{
  "ioc_value":       "${ioc_value}",
  "ioc_type_id":     1,
  "ioc_type":        "${ioc_type}",
  "ioc_description": "${ioc_desc}",
  "ioc_tlp_id":      ${tlp}
}
EOF
)
    log_info "Adding IOC to case $case_id..."
    _iris POST "/api/v2/cases/${case_id}/iocs" "$payload" | _pretty
    log_success "IOC added."
    _log "IOC added: case=$case_id type=$ioc_type value=$ioc_value"
}

_list_iocs() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case ID: ${NC}")" case_id
    log_info "Fetching IOCs for case $case_id..."
    _iris GET "/api/v2/cases/${case_id}/iocs" | python3 -c "
import sys, json
data = json.load(sys.stdin)
iocs = data.get('data', {}).get('iocs', [])
print(f\"  {'Type':<15} {'TLP':<6} {'Value'}\")
print('  ' + '-'*60)
for i in iocs:
    t   = i.get('ioc_type','?')
    tlp = str(i.get('ioc_tlp_id','?'))
    val = i.get('ioc_value','?')[:50]
    print(f'  {t:<15} {tlp:<6} {val}')
" 2>/dev/null || log_warn "Could not parse IOC list."
}

#  timeline 

_add_event() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case ID: ${NC}")" case_id
    read -rp "$(echo -e "  ${PROMPT}[?] Event title: ${NC}")" title
    read -rp "$(echo -e "  ${PROMPT}[?] Event description: ${NC}")" desc
    read -rp "$(echo -e "  ${PROMPT}[?] Date/time (YYYY-MM-DD HH:MM, blank=now): ${NC}")" dt
    [[ -z "$dt" ]] && dt=$(date '+%Y-%m-%d %H:%M')

    local payload
    payload=$(cat <<EOF
{
  "event_title":       "${title}",
  "event_description": "${desc}",
  "event_date":        "${dt}",
  "event_tz":          "+00:00"
}
EOF
)
    log_info "Adding timeline event to case $case_id..."
    _iris POST "/api/v2/cases/${case_id}/events" "$payload" | _pretty
    log_success "Event added to timeline."
    _log "timeline event: case=$case_id title=$title dt=$dt"
}

#  notes 

_add_note() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case ID: ${NC}")" case_id
    read -rp "$(echo -e "  ${PROMPT}[?] Note title: ${NC}")" note_title
    read -rp "$(echo -e "  ${PROMPT}[?] Note content: ${NC}")" note_content

    local payload
    payload=$(cat <<EOF
{
  "note_title":   "${note_title}",
  "note_content": "${note_content}"
}
EOF
)
    log_info "Adding note to case $case_id..."
    _iris POST "/api/v2/cases/${case_id}/notes" "$payload" | _pretty
    log_success "Note added."
    _log "note added: case=$case_id title=$note_title"
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}IRIS — Incident Response Platform${NC}"
echo
kv "  IRIS URL" "$IRIS_URL"
echo

_check_auth || exit 1
echo

echo -e "  ${GREEN}  1.${NC}  List cases"
echo -e "  ${GREEN}  2.${NC}  Create new case"
echo -e "  ${GREEN}  3.${NC}  Add IOC to case"
echo -e "  ${GREEN}  4.${NC}  List IOCs for case"
echo -e "  ${GREEN}  5.${NC}  Add timeline event"
echo -e "  ${GREEN}  6.${NC}  Add note to case"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _list_cases  ;;
    2) _create_case ;;
    3) _add_ioc     ;;
    4) _list_iocs   ;;
    5) _add_event   ;;
    6) _add_note    ;;
    0) exit 0       ;;
    *) log_error "Invalid choice." ;;
esac