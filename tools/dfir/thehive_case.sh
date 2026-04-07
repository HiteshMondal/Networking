#!/usr/bin/env bash
# tools/dfir/thehive_case.sh
# TheHive — create & manage incident response cases via REST API

set -Eeuo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_ROOT="$(cd "$TOOLS_DIR/.." && pwd)"

source "$PROJECT_ROOT/lib/colors.sh"
source "$PROJECT_ROOT/lib/functions.sh"
source "$PROJECT_ROOT/config/settings.conf"

OUTPUT_DIR="$PROJECT_ROOT/output/thehive"
LOG_FILE="$PROJECT_ROOT/logs/thehive.log"
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

#  config 
THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
THEHIVE_KEY="${THEHIVE_KEY:-}"
THEHIVE_ORG="${THEHIVE_ORG:-}"
THEHIVE_VERIFY_SSL="${THEHIVE_VERIFY_SSL:-true}"

_ssl_flag() { [[ "$THEHIVE_VERIFY_SSL" == "false" ]] && echo "-k" || echo ""; }

_hive() {
    local method="$1" endpoint="$2" data="${3:-}"
    local curl_args=(-sf -X "$method"
        -H "Authorization: Bearer $THEHIVE_KEY"
        -H "Content-Type: application/json"
    )
    # shellcheck disable=SC2046
    [[ "$THEHIVE_VERIFY_SSL" == "false" ]] && curl_args+=(-k)
    [[ -n "$data" ]] && curl_args+=(-d "$data")
    curl "${curl_args[@]}" "${THEHIVE_URL}${endpoint}" 2>>"$LOG_FILE"
}

_pretty() { command -v jq &>/dev/null && jq '.' || cat; }

#  auth check 

_check_auth() {
    if [[ -z "$THEHIVE_KEY" ]]; then
        read -rsp "$(echo -e "  ${PROMPT}[?] TheHive API key: ${NC}")" THEHIVE_KEY
        echo
    fi

    local rc
    # shellcheck disable=SC2046
    rc=$(curl -sf $(_ssl_flag) \
         -H "Authorization: Bearer $THEHIVE_KEY" \
         "${THEHIVE_URL}/api/v1/user/current" \
         -o /dev/null -w "%{http_code}" 2>/dev/null) || true

    if [[ "$rc" != "200" ]]; then
        log_error "Cannot authenticate to TheHive (HTTP $rc)."
        log_info  "Check THEHIVE_URL=$THEHIVE_URL and THEHIVE_KEY."
        return 1
    fi
    log_success "Connected to TheHive: $THEHIVE_URL"
}

#  severity / TLP helpers 

_pick_severity() {
    echo -e "  ${LABEL}Severity:${NC}  1=Low  2=Medium  3=High  4=Critical"
    read -rp "$(echo -e "  ${PROMPT}[?] Severity [2]: ${NC}")" sev
    echo "${sev:-2}"
}

_pick_tlp() {
    echo -e "  ${LABEL}TLP:${NC}  0=WHITE  1=GREEN  2=AMBER  3=RED"
    read -rp "$(echo -e "  ${PROMPT}[?] TLP [2]: ${NC}")" tlp
    echo "${tlp:-2}"
}

#  cases 

_create_case() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case title: ${NC}")" title
    read -rp "$(echo -e "  ${PROMPT}[?] Description: ${NC}")" description
    local severity; severity=$(_pick_severity)
    local tlp;      tlp=$(_pick_tlp)
    read -rp "$(echo -e "  ${PROMPT}[?] Tags (comma-separated, optional): ${NC}")" tags_raw

    # Build tags JSON array
    local tags_json="[]"
    if [[ -n "$tags_raw" ]]; then
        tags_json=$(python3 -c "import sys,json; print(json.dumps([t.strip() for t in sys.argv[1].split(',')]))" "$tags_raw")
    fi

    local payload
    payload=$(cat <<EOF
{
  "title":       "${title}",
  "description": "${description}",
  "severity":    ${severity},
  "tlp":         ${tlp},
  "tags":        ${tags_json},
  "flag":        false
}
EOF
)
    log_info "Creating case: $title"
    _log "create case: $title sev=$severity tlp=$tlp"

    local result
    result=$(_hive POST "/api/v1/case" "$payload") || {
        log_error "Failed to create case."
        return 1
    }

    echo "$result" | _pretty
    local case_id
    case_id=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('_id','?'))" 2>/dev/null || true)
    log_success "Case created. ID: $case_id"
    _log "case created: $case_id"
}

_list_cases() {
    log_info "Fetching open cases..."
    _hive POST "/api/v1/case/_search" \
        '{"query":[{"_name":"listCase"},{"_name":"filter","_not":{"_field":"status","_value":"Resolved"}}],"ranges":["0-30"]}' \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
if not isinstance(data, list):
    print('  Unexpected response format.')
    sys.exit(0)
print(f\"  {'ID':<26} {'Sev':<5} {'Status':<12} {'Title'}\")
print('  ' + '-'*70)
for c in data:
    cid    = c.get('_id', '?')[:24]
    sev    = str(c.get('severity','?'))
    status = c.get('status','?')
    title  = c.get('title','?')[:40]
    print(f'  {cid:<26} {sev:<5} {status:<12} {title}')
" 2>/dev/null || log_warn "Could not parse case list."
}

_add_observable() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case ID: ${NC}")" case_id
    [[ -z "$case_id" ]] && log_error "No case ID." && return 1

    echo -e "  ${LABEL}Observable types:${NC}"
    echo -e "  ip  domain  url  hash  email  filename  other"
    read -rp "$(echo -e "  ${PROMPT}[?] Type: ${NC}")" obs_type
    read -rp "$(echo -e "  ${PROMPT}[?] Value: ${NC}")" obs_value
    read -rp "$(echo -e "  ${PROMPT}[?] Description (optional): ${NC}")" obs_desc
    local tlp; tlp=$(_pick_tlp)

    local payload
    payload=$(cat <<EOF
{
  "dataType":    "${obs_type}",
  "data":        "${obs_value}",
  "message":     "${obs_desc}",
  "tlp":         ${tlp},
  "ioc":         true
}
EOF
)
    log_info "Adding observable to case $case_id..."
    _hive POST "/api/v1/case/${case_id}/observable" "$payload" | _pretty
    log_success "Observable added."
    _log "observable added: case=$case_id type=$obs_type value=$obs_value"
}

_add_task() {
    read -rp "$(echo -e "  ${PROMPT}[?] Case ID: ${NC}")" case_id
    [[ -z "$case_id" ]] && log_error "No case ID." && return 1

    read -rp "$(echo -e "  ${PROMPT}[?] Task title: ${NC}")" task_title
    read -rp "$(echo -e "  ${PROMPT}[?] Assignee (login, optional): ${NC}")" assignee

    local payload="{\"title\": \"${task_title}\", \"status\": \"Waiting\"}"
    [[ -n "$assignee" ]] && \
        payload=$(echo "$payload" | python3 -c "import sys,json; d=json.load(sys.stdin); d['assignee']='${assignee}'; print(json.dumps(d))")

    log_info "Adding task to case $case_id..."
    _hive POST "/api/v1/case/${case_id}/task" "$payload" | _pretty
    log_success "Task added."
    _log "task added: case=$case_id title=$task_title"
}

#  menu 

clear; show_banner

echo -e "  ${LABEL}TheHive — Incident Response Case Manager${NC}"
echo
kv "  TheHive URL" "$THEHIVE_URL"
echo

_check_auth || exit 1
echo

echo -e "  ${GREEN}  1.${NC}  Create new case"
echo -e "  ${GREEN}  2.${NC}  List open cases"
echo -e "  ${GREEN}  3.${NC}  Add observable to case"
echo -e "  ${GREEN}  4.${NC}  Add task to case"
echo -e "  ${RED}  0.${NC}  Back"
echo
read -rp "$(echo -e "  ${PROMPT}[?] Choice: ${NC}")" choice
echo

case $choice in
    1) _create_case     ;;
    2) _list_cases      ;;
    3) _add_observable  ;;
    4) _add_task        ;;
    0) exit 0           ;;
    *) log_error "Invalid choice." ;;
esac