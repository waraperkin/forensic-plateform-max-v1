#!/bin/bash
# Deep test global — scénarios E2E « usage réel » (simulation Wara)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

CERT_URL="${CERT_URL:-https://localhost}"
IT_URL="${IT_URL:-https://localhost/it}"
OS_URL="${OS_URL:-http://localhost:9200}"
TS_URL="${TIMESKETCH_URL:-http://localhost:5000}"
# P-15 : hôte dynamique (PUBLIC_HOST / détection) — plus d'IP codée en dur
. "$ROOT/scripts/lib/host-ip.sh" 2>/dev/null || true
_fp_host="$(fp_url_identity 2>/dev/null | head -n1 || echo localhost)"
GRAFANA_URL="${GRAFANA_URL:-https://${_fp_host}/grafana}"
RUN_ID="WARA-$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${ROOT}/logs/deep-test-${RUN_ID}"
mkdir -p "$LOG_DIR"

PASS=0
FAIL=0
WARN=0

log() { echo "[deep] $*" | tee -a "$LOG_DIR/run.log"; }
ok()  { log "✓ $*"; PASS=$((PASS + 1)); }
bad() { log "✗ $*"; FAIL=$((FAIL + 1)); }
warn(){ log "⚠ $*"; WARN=$((WARN + 1)); }

upload_cert() {
  local case_id="$1" analyst="$2" priority="$3" os_type="$4" file="$5"
  local resp
  resp=$(curl -sk -X POST "$CERT_URL/api/upload" \
    -F "case_id=$case_id" \
    -F "analyst=$analyst" \
    -F "priority=$priority" \
    -F "os_type=$os_type" \
    -F "files=@$file") || true
  echo "$resp" > "$LOG_DIR/upload-${case_id}.json"
  python3 -c "
import json,sys
d=json.load(open('$LOG_DIR/upload-${case_id}.json'))
r=d.get('results',[{}])[0]
print(r.get('uploadId',''), r.get('ok'), r.get('ingest_queued'))
" 2>/dev/null
}

upload_it() {
  local case_id="$1" file="$2" os_type="${3:-linux}"
  local tok_resp tok
  tok_resp=$(curl -sk -X POST "$CERT_URL/api/tokens/generate" \
    -H "Content-Type: application/json" \
    -d "{\"case_id\":\"$case_id\",\"description\":\"Deep test IT\",\"expires_in_hours\":2,\"max_uses\":5,\"os_type\":\"$os_type\"}")
  tok=$(echo "$tok_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))")
  [ -n "$tok" ] || { echo "  token_fail"; return 1; }
  curl -sk -X POST "$IT_URL/api/upload" -H "x-it-token: $tok" \
    -F "files=@$file" -F "submitter_name=wara-it" \
    > "$LOG_DIR/upload-it-${case_id}.json"
  python3 -c "
import json,sys
d=json.load(open('$LOG_DIR/upload-it-${case_id}.json'))
r=d.get('results',[{}])[0]
print(r.get('uploadId',''), r.get('ok'), r.get('ingest_queued'))
"
}

wait_ingest() {
  local uid="$1" max="${2:-120}"
  local deadline=$((SECONDS + max))
  while [ "$SECONDS" -lt "$deadline" ]; do
    local st ts_ok
    st=$(curl -sk "$OS_URL/forensic-uploads/_doc/$uid" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('_source',{}).get('ingest_status','') if d.get('found') else '')
" 2>/dev/null || echo "")
    ts_ok=$(curl -sk "$OS_URL/forensic-uploads/_doc/$uid" | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=(d.get('_source') or {}).get('timesketch') or {}
print('1' if t.get('ok') else '0')
" 2>/dev/null || echo "0")
    [ "$st" = "failed" ] && { echo "failed"; return 1; }
    [ "$st" = "completed" ] && { echo "completed $ts_ok"; return 0; }
    sleep 5
  done
  echo "timeout"
  return 1
}

count_index() {
  curl -sk "$OS_URL/${1}*/_count" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0"
}

log "=== Génération fixtures ==="
python3 scripts/generate_test_fixtures.py | tee -a "$LOG_DIR/run.log"

log "=== Scénario 1 — Incident Windows (CERT) ==="
CASE_WIN="IR-2024-TEST-WIN-${RUN_ID}"
WIN_BEFORE=$(count_index forensic-windows)
read -r UID_WIN OK_WIN Q_WIN <<< "$(upload_cert "$CASE_WIN" "j.doe" "high" "windows" "tests/fixtures/wara-windows-events.csv")"
[ "$OK_WIN" = "True" ] && ok "S1 upload CERT Windows ($UID_WIN)" || bad "S1 upload CERT échoué"
RES=$(wait_ingest "$UID_WIN" 120 || true)
WIN_AFTER=$(count_index forensic-windows)
echo "$RES" | grep -q completed && [ "${WIN_AFTER:-0}" -gt "${WIN_BEFORE:-0}" ] && ok "S1 forensic-windows $WIN_BEFORE→$WIN_AFTER" || bad "S1 ingest Windows: $RES ($WIN_BEFORE→$WIN_AFTER)"

log "=== Scénario 2 — Incident Linux ==="
CASE_LIN="IR-2024-TEST-LIN-${RUN_ID}"
LIN_BEFORE=$(count_index forensic-linux)
read -r UID_LIN OK_LIN _ <<< "$(upload_cert "$CASE_LIN" "j.doe" "medium" "linux" "tests/fixtures/wara-linux-auth.log")"
[ "$OK_LIN" = "True" ] && ok "S2 upload Linux" || bad "S2 upload Linux"
RES=$(wait_ingest "$UID_LIN" 90 || true)
LIN_AFTER=$(count_index forensic-linux)
echo "$RES" | grep -q completed && [ "${LIN_AFTER:-0}" -gt "${LIN_BEFORE:-0}" ] && ok "S2 forensic-linux $LIN_BEFORE→$LIN_AFTER" || bad "S2 ingest Linux: $RES"

log "=== Scénario 3 — Logs Web (IT) ==="
CASE_WEB="IR-2024-TEST-WEB-${RUN_ID}"
WEB_BEFORE=$(count_index forensic-web)
read -r UID_WEB OK_WEB _ <<< "$(upload_it "$CASE_WEB" "tests/fixtures/wara-nginx-access.log" "unknown")"
[ "$OK_WEB" = "True" ] && ok "S3 upload IT web" || bad "S3 upload IT"
RES=$(wait_ingest "$UID_WEB" 90 || true)
WEB_AFTER=$(count_index forensic-web)
WEB_IDX=$(curl -sk "$OS_URL/forensic-uploads/_doc/$UID_WEB" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print((d.get('_source') or {}).get('content_indexed',{}).get('index',''))
" 2>/dev/null || echo "")
WEB_EVENTS=$(curl -sk "$OS_URL/forensic-uploads/_doc/$UID_WEB" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print((d.get('_source') or {}).get('content_indexed',{}).get('events_indexed',0))
" 2>/dev/null || echo "0")
if echo "$RES" | grep -q completed && { [ "${WEB_AFTER:-0}" -gt "${WEB_BEFORE:-0}" ] || [ "${WEB_EVENTS:-0}" -gt 0 ]; }; then
  ok "S3 forensic-web index=${WEB_IDX:-forensic-web} events=$WEB_EVENTS ($WEB_BEFORE→$WEB_AFTER)"
else
  bad "S3 ingest web: $RES idx=$WEB_IDX events=$WEB_EVENTS"
fi

log "=== Scénario 4 — Threat Intel OpenCTI ==="
IND=$(curl -sk "$CERT_URL/cti/graphql" -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary '{"query":"{ indicatorsNumber { total } stixCoreObjectsNumber { total } connectors { name active } }"}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['data']; print(d['indicatorsNumber']['total'], d['stixCoreObjectsNumber']['total'], sum(1 for c in d['connectors'] if c['active']))")
read -r IND_T STIX_T ACT_T <<< "$IND"
[ "${IND_T:-0}" -ge 40 ] && ok "S4 OpenCTI indicateurs=$IND_T" || bad "S4 indicateurs=$IND_T"
[ "${STIX_T:-0}" -ge 500 ] && ok "S4 OpenCTI STIX=$STIX_T" || bad "S4 STIX=$STIX_T"
[ "${ACT_T:-0}" -ge 6 ] && ok "S4 connecteurs actifs=$ACT_T" || warn "S4 connecteurs=$ACT_T"

log "=== Scénario 5 — MISP ==="
python3 scripts/test_misp_e2e.py 2>&1 | tee -a "$LOG_DIR/misp.log" && ok "S5 MISP event+IOC" || bad "S5 MISP"

log "=== Scénario 6 — TheHive / Cortex ==="
TH_ST=$(curl -sk -u "${THEHIVE_ADMIN_LOGIN}:${THEHIVE_ADMIN_PASSWORD}" "${THEHIVE_URL:-http://localhost:9002/thehive}/api/status" | python3 -c "import json,sys; print(json.load(sys.stdin).get('versions',{}).get('TheHive','?'))" 2>/dev/null || echo "?")
[ "$TH_ST" != "?" ] && ok "S6 TheHive status ($TH_ST)" || bad "S6 TheHive down"
CX_ST=$(curl -sk -H "Authorization: ${CORTEX_API_KEY}" "http://localhost:9003/api/status" | python3 -c "import json,sys; print(json.load(sys.stdin).get('versions',{}).get('Cortex','?'))" 2>/dev/null || echo "?")
[ "$CX_ST" != "?" ] && ok "S6 Cortex status ($CX_ST)" || bad "S6 Cortex down"
python3 scripts/test_thehive_cortex_e2e.py 2>&1 | tee -a "$LOG_DIR/thehive.log" && ok "S6 TheHive case+observable" || warn "S6 TheHive/Cortex — voir logs (RBAC / analyzers)"

log "=== Scénario 7 — Stress léger (3 fichiers CERT) ==="
CASE_STRESS="IR-STRESS-${RUN_ID}"
for i in 1 2 3; do
  upload_cert "$CASE_STRESS" "stress" "low" "windows" "tests/fixtures/wara-windows-events.csv" >/dev/null || true
done
sleep 3
STATS=$(curl -sk "$CERT_URL/api/stats")
echo "$STATS" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('uploads',0)>0" 2>/dev/null && ok "S7 stats API OK après stress" || bad "S7 stats"

log "=== Portails API ==="
UP_N=$(curl -sk "$CERT_URL/api/uploads" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
[ "${UP_N:-0}" -gt 0 ] && ok "GET /api/uploads ($UP_N entrées)" || bad "GET /api/uploads vide"
curl -sk "$CERT_URL/api/tokens" | python3 -m json.tool >/dev/null 2>&1 && ok "GET /api/tokens" || bad "GET /api/tokens"
curl -sk "$CERT_URL/api/services" | python3 -c "import json,sys; assert len(json.load(sys.stdin))>=5" 2>/dev/null && ok "GET /api/services" || bad "GET /api/services"

log "=== Timesketch explore (sketch Windows) ==="
export TS_URL TS_USER="${TIMESKETCH_USER:-admin}" TS_PASS="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}" CASE_ID="$CASE_WIN" OS_URL
python3 <<'PY' 2>&1 | tee -a "$LOG_DIR/ts-explore.log" && ok "Timesketch explore $CASE_WIN" || bad "Timesketch explore"
import os, re, sys, requests
TS=os.environ["TS_URL"]; CASE=os.environ["CASE_ID"]
s=requests.Session()
r=s.get(f"{TS}/login/",timeout=20)
m=re.search(r'csrf-token" content="([^"]+)"', r.text)
s.post(f"{TS}/login/",data={"username":os.environ["TS_USER"],"password":os.environ["TS_PASS"]},headers={"Referer":f"{TS}/login/"},timeout=25)
h={"X-CSRFToken":m.group(1),"Content-Type":"application/json","Referer":TS}
name=f"[FP] {CASE}"
sk=next(x for x in s.get(f"{TS}/api/v1/sketches/",headers=h,timeout=20).json().get("objects",[]) if x.get("name")==name)
er=s.post(f"{TS}/api/v1/sketches/{sk['id']}/explore/",json={"query_string":"*","filter":{}},headers=h,timeout=60)
assert er.status_code==200 and er.json().get("meta",{}).get("es_total_count",0)>=1
print("events", er.json()["meta"]["es_total_count"])
PY

log "=== Grafana ==="
GF=$(curl -sk "https://localhost/grafana/api/health" 2>/dev/null || curl -sk "${GRAFANA_URL}/api/health" 2>/dev/null)
echo "$GF" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get('database')=='ok' else 1)" 2>/dev/null && ok "Grafana health" || warn "Grafana health"

log "=== Scripts validation ==="
./diagnostic.sh 2>&1 | tee "$LOG_DIR/diagnostic.log" | tail -5
DIAG_FAIL=$(grep -c 'Échoués:  0' "$LOG_DIR/diagnostic.log" || true)
[ "$DIAG_FAIL" -ge 1 ] && ok "diagnostic.sh vert" || bad "diagnostic.sh KO"

./validate_all.sh 2>&1 | tee "$LOG_DIR/validate.log" | tail -8
VAL_FAIL=$(grep -E 'Échoués : 0' "$LOG_DIR/validate.log" || true)
[ -n "$VAL_FAIL" ] && ok "validate_all.sh vert" || bad "validate_all.sh KO"

log "=== RÉSUMÉ deep test ($RUN_ID) ==="
log "PASS=$PASS FAIL=$FAIL WARN=$WARN — logs: $LOG_DIR"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
