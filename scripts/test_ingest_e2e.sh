#!/bin/bash
# Test E2E : upload IT → MinIO → ingest-worker → forensic-windows-* + Timesketch
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

[ -f .env ] && set -a && source .env && set +a

CERT_URL="${CERT_URL:-https://localhost}"
IT_URL="${IT_URL:-https://localhost/it}"
OS_URL="${OS_URL:-http://localhost:9200}"
TS_URL="${TS_URL:-http://localhost:5000}"
CASE_ID="${E2E_CASE_ID:-E2E-INGEST-$(date +%s)}"
FIXTURE="${E2E_FIXTURE:-tests/fixtures/windows-security-sample.csv}"
POLL_SEC="${E2E_POLL_SEC:-120}"
INTERVAL="${E2E_POLL_INTERVAL:-5}"

log() { echo "[e2e] $*"; }
die() { echo "[e2e] ERREUR: $*" >&2; exit 1; }

command -v curl >/dev/null || die "curl requis"
command -v python3 >/dev/null || die "python3 requis"
[ -f "$FIXTURE" ] || die "Fixture introuvable: $FIXTURE"

log "Compteur forensic-windows avant test..."
WIN_BEFORE=$(curl -sk "$OS_URL/forensic-windows*/_count" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")

log "Génération token IT (case=$CASE_ID, os_type=windows)..."
TOKEN_RESP=$(curl -sk -X POST "$CERT_URL/api/tokens/generate" \
  -H "Content-Type: application/json" \
  -d "{\"case_id\":\"$CASE_ID\",\"description\":\"E2E ingest test\",\"expires_in_hours\":1,\"max_uses\":5,\"os_type\":\"windows\",\"analyst\":\"e2e-bot\"}" 2>/dev/null) || true
TOKEN=$(echo "$TOKEN_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null || echo "")
[ -n "$TOKEN" ] || die "Impossible de générer un token IT: $TOKEN_RESP"

log "Upload fixture via portail IT..."
UPLOAD_RESP=$(curl -sk -X POST "$IT_URL/api/upload" \
  -H "x-it-token: $TOKEN" \
  -F "files=@${FIXTURE}" \
  -F "submitter_name=e2e-bot" \
  -F "notes=automated e2e test" 2>/dev/null) || true
echo "$UPLOAD_RESP" | python3 -m json.tool 2>/dev/null || echo "$UPLOAD_RESP"

QUEUED=$(echo "$UPLOAD_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
r=d.get('results',[{}])[0]
print('1' if r.get('ingest_queued') else '0')
" 2>/dev/null || echo "0")
[ "$QUEUED" = "1" ] || die "ingest_queued=false — vérifier Redis et ingest-worker"

log "Attente indexation (max ${POLL_SEC}s)..."
DEADLINE=$((SECONDS + POLL_SEC))
WIN_AFTER="$WIN_BEFORE"
INGEST_OK=0
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  WIN_AFTER=$(curl -sk "$OS_URL/forensic-windows*/_count" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
  if [ "${WIN_AFTER:-0}" -gt "${WIN_BEFORE:-0}" ]; then
    INGEST_OK=1
    break
  fi
  # Vérifier statut upload dans forensic-uploads
  UPLOAD_ID=$(echo "$UPLOAD_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('results',[{}])[0].get('uploadId',''))" 2>/dev/null || echo "")
  if [ -n "$UPLOAD_ID" ]; then
    STATUS=$(curl -sk "$OS_URL/forensic-uploads/_doc/$UPLOAD_ID" 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('_source',{}).get('ingest_status',''))
" 2>/dev/null || echo "")
    log "  ingest_status=$STATUS events_windows=$WIN_AFTER"
    [ "$STATUS" = "failed" ] && die "Worker a échoué pour upload $UPLOAD_ID"
    if [ "$STATUS" = "completed" ]; then
      TS_OK=$(curl -sk "$OS_URL/forensic-uploads/_doc/$UPLOAD_ID" 2>/dev/null | python3 -c "import json,sys; print('1' if json.load(sys.stdin).get('_source',{}).get('timesketch',{}).get('ok') else '0')" 2>/dev/null || echo "0")
      WIN_AFTER=$(curl -sk "$OS_URL/forensic-windows*/_count" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
      [ "${WIN_AFTER:-0}" -gt "${WIN_BEFORE:-0}" ] && [ "$TS_OK" = "1" ] && INGEST_OK=1 && break
    fi
  fi
  sleep "$INTERVAL"
done

[ "$INGEST_OK" = "1" ] || die "forensic-windows* inchangé ($WIN_BEFORE → $WIN_AFTER) après ${POLL_SEC}s"

log "Vérification Timesketch (sketch [FP] $CASE_ID)..."
TS_USER="${TIMESKETCH_USER:-admin}"
TS_PASS="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}"
SKETCH_OK=$(python3 <<PY
import re, sys
import requests

ts_url = "${TS_URL}"
user, password = "${TS_USER}", "${TS_PASS}"
case_id = "${CASE_ID}"
sketch_name = f"[FP] {case_id}"

s = requests.Session()
r = s.get(f"{ts_url}/login/", timeout=15)
m = re.search(r'csrf-token" content="([^"]+)"', r.text) or re.search(r'name="csrf_token"[^>]*value="([^"]+)"', r.text)
if not m:
    print("0")
    sys.exit(0)
csrf = m.group(1)
lr = s.post(f"{ts_url}/login/", data={"username": user, "password": password},
           headers={"Referer": f"{ts_url}/login/"}, timeout=20, allow_redirects=True)
api = s.get(f"{ts_url}/api/v1/sketches/", timeout=15)
if api.status_code >= 300:
    print("0")
    sys.exit(0)
sketches = api.json().get("objects", [])
found = any(sk.get("name") == sketch_name for sk in sketches)
print("1" if found else "0")
PY
)
[ "$SKETCH_OK" = "1" ] || die "Sketch Timesketch '$CASE_ID' introuvable"

log "✓ E2E OK — forensic-windows: $WIN_BEFORE → $WIN_AFTER, Timesketch sketch présent"
exit 0
