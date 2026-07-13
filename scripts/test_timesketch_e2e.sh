#!/bin/bash
# E2E Timesketch : upload EVTX/CSV → ingest-worker → sketch → explore sans Server side error
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

CERT_URL="${CERT_URL:-https://localhost}"
IT_URL="${IT_URL:-https://localhost/it}"
OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
TS_URL="${TIMESKETCH_URL:-http://localhost:5000}"
CASE_ID="${TS_E2E_CASE:-TS-E2E-$(date +%s)}"
FIXTURE="${TS_E2E_FIXTURE:-tests/fixtures/windows-security-sample.csv}"
POLL="${TS_E2E_POLL:-180}"
INTERVAL="${TS_E2E_INTERVAL:-5}"

log() { echo "[ts-e2e] $*"; }
die() { echo "[ts-e2e] ERREUR: $*" >&2; exit 1; }

[ -f "$FIXTURE" ] || die "Fixture: $FIXTURE"

log "Token IT + upload $FIXTURE (case=$CASE_ID)..."
TOKEN=$(curl -sk -X POST "$CERT_URL/api/tokens/generate" -H "Content-Type: application/json" \
  -d "{\"case_id\":\"$CASE_ID\",\"expires_in_hours\":1,\"max_uses\":3,\"os_type\":\"windows\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))")
[ -n "$TOKEN" ] || die "token IT"

UPLOAD=$(curl -sk -X POST "$IT_URL/api/upload" -H "x-it-token: $TOKEN" \
  -F "files=@$FIXTURE" -F "submitter_name=ts-e2e")
UPLOAD_ID=$(echo "$UPLOAD" | python3 -c "import json,sys; print(json.load(sys.stdin).get('results',[{}])[0].get('uploadId',''))")
[ -n "$UPLOAD_ID" ] || die "upload failed: $UPLOAD"

log "Attente ingest (max ${POLL}s) upload_id=$UPLOAD_ID..."
DEADLINE=$((SECONDS + POLL))
TS_OK=0
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  DOC=$(curl -sk "$OS_URL/forensic-uploads/_doc/$UPLOAD_ID" 2>/dev/null || true)
  STATUS=$(echo "$DOC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
src=d.get('_source') or {}
print(src.get('ingest_status','') if d.get('found') else '')
" 2>/dev/null || echo "")
  TS_OK=$(echo "$DOC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
src=d.get('_source') or {}
if not d.get('found'): print('0'); sys.exit(0)
t=src.get('timesketch') or {}
print('1' if t.get('ok') and t.get('timeline_ready') else '0')
" 2>/dev/null || echo "0")
  log "  status=$STATUS timesketch_ok=$TS_OK"
  [ "$STATUS" = "failed" ] && die "ingest failed"
  [ "$TS_OK" = "1" ] && break
  sleep "$INTERVAL"
done
[ "$TS_OK" = "1" ] || die "Timesketch ingest non OK après ${POLL}s"

log "Vérification explore API + timelines ready..."
export TS_URL TS_USER="${TIMESKETCH_USER:-admin}" TS_PASS="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}" CASE_ID OS_URL
python3 <<'PY'
import os, re, sys
import requests

TS = os.environ["TS_URL"]
USER = os.environ["TS_USER"]
PASS = os.environ["TS_PASS"]
CASE = os.environ["CASE_ID"]
OS = os.environ.get("OS_URL", "http://localhost:9200")

s = requests.Session()
r = s.get(f"{TS}/login/", timeout=20)
m = re.search(r'csrf-token" content="([^"]+)"', r.text)
s.post(f"{TS}/login/", data={"username": USER, "password": PASS}, headers={"Referer": f"{TS}/login/"}, timeout=25)
h = {"X-CSRFToken": m.group(1), "Content-Type": "application/json", "Referer": TS}

name = f"[FP] {CASE}"
sketches = s.get(f"{TS}/api/v1/sketches/", headers=h, timeout=20).json().get("objects", [])
sk = next((x for x in sketches if x.get("name") == name), None)
if not sk:
    sys.exit(f"sketch {name} introuvable")
sid = sk["id"]
detail = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()["objects"][0]
timelines = detail.get("timelines", [])
if not timelines:
    sys.exit("aucune timeline")
for tl in timelines:
    st = (tl.get("status") or [{}])[-1].get("status")
    idx = (tl.get("searchindex") or {}).get("index_name", "")
    cnt = requests.get(f"{OS}/{idx}/_count", timeout=10).json().get("count", 0) if idx else 0
    if st == "fail" or cnt == 0:
        sys.exit(f"timeline {tl.get('name')} status={st} docs={cnt}")
er = s.post(f"{TS}/api/v1/sketches/{sid}/explore/", json={"query_string": "*", "filter": {}}, headers=h, timeout=60)
if er.status_code != 200:
    sys.exit(f"explore HTTP {er.status_code}: {er.text[:300]}")
total = er.json().get("meta", {}).get("es_total_count", 0)
if total < 1:
    sys.exit(f"explore 0 events")
print(f"OK sketch={sid} timelines={len(timelines)} explore_events={total}")
PY

log "Application patch explore Timesketch (chronology UI)..."
bash "$ROOT/scripts/timesketch-patch-explore.sh" >/dev/null 2>&1 || true

log "Vérification sketch WARA Windows (si présent)..."
export TS_WARA_PATTERN="${TS_WARA_PATTERN:-IR-2024-TEST-WIN-WARA}"
python3 <<'PY'
import os, re, sys
import requests

TS = os.environ["TS_URL"]
USER = os.environ["TS_USER"]
PASS = os.environ["TS_PASS"]
OS = os.environ.get("OS_URL", "http://localhost:9200")
PAT = os.environ.get("TS_WARA_PATTERN", "IR-2024-TEST-WIN-WARA")

s = requests.Session()
r = s.get(f"{TS}/login/", timeout=20)
m = re.search(r'csrf-token" content="([^"]+)"', r.text)
s.post(f"{TS}/login/", data={"username": USER, "password": PASS}, headers={"Referer": f"{TS}/login/"}, timeout=25)
h = {"X-CSRFToken": m.group(1), "Content-Type": "application/json", "Referer": TS}
sketches = s.get(f"{TS}/api/v1/sketches/", headers=h, timeout=20).json().get("objects", [])
wara = [x for x in sketches if PAT in (x.get("name") or "")]
if not wara:
    print(f"SKIP: aucun sketch contenant {PAT!r}")
    sys.exit(0)
sk = max(wara, key=lambda x: x.get("id", 0))
sid = sk["id"]
detail = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()["objects"][0]
for tl in detail.get("timelines", []):
    st = (tl.get("status") or [{}])[-1].get("status")
    idx = (tl.get("searchindex") or {}).get("index_name", "")
    cnt = requests.get(f"{OS}/{idx}/_count", timeout=10).json().get("count", 0) if idx else 0
    if st == "fail" or cnt == 0:
        sys.exit(f"WARA timeline {tl.get('name')} status={st} docs={cnt}")
er = s.post(f"{TS}/api/v1/sketches/{sid}/explore/", json={"query_string": "*", "filter": {}}, headers=h, timeout=60)
if er.status_code != 200:
    sys.exit(f"WARA explore HTTP {er.status_code}")
total = er.json().get("meta", {}).get("es_total_count", 0)
if total < 1:
    sys.exit("WARA explore 0 events")
ui = s.get(f"{TS}/sketch/{sid}/explore/", timeout=30)
if "Server side error" in ui.text:
    sys.exit("WARA UI: Server side error")
# Payload UI (chronology + fields objet) — cause historique du bandeau rouge
chr = s.post(
    f"{TS}/api/v1/sketches/{sid}/explore/",
    json={
        "query_string": "*",
        "filter": {},
        "fields": [{"field": "datetime", "type": "datetime"}],
        "chronology": True,
        "order": "asc",
    },
    headers=h,
    timeout=60,
)
if chr.status_code != 200:
    sys.exit(f"WARA chronology explore HTTP {chr.status_code}")
print(f"OK WARA sketch={sid} name={sk.get('name')} explore_events={total}")
PY

log "✓ Timesketch E2E OK — case $CASE_ID"
exit 0
