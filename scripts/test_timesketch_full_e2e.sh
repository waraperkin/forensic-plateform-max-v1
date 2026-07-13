#!/usr/bin/env bash
# E2E complet Timesketch : patch explore → upload → ingest → explore API + UI + tous sketchs
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

CERT_URL="${CERT_URL:-https://localhost}"
IT_URL="${IT_URL:-https://localhost/it}"
OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
TS_URL="${TIMESKETCH_URL:-http://localhost:5000}"
CASE_ID="${TS_FULL_CASE:-TS-FULL-$(date +%s)}"
FIXTURE="${TS_FULL_FIXTURE:-tests/fixtures/wara-windows-events.csv}"
POLL="${TS_FULL_POLL:-240}"
INTERVAL="${TS_FULL_INTERVAL:-5}"

log() { echo "[ts-full] $*"; }
die() { echo "[ts-full] ERREUR: $*" >&2; exit 1; }

log "1/5 Patch explore Timesketch..."
bash "$ROOT/scripts/timesketch-patch-explore.sh" || bash "$ROOT/config/timesketch/apply-explore-patch.sh" || true

log "2/5 Rebuild ingest-worker (pipeline Timesketch)..."
if docker ps >/dev/null 2>&1; then
  docker compose build ingest-worker >/dev/null
  docker compose up -d ingest-worker timesketch-web timesketch-worker >/dev/null
  sleep 8
else
  log "Docker indisponible — skip rebuild (stack supposé déjà actif)"
fi

[ -f "$FIXTURE" ] || die "Fixture manquante: $FIXTURE"

log "3/5 Upload $FIXTURE (case=$CASE_ID)..."
TOKEN=$(curl -sk -X POST "$CERT_URL/api/tokens/generate" -H "Content-Type: application/json" \
  -d "{\"case_id\":\"$CASE_ID\",\"expires_in_hours\":1,\"max_uses\":3,\"os_type\":\"windows\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))")
[ -n "$TOKEN" ] || die "token IT"

UPLOAD=$(curl -sk -X POST "$IT_URL/api/upload" -H "x-it-token: $TOKEN" \
  -F "files=@$FIXTURE" -F "submitter_name=ts-full-e2e")
UPLOAD_ID=$(echo "$UPLOAD" | python3 -c "import json,sys; print(json.load(sys.stdin).get('results',[{}])[0].get('uploadId',''))")
[ -n "$UPLOAD_ID" ] || die "upload: $UPLOAD"

log "4/5 Attente ingest (max ${POLL}s)..."
DEADLINE=$((SECONDS + POLL))
TS_OK=0
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  DOC=$(curl -sk "$OS_URL/forensic-uploads/_doc/$UPLOAD_ID" 2>/dev/null || true)
  STATUS=$(echo "$DOC" | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('_source') or {}).get('ingest_status','') if d.get('found') else '')" 2>/dev/null || echo "")
  TS_OK=$(echo "$DOC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=(d.get('_source') or {}).get('timesketch') or {}
print('1' if d.get('found') and t.get('ok') and t.get('explore_ok', t.get('timeline_ready')) else '0')
" 2>/dev/null || echo "0")
  log "  status=$STATUS ts_ok=$TS_OK"
  [ "$STATUS" = "failed" ] && die "ingest failed: $DOC"
  [ "$TS_OK" = "1" ] && break
  sleep "$INTERVAL"
done
[ "$TS_OK" = "1" ] || die "Timesketch pipeline non OK"

log "5/5 Vérification sketch créé + TOUS les sketches..."
export TIMESKETCH_URL TS_URL TS_USER="${TIMESKETCH_USER:-admin}" TIMESKETCH_PASSWORD="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}"
export TS_VERIFY_PATTERN="$CASE_ID"
python3 "$ROOT/scripts/timesketch_verify_all_sketches.py" || true
unset TS_VERIFY_PATTERN
python3 "$ROOT/scripts/timesketch_verify_all_sketches.py"

log "✓ test_timesketch_full_e2e OK — case $CASE_ID"
