#!/usr/bin/env bash
# POINT 3 — E2E Timesketch avancé : activation → ingest → analyzers → vérification API
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f "$ROOT/.env" ] && set -a && source "$ROOT/.env" && set +a

CERT_URL="${CERT_URL:-https://localhost}"
IT_URL="${IT_URL:-https://localhost/it}"
OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
TS_URL="${TIMESKETCH_URL:-http://localhost:5000}"
CASE_ID="${TS_ADV_E2E_CASE:-TS-ADV-E2E-$(date +%s)}"
FIXTURE="${TS_ADV_E2E_FIXTURE:-tests/fixtures/timesketch-advanced-e2e.csv}"
POLL="${TS_ADV_E2E_POLL:-300}"
INTERVAL="${TS_ADV_E2E_INTERVAL:-5}"
ANALYZER_WAIT="${TS_ADV_E2E_ANALYZER_WAIT:-180}"
SKIP_ACTIVATE="${TS_E2E_SKIP_ACTIVATE:-0}"
LOG_DIR="${TS_ADV_E2E_LOG_DIR:-$ROOT/logs}"
mkdir -p "$LOG_DIR"
E2E_LOG="$LOG_DIR/timesketch_advanced_e2e.log"

G='\033[0;32m'
R='\033[0;31m'
Y='\033[1;33m'
C='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${C}[ts-adv-e2e]${NC} $*" | tee -a "$E2E_LOG"; }
ok()   { echo -e "  ${G}✓${NC} $*" | tee -a "$E2E_LOG"; }
bad()  { echo -e "  ${R}✗${NC} $*" | tee -a "$E2E_LOG"; }
warn() { echo -e "  ${Y}⚠${NC} $*" | tee -a "$E2E_LOG"; }
die()  { bad "$*"; exit 1; }

: >"$E2E_LOG"
log "Journal : $E2E_LOG"

import_sigma_rules() {
  local web="${TIMESKETCH_WEB_CONTAINER:-forensic-timesketch-web}"
  local f ok_count=0 fail_count=0
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${web}$"; then
    warn "conteneur $web absent — import Sigma ignoré"
    return 0
  fi
  for f in example_sigma.yml fp-e2e-4625-stable.yml forensic-detection-rules.yml; do
    if docker exec "$web" test -f "/opt/timesketch/sigma_rules/$f" 2>/dev/null; then
      if docker exec "$web" bash -c ". /opt/venv/bin/activate && tsctl import-sigma-rules /opt/timesketch/sigma_rules/$f" >>"$E2E_LOG" 2>&1; then
        ok_count=$((ok_count + 1))
      else
        fail_count=$((fail_count + 1))
        warn "import sigma $f échoué"
      fi
    fi
  done
  if [ "$ok_count" -ge 1 ]; then
    ok "import règles Sigma ($ok_count fichier(s))"
  else
    warn "aucun import Sigma réussi"
  fi
}

if [ "$SKIP_ACTIVATE" != "1" ]; then
  log "1/7 — Activation Timesketch avancé (Sigma/TI/patches)..."
  if bash "$ROOT/scripts/activate_timesketch_advanced.sh" >>"$E2E_LOG" 2>&1; then
    ok "activate_timesketch_advanced.sh"
    import_sigma_rules
  else
    die "activation Timesketch avancé échouée"
  fi
else
  warn "TS_E2E_SKIP_ACTIVATE=1 — activation ignorée"
  import_sigma_rules
fi

[ -f "$FIXTURE" ] || die "Fixture manquante: $FIXTURE"

log "2/7 — Rebuild ingest-worker (CSV structuré prioritaire)..."
if docker ps >/dev/null 2>&1; then
  docker compose build ingest-worker >>"$E2E_LOG" 2>&1 || warn "build ingest-worker ignoré"
  docker compose up -d ingest-worker >>"$E2E_LOG" 2>&1 || true
  sleep 5
else
  warn "Docker indisponible — ingest-worker non reconstruit"
fi

log "3/7 — Upload IT $FIXTURE (case=$CASE_ID)..."
TOKEN=$(curl -sk -X POST "$CERT_URL/api/tokens/generate" -H "Content-Type: application/json" \
  -d "{\"case_id\":\"$CASE_ID\",\"expires_in_hours\":1,\"max_uses\":5,\"os_type\":\"windows\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))")
[ -n "$TOKEN" ] || die "token IT introuvable"

UPLOAD=$(curl -sk -X POST "$IT_URL/api/upload" -H "x-it-token: $TOKEN" \
  -F "files=@$FIXTURE" -F "submitter_name=timesketch-advanced-e2e")
UPLOAD_ID=$(echo "$UPLOAD" | python3 -c "import json,sys; print(json.load(sys.stdin).get('results',[{}])[0].get('uploadId',''))")
[ -n "$UPLOAD_ID" ] || die "upload échoué: $UPLOAD"
ok "upload_id=$UPLOAD_ID"

log "4/7 — Attente ingest OpenSearch + Timesketch (max ${POLL}s)..."
DEADLINE=$((SECONDS + POLL))
TS_OK=0
SKETCH_ID=""
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  DOC=$(curl -sk "$OS_URL/forensic-uploads/_doc/$UPLOAD_ID" 2>/dev/null || true)
  STATUS=$(echo "$DOC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print((d.get('_source') or {}).get('ingest_status','') if d.get('found') else '')
" 2>/dev/null || echo "")
  TS_OK=$(echo "$DOC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
t=(d.get('_source') or {}).get('timesketch') or {}
print('1' if d.get('found') and t.get('ok') and t.get('timeline_ready') else '0')
" 2>/dev/null || echo "0")
  SKETCH_ID=$(echo "$DOC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print((d.get('_source') or {}).get('timesketch',{}).get('sketch_id','') or '')
" 2>/dev/null || echo "")
  log "  ingest_status=$STATUS ts_ok=$TS_OK sketch_id=${SKETCH_ID:-?}"
  [ "$STATUS" = "failed" ] && die "ingest failed: $DOC"
  [ "$TS_OK" = "1" ] && break
  sleep "$INTERVAL"
done
[ "$TS_OK" = "1" ] || die "pipeline Timesketch non OK après ${POLL}s"

log "5/7 — Lancement analyzers (sigma, domain, feature_extraction, misp_analyzer)..."
export TIMESKETCH_URL="$TS_URL"
export TIMESKETCH_USER="${TIMESKETCH_USER:-admin}"
export TIMESKETCH_PASSWORD="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}"
export TS_ADV_E2E_CASE_ID="$CASE_ID"
export TS_ADV_E2E_SKETCH_ID="${SKETCH_ID:-}"
export TS_ADV_E2E_ANALYZER_WAIT="$ANALYZER_WAIT"

python3 "$ROOT/scripts/timesketch_advanced_e2e_run_analyzers.py" 2>&1 | tee -a "$E2E_LOG" || die "lancement analyzers échoué"

log "6/7 — Vérification API (Sigma/TI/domain/features/explore)..."
export TS_VERIFY_CASE_ID="$CASE_ID"
export TS_VERIFY_SKETCH_ID="${SKETCH_ID:-}"
if python3 "$ROOT/scripts/timesketch_advanced_e2e_verify.py" 2>&1 | tee -a "$E2E_LOG"; then
  ok "timesketch_advanced_e2e_verify.py"
  VERIFY_RC=0
else
  bad "timesketch_advanced_e2e_verify.py"
  VERIFY_RC=1
fi

log "7/7 — Logs Docker (extrait)..."
if docker ps >/dev/null 2>&1; then
  for c in forensic-timesketch-web forensic-timesketch-worker forensic-ingest-worker; do
    if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
      echo "--- $c (dernières lignes) ---" >>"$E2E_LOG"
      docker logs "$c" --tail 25 >>"$E2E_LOG" 2>&1 || true
    fi
  done
fi

SKETCH_URL_FILE="$LOG_DIR/timesketch_advanced_e2e_sketch.url"
python3 -c "
import os
sid=os.environ.get('TS_VERIFY_SKETCH_ID','').strip()
case=os.environ.get('TS_VERIFY_CASE_ID','')
url=os.environ.get('TIMESKETCH_URL','http://localhost:5000').rstrip('/')
if not sid:
    import re, requests
    s=requests.Session()
    TS=url
    r=s.get(f'{TS}/login/',timeout=20)
    m=re.search(r'csrf-token\" content=\"([^\"]+)\"', r.text)
    s.post(f'{TS}/login/',data={'username':os.environ.get('TIMESKETCH_USER','admin'),'password':os.environ.get('TIMESKETCH_PASSWORD','')},headers={'Referer':f'{TS}/login/'},timeout=25)
    h={'X-CSRFToken':m.group(1),'Referer':TS}
    name=f'[FP] {case}'
    for sk in s.get(f'{TS}/api/v1/sketches/',headers=h,timeout=20).json().get('objects',[]):
        if sk.get('name')==name:
            sid=str(sk['id']); break
if sid:
    open('$SKETCH_URL_FILE','w').write(f'{url}/sketch/{sid}/explore/')
    print(sid)
" 2>/dev/null | while read -r sid_out; do
  export TS_VERIFY_SKETCH_ID="$sid_out"
done

if [ -f "$SKETCH_URL_FILE" ]; then
  SKETCH_URL=$(cat "$SKETCH_URL_FILE")
  ok "UI sketch : $SKETCH_URL"
  echo "$SKETCH_URL"
else
  warn "URL sketch non écrite — ouvrir Timesketch et chercher [FP] $CASE_ID"
fi

echo ""
if [ "${VERIFY_RC:-1}" -eq 0 ]; then
  echo -e "${G}══ Résultat E2E Timesketch avancé : OK ══${NC}"
  exit 0
fi
echo -e "${R}══ Résultat E2E Timesketch avancé : KO ══${NC}"
exit 1
