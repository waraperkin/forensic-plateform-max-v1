#!/usr/bin/env bash
# Deep test OpenSearch + OpenSearch Dashboards : cluster, templates, pipelines, aliases, search, OSD UI
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

OS="${OS_URL:-http://localhost:9200}"
OSD="${OSD_URL:-http://localhost:5601/dashboards}"
OS1="${OPENSEARCH_CONTAINER:-forensic-opensearch-1}"
OS2="${OPENSEARCH_CONTAINER2:-forensic-opensearch-2}"
OSD_C="${OSD_CONTAINER:-forensic-opensearch-dashboards}"
INIT_C="${OS_INIT_CONTAINER:-forensic-opensearch-init}"
LOG="${OS_DEEP_LOG:-$ROOT/logs/opensearch_deep_test.log}"

mkdir -p "$(dirname "$LOG")"
: >"$LOG"

G='\033[0;32m'
R='\033[0;31m'
Y='\033[1;33m'
C='\033[0;36m'
NC='\033[0m'
PASS_N=0
FAIL_N=0

log()  { echo -e "${C}[os-deep]${NC} $*" | tee -a "$LOG"; }
ok()   { echo -e "  ${G}✓${NC} $*" | tee -a "$LOG"; PASS_N=$((PASS_N + 1)); }
bad()  { echo -e "  ${R}✗${NC} $*" | tee -a "$LOG"; FAIL_N=$((FAIL_N + 1)); }
warn() { echo -e "  ${Y}⚠${NC} $*" | tee -a "$LOG"; }

log "Journal : $LOG"

log "1/5 — Conteneurs Docker OpenSearch..."
for c in "$OS1" "$OS2" "$OSD_C"; do
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$c"; then
    ok "container $c running"
  else
    bad "container $c absent — docker compose up -d opensearch-node1 opensearch-dashboards"
  fi
done

log "2/5 — Fichiers config montés (init, templates, pipelines)..."
for f in scripts/opensearch-init.sh parsers/ingest-pipelines/windows-ecs.json \
         parsers/ingest-pipelines/linux-ecs.json parsers/ingest-pipelines/web-ecs.json \
         config/opensearch/index-templates/forensic-template.json; do
  [ -f "$ROOT/$f" ] && ok "$f" || bad "$f manquant"
done
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${INIT_C}$"; then
  ok "opensearch-init container présent (one-shot)"
elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${INIT_C}$"; then
  ok "opensearch-init terminé (exit 0 attendu)"
else
  warn "opensearch-init non trouvé — lancer: docker compose up opensearch-init"
fi

log "3/5 — Pipeline attachment (OpenCTI) si absent..."
if ! curl -sf --max-time 5 "$OS/_ingest/pipeline/attachment" >/dev/null 2>&1; then
  if [ -x "$ROOT/scripts/opensearch-attachment-pipeline.sh" ]; then
    OS_URL="$OS" bash "$ROOT/scripts/opensearch-attachment-pipeline.sh" >>"$LOG" 2>&1 && ok "pipeline attachment créé" \
      || bad "opensearch-attachment-pipeline.sh"
  else
    bad "pipeline attachment absent"
  fi
else
  ok "pipeline attachment déjà présent"
fi

log "4/5 — Tests API Python (cluster, templates, aliases, OSD)..."
export OS_URL="$OS" OSD_URL="$OSD" OSD_NGINX_URL="${OSD_NGINX_URL:-https://localhost/dashboards}"
if python3 "$ROOT/scripts/opensearch_deep_test_verify.py" >>"$LOG" 2>&1; then
  ok "opensearch_deep_test_verify.py"
else
  bad "opensearch_deep_test_verify.py"
fi

log "5/6 — Simulation UI (navigateur, Nginx, headless Chrome)..."
if [ "${OS_DEEP_SKIP_UI:-0}" != "1" ]; then
  export OSD_NGINX_URL="${OSD_NGINX_URL:-https://localhost/dashboards}" OSD_URL="$OSD" OBS_UI_SCOPE=osd
  if python3 "$ROOT/scripts/observability_ui_verify.py" >>"$LOG" 2>&1; then
    ok "observability_ui_verify.py (OSD)"
  else
    bad "observability_ui_verify.py (OSD)"
  fi
else
  warn "OS_DEEP_SKIP_UI=1"
fi

log "6/6 — Logs OpenSearch (erreurs récentes)..."
for c in "$OS1" "$OS2"; do
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$c"; then
    ERR=$(docker logs "$c" --tail 60 2>&1 | grep -ciE 'fatal|OutOfMemory|ClusterBlockException|failed to parse' || true)
    if [ "${ERR:-0}" -eq 0 ]; then
      ok "logs $c sans erreur critique récente"
    else
      warn "$ERR ligne(s) critique(s) dans $c (peut être historique)"
    fi
  fi
done
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$OSD_C"; then
  ERR_OSD=$(docker logs "$OSD_C" --tail 40 2>&1 | grep -ciE 'FATAL|Error:|\[error\]' || true)
  if [ "${ERR_OSD:-0}" -le 2 ]; then
    ok "logs $OSD_C OK"
  else
    warn "logs $OSD_C: $ERR_OSD ligne(s) error"
  fi
fi

echo "" | tee -a "$LOG"
if [ "$FAIL_N" -eq 0 ]; then
  echo -e "${G}══ OpenSearch deep test : OK ($PASS_N checks) ══${NC}" | tee -a "$LOG"
  exit 0
fi
echo -e "${R}══ OpenSearch deep test : KO ($FAIL_N échec(s), $PASS_N OK) ══${NC}" | tee -a "$LOG"
exit 1
