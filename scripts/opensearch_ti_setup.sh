#!/usr/bin/env bash
# Déploie pipeline fp-ti-match + policies enrich OpenSearch
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

OS="${OS_URL:-http://localhost:9200}"
PIPELINE_SRC="$ROOT/scripts/opensearch_pipeline_ti_match.json"
PIPELINE_DST="$ROOT/parsers/ingest-pipelines/fp-ti-match.json"

G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
NC='\033[0m'
log() { echo -e "${C}[ti-setup]${NC} $*"; }
ok()  { echo -e "  ${G}✓${NC} $*"; }
bad() { echo -e "  ${R}✗${NC} $*"; exit 1; }

mkdir -p "$(dirname "$PIPELINE_DST")"
cp -f "$PIPELINE_SRC" "$PIPELINE_DST"

log "1/4 — Ingest pipeline fp-ti-match..."
curl -sf -X PUT "$OS/_ingest/pipeline/fp-ti-match" \
  -H "Content-Type: application/json" \
  --data-binary "@$PIPELINE_SRC" >/dev/null && ok "pipeline fp-ti-match" || bad "pipeline"

log "2/4 — Template fp-events-ti-pipeline..."
curl -sf -X PUT "$OS/_index_template/fp-events-ti-pipeline" \
  -H "Content-Type: application/json" \
  --data-binary "@$ROOT/config/opensearch/index-templates/fp-events-ti-pipeline.json" \
  >/dev/null && ok "template events+TI" || bad "template"

log "3/4 — Corrélation TI (ingest-worker + opensearch_ti_enrich_logs.py)..."
ok "enrich processor non disponible — corrélation via worker Python"

log "4/4 — Template fp-ti + fp-events-ti..."
curl -sf -X PUT "$OS/_index_template/fp-ti-template" \
  -H "Content-Type: application/json" \
  --data-binary "@$ROOT/config/opensearch/index-templates/fp-ti-template.json" >/dev/null && ok "fp-ti-template"

echo -e "${G}══ TI setup OK ══${NC}"
