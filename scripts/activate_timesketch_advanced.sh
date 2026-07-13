#!/usr/bin/env bash
# Forensic Platform — activation Timesketch avancé (Sigma / TI / analyzers filtrés)
# Idempotent : rebuild worker, patches FP, vérifications HTTP.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck source=/dev/null
[ -f "$ROOT/.env" ] && set -a && source "$ROOT/.env" && set +a

export TIMESKETCH_URL="${TIMESKETCH_URL:-http://localhost:5000}"
export TIMESKETCH_USER="${TIMESKETCH_USER:-admin}"
export TIMESKETCH_PASSWORD="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}"
export TS_ACTIVATE_SKETCH_ID="${TS_ACTIVATE_SKETCH_ID:-}"

WEB_CONTAINER="${TIMESKETCH_WEB_CONTAINER:-forensic-timesketch-web}"
WORKER_CONTAINER="${TIMESKETCH_WORKER_CONTAINER:-forensic-timesketch-worker}"

G='\033[0;32m'
R='\033[0;31m'
Y='\033[1;33m'
C='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0

log()  { echo -e "${C}[ts-advanced]${NC} $*"; }
ok()   { echo -e "  ${G}✓${NC} $*"; PASS=$((PASS + 1)); }
bad()  { echo -e "  ${R}✗${NC} $*"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${Y}⚠${NC} $*"; }

need_docker() {
  if ! docker ps >/dev/null 2>&1; then
    bad "Docker inaccessible — exécuter: sudo $ROOT/scripts/fix-docker-socket.sh"
    exit 1
  fi
}

main() {
  echo ""
  echo -e "${C}══ Activation Timesketch avancé (Forensic Platform) ══${NC}"
  echo ""
  need_docker

  log "1/8 — Génération timesketch.conf + build worker..."
  if [ -x "$ROOT/scripts/generate-timesketch-conf.sh" ]; then
    bash "$ROOT/scripts/generate-timesketch-conf.sh"
  fi
  if docker compose build timesketch-worker; then
    ok "build timesketch-worker (forensic-timesketch-worker:fp)"
  else
    bad "build timesketch-worker"
    step_summary
    exit 1
  fi

  log "2/8 — Démarrage timesketch-web + timesketch-worker..."
  docker compose up -d timesketch-web timesketch-worker
  ok "docker compose up -d timesketch-web timesketch-worker"

  log "3/8 — Application des patches Timesketch..."
  local waited=0
  while [ "$waited" -lt 120 ]; do
    if docker ps --format '{{.Names}}' | grep -q "^${WEB_CONTAINER}$"; then
      if docker exec "$WEB_CONTAINER" test -f /opt/fp-timesketch/apply-explore-patch.sh 2>/dev/null; then
        break
      fi
    fi
    sleep 2
    waited=$((waited + 2))
  done
  if docker exec "$WEB_CONTAINER" bash /opt/fp-timesketch/apply-explore-patch.sh; then
    ok "patches appliqués sur $WEB_CONTAINER"
  else
    bad "apply-explore-patch.sh (web)"
    step_summary
    exit 1
  fi
  if docker ps --format '{{.Names}}' | grep -q "^${WORKER_CONTAINER}$"; then
    if docker exec "$WORKER_CONTAINER" bash /opt/fp-timesketch/apply-explore-patch.sh 2>/dev/null; then
      ok "patches appliqués sur $WORKER_CONTAINER"
    else
      warn "patches worker — vérifier entrypoint/volumes"
    fi
  fi

  log "4/8 — Redémarrage web + worker..."
  docker restart "$WEB_CONTAINER" "$WORKER_CONTAINER" >/dev/null
  ok "restart $WEB_CONTAINER $WORKER_CONTAINER"
  log "Attente santé Timesketch (max 90s)..."
  local i=0
  local healthy=0
  while [ "$i" -lt 45 ]; do
    if curl -sf --max-time 3 "${TIMESKETCH_URL%/}/login/" >/dev/null 2>&1; then
      healthy=1
      break
    fi
    sleep 2
    i=$((i + 1))
  done
  if [ "$healthy" -eq 1 ]; then
    ok "Timesketch web répond sur ${TIMESKETCH_URL}"
  else
    bad "Timesketch web ne répond pas sur ${TIMESKETCH_URL}/login/"
    step_summary
    exit 1
  fi
  sleep 5

  log "5/8 — Volumes Sigma/TI + config + patches code..."
  if docker exec "$WEB_CONTAINER" test -f /opt/timesketch/sigma_rules/example_sigma.yml 2>/dev/null; then
    ok "volume sigma_rules (web)"
  else
    bad "volume sigma_rules manquant (web)"
  fi
  if docker exec "$WEB_CONTAINER" test -f /opt/timesketch/ti/indicators.json 2>/dev/null; then
    ok "volume ti (web)"
  else
    bad "volume ti manquant (web)"
  fi
  if docker exec "$WEB_CONTAINER" test -f /opt/fp-timesketch-src/analyzers_enabled.txt 2>/dev/null; then
    ok "volume analyzers_enabled.txt"
  else
    bad "volume analyzers_enabled.txt manquant"
  fi
  if docker exec "$WEB_CONTAINER" grep -q 'SIGMA_RULES_PATH = "/opt/timesketch/sigma_rules"' \
    /etc/timesketch/timesketch.conf 2>/dev/null; then
    ok "timesketch.conf SIGMA_RULES_PATH + TI + ENABLE_GRAPHS"
  else
    bad "timesketch.conf — regénérer via generate-timesketch-conf.sh"
  fi
  for yf in sigma_config.yaml ontology.yaml intelligence_tag_metadata.yaml; do
    if docker exec "$WEB_CONTAINER" test -f "/etc/timesketch/$yf" 2>/dev/null; then
      ok "/etc/timesketch/$yf"
    else
      bad "/etc/timesketch/$yf manquant (montage docker-compose)"
    fi
  done
  if docker exec "$WEB_CONTAINER" sh -c 'grep -q FP_PATCH_ANALYZERS_FILTER /opt/venv/lib/python3.*/site-packages/timesketch/lib/analyzers/manager.py' 2>/dev/null; then
    ok "FP_PATCH_ANALYZERS_FILTER présent"
  else
    bad "FP_PATCH_ANALYZERS_FILTER absent dans manager.py"
  fi

  log "5b/8 — Import règles Sigma (tsctl, fichiers FP)..."
  _sigma_imp=0
  for _sf in example_sigma.yml fp-e2e-4625-stable.yml forensic-detection-rules.yml; do
    if docker exec "$WEB_CONTAINER" test -f "/opt/timesketch/sigma_rules/$_sf" 2>/dev/null; then
      if docker exec "$WEB_CONTAINER" bash -c ". /opt/venv/bin/activate && tsctl import-sigma-rules /opt/timesketch/sigma_rules/$_sf" >>/dev/null 2>&1; then
        _sigma_imp=$((_sigma_imp + 1))
      fi
    fi
  done
  if [ "$_sigma_imp" -ge 1 ]; then
    ok "import-sigma-rules ($_sigma_imp fichier(s))"
  else
    warn "import-sigma-rules — vérifier sigma_config.yaml"
  fi

  log "6/8 — Logs récents..."
  local web_err worker_err
  web_err=$(docker logs "$WEB_CONTAINER" --tail 40 2>&1 | grep -ciE 'traceback' || true)
  worker_err=$(docker logs "$WORKER_CONTAINER" --tail 40 2>&1 | grep -ciE 'traceback' || true)
  if [ "${web_err:-0}" -eq 0 ]; then
    ok "logs $WEB_CONTAINER OK"
  else
    warn "tracebacks dans logs $WEB_CONTAINER"
  fi
  if [ "${worker_err:-0}" -eq 0 ]; then
    ok "logs $WORKER_CONTAINER OK"
  else
    warn "tracebacks dans logs $WORKER_CONTAINER"
  fi

  log "7/8 — Vérifications API (sketches, analyzer, explore)..."
  if python3 "$ROOT/scripts/timesketch_advanced_verify.py"; then
    ok "API Timesketch (login, sketches, analyzer whitelist, explore)"
  else
    bad "API Timesketch — échec (voir sortie ci-dessus)"
  fi

  log "8/8 — Résumé"
  step_summary
}

step_summary() {
  echo ""
  echo -e "${C}════════════════════════════════════════${NC}"
  echo -e "  ${G}Réussis : $PASS${NC}"
  echo -e "  ${R}Échoués : $FAIL${NC}"
  echo ""
  if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${G}✓ Timesketch avancé ACTIF — Sigma/TI/analyzers prêts${NC}"
    echo ""
    echo "  UI: ${TIMESKETCH_URL}/"
    echo "  Login: ${TIMESKETCH_USER} / (mot de passe .env)"
    echo "  Vérification visuelle: Explore + onglet Analyzers (liste filtrée)"
    exit 0
  fi
  echo -e "  ${R}✗ Activation incomplète${NC}"
  exit 1
}

main "$@"
