#!/usr/bin/env bash
# Configure HELK sidecar pour usage analyste : pipelines, Sigma, Kibana, simulateur lab.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FM_ROOT="${FM_ROOT:-$(dirname "$ROOT")}"
if [ -f "$FM_ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$FM_ROOT/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi
PUBLIC_HOST="${PUBLIC_HOST:-$(fp_resolve_public_host 2>/dev/null || echo "localhost")}"
SIGMA_DIR="$ROOT/sigma"

step() { echo -e "\n\033[0;36m━━━ $* ━━━\033[0m"; }

start_helk() {
  step "Démarrage HELK sidecar"
  cd "$ROOT"
  docker compose -f docker-compose.helk.yml up -d
  for i in $(seq 1 40); do
    curl -sf "http://127.0.0.1:19200/_cluster/health" >/dev/null 2>&1 && break
    sleep 3
  done
}

clone_sigma() {
  step "Repo Sigma (subset)"
  mkdir -p "$SIGMA_DIR"
  if [ ! -d "$SIGMA_DIR/rules" ]; then
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$SIGMA_DIR" 2>/dev/null \
      || echo "Sigma clone skipped (offline) — règles intégrées dans sigma_runner.py"
  else
    echo "Sigma déjà présent: $SIGMA_DIR"
  fi
}

import_kibana() {
  step "Import dashboards Kibana HELK"
  bash "$ROOT/scripts/kibana-import-sidecar.sh" || echo "Import Kibana partiel (OK en lab)"
}

simulate_lab() {
  step "Simulation ingest lab"
  docker run --rm --network helk_net \
    -e HELK_LOGSTASH_HTTP=http://helk-logstash:8080 \
    -v "$ROOT/scripts:/scripts:ro" \
    python:3.11-slim bash -c "pip -q install requests && python3 /scripts/lab-ingest-simulator.py"
}

start_sigma_runner() {
  step "Sigma runner (détections)"
  cd "$FM_ROOT"
  docker compose up -d helk-sigma-runner 2>/dev/null || {
    echo "helk-sigma-runner non défini — exécution one-shot"
    docker run --rm -d --name helk-sigma-runner --network helk_net \
      -e HELK_ES_URL=http://helk-elasticsearch:9200 \
      -e SIGMA_INTERVAL_SEC=300 \
      -v "$ROOT/scripts/sigma_runner.py:/app/sigma_runner.py:ro" \
      python:3.11-slim bash -c "pip -q install requests && python3 /app/sigma_runner.py" || true
  }
}

verify() {
  step "Vérification"
  curl -skf "https://${PUBLIC_HOST}/api/helk/status" | grep -qE '"ok"[[:space:]]*:[[:space:]]*true' && echo "HELK API OK"
  curl -skf "http://127.0.0.1:19200/helk-sysmon-*/_count" 2>/dev/null | head -c 120 || true
  echo
}

MODE="${1:-all}"
case "$MODE" in
  start) start_helk ;;
  sigma) clone_sigma; start_sigma_runner ;;
  kibana) import_kibana ;;
  simulate) simulate_lab ;;
  verify) verify ;;
  all)
    start_helk
    clone_sigma
    import_kibana
    simulate_lab
    start_sigma_runner
    verify
    ;;
  *) echo "Usage: $0 [all|start|sigma|kibana|simulate|verify]" ;;
esac
