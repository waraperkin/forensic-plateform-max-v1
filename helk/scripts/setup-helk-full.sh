#!/usr/bin/env bash
# HELK full configuration SAFE — simulateurs uniquement, pas d'ingestion live.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FM="${FM_ROOT:-$(dirname "$ROOT")}"
if [ -f "$FM/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$FM/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi
PUBLIC_HOST="${PUBLIC_HOST:-$(fp_resolve_public_host 2>/dev/null || echo "localhost")}"

step() { echo -e "\n\033[0;36m━━━ $* ━━━\033[0m"; }

start_stack() {
  step "Démarrage HELK sidecar (safe)"
  cd "$ROOT"
  docker compose -f docker-compose.helk.yml up -d helk-elasticsearch helk-kibana helk-logstash
  for i in $(seq 1 40); do
    curl -sf http://127.0.0.1:19200/_cluster/health >/dev/null 2>&1 && break
    sleep 3
  done
}

clone_sigma() {
  step "Clone Sigma (officiel)"
  if [ ! -d "$ROOT/sigma/rules" ]; then
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$ROOT/sigma" 2>/dev/null \
      || echo "Sigma clone offline — builtin rules"
  else
    echo "Sigma déjà présent"
  fi
}

lab_ingest() {
  step "Ingestion lab safe (HTTP 18080)"
  docker run --rm --network helk_net \
    -e HELK_LOGSTASH_HTTP=http://helk-logstash:8080 \
    -e LAB_SOURCES=/lab \
    -v "$ROOT/lab-sources:/lab:ro" \
    -v "$ROOT/scripts:/scripts:ro" \
    python:3.11-slim bash -c "pip -q install requests pyyaml && python3 /scripts/lab_ingest.py"
}

sigma_once() {
  step "Sigma runner (one-shot)"
  docker run --rm --network helk_net \
    -e HELK_ES_URL=http://helk-elasticsearch:9200 \
    -e SIGMA_DIR=/sigma \
    -e SIGMA_MAX_RULES=100 \
    -v "$ROOT/scripts/sigma_runner.py:/app/sigma_runner.py:ro" \
    -v "$ROOT/sigma:/sigma:ro" \
    -v "$ROOT/mitre:/mitre:ro" \
    -e MITRE_PATH=/mitre/enterprise-attack.json \
    python:3.11-slim bash -c "pip -q install requests pyyaml && python3 /app/sigma_runner.py --once"
}

import_kibana() {
  step "Import dashboards Kibana"
  bash "$ROOT/scripts/kibana-import-sidecar.sh" 2>/dev/null || true
  bash "$ROOT/scripts/kibana-import-full.sh" 2>/dev/null || true
}

start_sigma_daemon() {
  step "Sigma runner daemon"
  cd "$FM"
  docker compose up -d helk-sigma-runner 2>/dev/null || true
}

verify() {
  step "Vérification"
  curl -skf "https://${PUBLIC_HOST}/api/helk/status" | grep -qE '"ok"[[:space:]]*:[[:space:]]*true' && echo "HELK API OK"
  for idx in helk-sysmon helk-linux helk-zeek helk-windows; do
    c=$(curl -sf "http://127.0.0.1:19200/${idx}-*/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
    echo "  ${idx}-*: ${c} docs"
  done
}

MODE="${1:-all}"
case "$MODE" in
  start) start_stack ;;
  sigma) clone_sigma ;;
  ingest) lab_ingest ;;
  kibana) import_kibana ;;
  verify) verify ;;
  all)
    start_stack
    clone_sigma
    lab_ingest
    import_kibana
    start_sigma_daemon
    verify
    ;;
  *) echo "Usage: $0 [all|start|sigma|ingest|kibana|verify]" ;;
esac
