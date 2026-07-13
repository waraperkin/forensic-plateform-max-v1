#!/usr/bin/env bash
# Pipeline QA CERT CYBERCORP — build → test → UI → rapport
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CERT_PORTAL_URL="${CERT_PORTAL_URL:-http://localhost:3000}"
export QA_BACKUP_PATH="${QA_BACKUP_PATH:-}"
REPORTS="$ROOT/tests/reports"
mkdir -p "$REPORTS"

SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"

log() { echo "[run-qa] $*"; }

if [[ "$SKIP_DOCKER" != "1" ]]; then
  log "docker compose build cert-portal cybercorp-sekoia-controlplane cybercorp-sentinelone-controlplane"
  docker compose build cert-portal cybercorp-sekoia-controlplane cybercorp-sentinelone-controlplane
  log "docker compose up -d cert-portal cybercorp-sekoia-controlplane cybercorp-sentinelone-controlplane"
  docker compose up -d cert-portal cybercorp-sekoia-controlplane cybercorp-sentinelone-controlplane
  for i in $(seq 1 40); do
    if curl -sf "$CERT_PORTAL_URL/api/health" >/dev/null 2>&1; then
      log "portail prêt"
      break
    fi
    sleep 2
  done
fi

if [[ ! -d "$ROOT/.venv-qa" ]]; then
  python3 -m venv "$ROOT/.venv-qa"
fi
# shellcheck disable=SC1091
source "$ROOT/.venv-qa/bin/activate"
pip install -q -r "$ROOT/tests/requirements-test.txt" pytest-json-report 2>/dev/null || pip install -q -r "$ROOT/tests/requirements-test.txt"

log "pytest api + regression + perf"
set +e
pytest tests/api tests/regression tests/perf \
  --json-report --json-report-file="$REPORTS/pytest-report.json" \
  -q 2>&1 | tee "$REPORTS/pytest.log"
PYTEST_RC=${PIPESTATUS[0]}
set -e

if [[ ! -d "$ROOT/tests/node_modules" ]]; then
  log "npm install (playwright)"
  (cd "$ROOT/tests" && npm install --no-audit --no-fund)
  (cd "$ROOT/tests" && npx playwright install chromium)
fi

log "playwright ui + perf"
set +e
(cd "$ROOT/tests" && npx playwright test --config=playwright.config.ts) 2>&1 | tee "$REPORTS/playwright.log"
PW_RC=${PIPESTATUS[0]}
set -e

python3 "$ROOT/scripts/generate-qa-report.py" || true

log "Rapports : $REPORTS/qa-report.{json,html}"

if [[ "$PYTEST_RC" -ne 0 ]] || [[ "$PW_RC" -ne 0 ]]; then
  log "Échec pipeline (pytest=$PYTEST_RC playwright=$PW_RC)"
  exit 1
fi
log "Pipeline QA terminé avec succès"
exit 0
