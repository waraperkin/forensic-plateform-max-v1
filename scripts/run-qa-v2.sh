#!/usr/bin/env bash
# Pipeline QA 2.0 CERT CYBERCORP — build → pytest → playwright → chaos → perf → IA → rapport HTML
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CERT_PORTAL_URL="${CERT_PORTAL_URL:-http://localhost:3000}"
export QA_BACKUP_PATH="${QA_BACKUP_PATH:-}"
export QA_FPS_MIN="${QA_FPS_MIN:-50}"
export QA_API_V2_MAX_MS="${QA_API_V2_MAX_MS:-150}"
export QA_PANEL_MAX_MS="${QA_PANEL_MAX_MS:-1200}"

REPORTS="$ROOT/tests/reports"
mkdir -p "$REPORTS" "$ROOT/tests/test-results"
chmod -R u+w "$REPORTS" "$ROOT/tests/test-results" 2>/dev/null || true

SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"
SKIP_PLAYWRIGHT="${SKIP_PLAYWRIGHT:-0}"

log() { echo "[run-qa-v2] $*"; }

# ── Backup optionnel (déjà fait manuellement si QA_BACKUP_PATH défini) ─────────
if [[ -z "$QA_BACKUP_PATH" ]] && [[ "${QA_V2_AUTO_BACKUP:-0}" == "1" ]]; then
  QA_BACKUP_PATH="/home/debian/Cybercorp-Backup-Portal-V2-Prompt2-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$QA_BACKUP_PATH"
  cp -a "$ROOT/portal-cert" "$ROOT/portal-shared" "$ROOT/tests" "$ROOT/scripts" "$ROOT/docker-compose.yml" "$QA_BACKUP_PATH/" 2>/dev/null || true
  export QA_BACKUP_PATH
  log "backup auto: $QA_BACKUP_PATH"
fi

if [[ "$SKIP_DOCKER" != "1" ]]; then
  log "docker compose build cert-portal + control-planes"
  docker compose build cert-portal cybercorp-sekoia-controlplane cybercorp-sentinelone-controlplane
  log "docker compose up -d"
  docker compose up -d cert-portal cybercorp-sekoia-controlplane cybercorp-sentinelone-controlplane
  for _ in $(seq 1 45); do
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
pip install -q -r "$ROOT/tests/requirements-test.txt" pytest-json-report 2>/dev/null \
  || pip install -q -r "$ROOT/tests/requirements-test.txt"

log "pytest — api, api_v2, regression, perf, perf_v2, chaos, ia, soc"
set +e
pytest tests/api tests/api_v2 tests/regression tests/perf tests/perf_v2 tests/chaos tests/ia tests/soc \
  --json-report --json-report-file="$REPORTS/pytest-v2-report.json" \
  -q 2>&1 | tee "$REPORTS/pytest-v2.log"
PYTEST_RC=${PIPESTATUS[0]}
set -e

PW_RC=0
if [[ "$SKIP_PLAYWRIGHT" != "1" ]]; then
  if [[ ! -d "$ROOT/tests/node_modules" ]]; then
    log "npm install playwright"
    (cd "$ROOT/tests" && npm install --no-audit --no-fund)
    (cd "$ROOT/tests" && npx playwright install chromium)
  fi
  log "playwright — ui, ui-v2, chaos, perf, perf-v2"
  chmod -R u+w "$ROOT/tests/reports" "$ROOT/tests/test-results" 2>/dev/null || true
  set +e
  PW_PROJECTS="${QA_V2_PLAYWRIGHT_PROJECTS:-ui-v2,chaos,perf-v2,ui,perf}"
  (cd "$ROOT/tests" && npx playwright test --config=playwright.config.ts --project=ui-v2 --project=chaos --project=perf-v2) 2>&1 | tee "$REPORTS/playwright-v2.log"
  PW_RC=${PIPESTATUS[0]}
  set -e
  cp -f "$REPORTS/playwright-report.json" "$REPORTS/playwright-v2-report.json" 2>/dev/null || true
else
  log "playwright ignoré (SKIP_PLAYWRIGHT=1)"
fi

python3 "$ROOT/scripts/generate-qa-v2-report.py" || true

log "Rapports V2 :"
log "  $REPORTS/qa-report-v2.html"
log "  $REPORTS/qa-report-v2.json"

if [[ "$PYTEST_RC" -ne 0 ]] || [[ "$PW_RC" -ne 0 ]]; then
  log "Échec pipeline V2 (pytest=$PYTEST_RC playwright=$PW_RC)"
  exit 1
fi
log "Pipeline QA 2.0 terminé avec succès"
exit 0
