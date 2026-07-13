#!/bin/bash
# Campagne QA ULTRA-AGRESSIVE — orchestration forensic.sh + Playwright + API
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
REPORT_DIR="$ROOT/tests/reports/soc-campaign"
mkdir -p "$REPORT_DIR"
LOG="$REPORT_DIR/ultra-campaign-run.log"

export NODE_OPTIONS="${NODE_OPTIONS:---use-system-ca}"
export CERT_PORTAL_URL="https://${IP}"
export IT_PORTAL_URL="https://${IP}/it"
export SOC_BASE_URL="https://${IP}"

echo "=== Campagne QA ULTRA $(date -Iseconds) IP=$IP ===" | tee "$LOG"

echo "[1/5] Rebuild cert-portal (correctifs API/i18n)..." | tee -a "$LOG"
docker compose up -d --build cert-portal nginx 2>&1 | tee -a "$LOG"

echo "[2/5] Validation API ingest..." | tee -a "$LOG"
for ep in ingest_status ingest_volume intakes ingest_errors; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://${IP}/api/master/${ep}")
  echo "  /api/master/${ep} → HTTP $code" | tee -a "$LOG"
done

echo "[3/5] Playwright — campagne ultra-agressive..." | tee -a "$LOG"
(
  cd "$ROOT/tests"
  PLAYWRIGHT_HTML_OPEN=never npx playwright test \
    --config=playwright.config.ts \
    --project=ui \
    ui/ \
    2>&1
) | tee -a "$LOG"

echo "[4/5] UI campaign Python (OSD/Grafana/TS)..." | tee -a "$LOG"
CERT_PORTAL_URL="https://${IP}" \
OSD_NGINX_URL="https://${IP}/dashboards" \
GRAFANA_URL="https://${IP}/grafana" \
python3 "$ROOT/scripts/ui_campaign_verify.py" 2>&1 | tee -a "$LOG" || true

echo "[5/5] Rapports → $REPORT_DIR" | tee -a "$LOG"
ls -la "$REPORT_DIR"/ultra-aggressive-campaign* "$REPORT_DIR"/campaign-report.md 2>/dev/null | tee -a "$LOG"
echo "=== FIN campagne $(date -Iseconds) ===" | tee -a "$LOG"
