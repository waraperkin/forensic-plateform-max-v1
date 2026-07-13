#!/usr/bin/env bash
# Mode TI Turbo : cadence max + tous les connecteurs en parallèle
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a
[ -f "$ROOT/config/opencti/ti-turbo.env" ] && set -a && source "$ROOT/config/opencti/ti-turbo.env" && set +a

echo "[ti-turbo] Sync UUID connecteurs depuis OpenCTI..."
python3 "$ROOT/scripts/opencti-sync-connector-ids.py" --write 2>/dev/null || true

echo "[ti-turbo] Démarrage parallèle de TOUS les connecteurs TI..."
docker compose up -d \
  connector-mitre connector-cve connector-opencti-datasets \
  connector-mitre-atlas connector-disarm \
  connector-urlhaus connector-vxvault connector-malwarebazaar \
  connector-threatfox connector-abuse-ssl \
  connector-cisa-known-exploited-vulnerabilities \
  2>&1 | tail -5

docker compose --profile connectors-ti up -d \
  connector-alienvault connector-abuseipdb connector-shodan \
  connector-ipinfo connector-apt-campaign \
  2>&1 | tail -5

echo "[ti-turbo] Connecteurs actifs:"
docker ps --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null | grep forensic-connector || true
