#!/bin/bash
# Démarre tous les connecteurs Threat Intelligence OpenCTI
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

echo "[opencti-ti] Sync UUID connecteurs..."
python3 "$ROOT/scripts/opencti-sync-connector-ids.py" --write 2>/dev/null || true

echo "[opencti-ti] Connecteurs sans clé API (flux publics)..."
docker compose up -d \
  connector-mitre connector-cve connector-opencti-datasets \
  connector-mitre-atlas connector-disarm \
  connector-urlhaus connector-vxvault connector-malwarebazaar \
  connector-threatfox connector-abuse-ssl \
  connector-cisa-known-exploited-vulnerabilities

echo "[opencti-ti] Connecteurs TI (profile connectors-ti, clés API .env)..."
docker compose --profile connectors-ti up -d \
  connector-alienvault \
  connector-abuseipdb \
  connector-shodan \
  connector-ipinfo \
  connector-apt-campaign

echo "[opencti-ti] Containers:"
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep forensic-connector || true
