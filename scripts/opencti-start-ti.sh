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
# Ne démarrer que les connecteurs dont la clé API est renseignée : sans clé
# ils bouclent en restart (l'API externe rejette les requêtes anonymes).
TI_CONNECTORS=(connector-apt-campaign)
[ -n "${ALIENVAULT_API_KEY:-}" ] && TI_CONNECTORS+=(connector-alienvault) \
  || echo "[opencti-ti] SKIP connector-alienvault (ALIENVAULT_API_KEY vide)"
[ -n "${ABUSEIPDB_API_KEY:-}" ] && TI_CONNECTORS+=(connector-abuseipdb) \
  || echo "[opencti-ti] SKIP connector-abuseipdb (ABUSEIPDB_API_KEY vide)"
[ -n "${SHODAN_API_KEY:-}" ] && TI_CONNECTORS+=(connector-shodan) \
  || echo "[opencti-ti] SKIP connector-shodan (SHODAN_API_KEY vide)"
[ -n "${IPINFO_TOKEN:-}" ] && TI_CONNECTORS+=(connector-ipinfo) \
  || echo "[opencti-ti] SKIP connector-ipinfo (IPINFO_TOKEN vide)"
docker compose --profile connectors-ti up -d "${TI_CONNECTORS[@]}"

echo "[opencti-ti] Containers:"
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep forensic-connector || true
