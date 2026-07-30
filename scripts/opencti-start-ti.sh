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
# Clés réelles uniquement : placeholders installer (Fp_*) font crasher les
# import EXTERNAL (AlienVault → SIGTERM 143). AlienVault a un entrypoint idle.
_fp_ti_key_ok() {
  case "${1:-}" in
    ""|Fp_*) return 1 ;;
    *) return 0 ;;
  esac
}
TI_CONNECTORS=(connector-apt-campaign connector-alienvault)
_fp_ti_key_ok "${ALIENVAULT_API_KEY:-}" \
  || echo "[opencti-ti] WARN connector-alienvault : clé OTX absente/placeholder — idle via entrypoint"
_fp_ti_key_ok "${ABUSEIPDB_API_KEY:-}" && TI_CONNECTORS+=(connector-abuseipdb) \
  || echo "[opencti-ti] SKIP connector-abuseipdb (clé vide ou placeholder Fp_*)"
_fp_ti_key_ok "${SHODAN_API_KEY:-}" && TI_CONNECTORS+=(connector-shodan) \
  || echo "[opencti-ti] SKIP connector-shodan (clé vide ou placeholder Fp_*)"
_fp_ti_key_ok "${IPINFO_TOKEN:-}" && TI_CONNECTORS+=(connector-ipinfo) \
  || echo "[opencti-ti] SKIP connector-ipinfo (token vide ou placeholder Fp_*)"
docker compose -f docker-compose.yml -f docker-compose.opencti.yml --profile connectors-ti up -d "${TI_CONNECTORS[@]}"

echo "[opencti-ti] Containers:"
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep forensic-connector || true
