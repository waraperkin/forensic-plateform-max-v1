#!/usr/bin/env bash
# Test TI OpenCTI profond : volumes indicateurs + observables + connecteurs actifs
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

CTI_URL="${OPENCTI_GRAPHQL_URL:-https://localhost/cti/graphql}"
TOKEN="${OPENCTI_ADMIN_TOKEN:-a1b2c3d4-e5f6-4789-a012-3456789abcde}"
MIN_IND="${OPENCTI_TI_DEEP_MIN_IND:-5000}"
MIN_OBS="${OPENCTI_TI_DEEP_MIN_OBS:-5000}"
MIN_ACTIVE="${OPENCTI_TI_DEEP_MIN_ACTIVE:-5}"
WAIT_SEC="${OPENCTI_TI_DEEP_WAIT:-120}"
POPULATE="${OPENCTI_TI_DEEP_POPULATE:-1}"

log() { echo "[opencti-deep-test] $*"; }
die() { echo "[opencti-deep-test] ERREUR: $*" >&2; exit 1; }

read_metrics() {
  python3 <<PY
import json, os, requests
url = os.environ["CTI_URL"]
token = os.environ["TOKEN"]
q = """{
  indicatorsNumber { total }
  stixCyberObservablesNumber { total }
  stixCoreObjectsNumber { total }
  connectors { name active }
}"""
r = requests.post(url, json={"query": q}, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=60)
d = r.json().get("data", {})
ind = d.get("indicatorsNumber", {}).get("total", 0)
obs = d.get("stixCyberObservablesNumber", {}).get("total", 0)
stix = d.get("stixCoreObjectsNumber", {}).get("total", 0)
active = [c["name"] for c in d.get("connectors", []) if c.get("active")]
ti_names = ("URLhaus", "VXVault", "Shodan", "AbuseIPDB", "AlienVault", "IPInfo", "MalwareBazaar", "CISA")
ti_active = [n for n in active if any(t in n for t in ti_names)]
print(f"{ind}|{obs}|{stix}|{len(active)}|{len(ti_active)}|" + ",".join(ti_active[:15]))
PY
}

export CTI_URL TOKEN
log "Démarrage connecteurs TI..."
bash "$ROOT/scripts/opencti-start-ti.sh" >/dev/null 2>&1 || true
log "Attente ${WAIT_SEC}s..."
sleep "$WAIT_SEC"

BEFORE=$(read_metrics)
B_IND=$(echo "$BEFORE" | cut -d'|' -f1)
B_OBS=$(echo "$BEFORE" | cut -d'|' -f2)
log "  avant: ind=$B_IND obs=$B_OBS"

if [ "$POPULATE" = "1" ] && { [ "${B_IND:-0}" -lt "$MIN_IND" ] || [ "${B_OBS:-0}" -lt "$MIN_OBS" ]; }; then
  log "Population deep (scripts/opencti-populate-ti-deep.py)..."
  python3 "$ROOT/scripts/opencti-populate-ti-deep.py" || true
fi

AFTER=$(read_metrics)
A_IND=$(echo "$AFTER" | cut -d'|' -f1)
A_OBS=$(echo "$AFTER" | cut -d'|' -f2)
A_STIX=$(echo "$AFTER" | cut -d'|' -f3)
A_ACT=$(echo "$AFTER" | cut -d'|' -f4)
A_TI=$(echo "$AFTER" | cut -d'|' -f5)
A_NAMES=$(echo "$AFTER" | cut -d'|' -f6)
log "  après: ind=$A_IND obs=$A_OBS stix=$A_STIX connecteurs_actifs=$A_ACT ti_actifs=$A_TI"
log "  TI: $A_NAMES"

# Vérifier qu'au moins un observable Url est listable
python3 <<PY || die "liste observables vide"
import os, requests
url = os.environ["CTI_URL"]
token = os.environ["TOKEN"]
q = """{ stixCyberObservables(search: "", types: ["Url"], first: 5) {
  edges { node { id entity_type observable_value } }
} }"""
r = requests.post(url, json={"query": q}, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=60)
edges = r.json().get("data", {}).get("stixCyberObservables", {}).get("edges", [])
if not edges:
    raise SystemExit("no observables in UI query")
print(f"[opencti-deep-test] OK observables list sample={len(edges)}")
PY

[ "${A_IND:-0}" -ge "$MIN_IND" ] || die "indicateurs=$A_IND < $MIN_IND"
[ "${A_OBS:-0}" -ge "$MIN_OBS" ] || die "observables=$A_OBS < $MIN_OBS"
[ "${A_TI:-0}" -ge "$MIN_ACTIVE" ] || die "connecteurs TI actifs=$A_TI < $MIN_ACTIVE"

log "✓ Test TI deep OK"
exit 0
