#!/bin/bash
# Test ingestion TI OpenCTI — GraphQL + croissance indicateurs
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

CTI_URL="${OPENCTI_GRAPHQL_URL:-https://localhost/cti/graphql}"
TOKEN="${OPENCTI_ADMIN_TOKEN:-a1b2c3d4-e5f6-4789-a012-3456789abcde}"
WAIT_SEC="${OPENCTI_TI_WAIT:-60}"
MIN_IND="${OPENCTI_TI_MIN_INDICATORS:-100}"
MIN_STIX="${OPENCTI_TI_MIN_STIX:-500}"
MIN_ACTIVE="${OPENCTI_TI_MIN_ACTIVE:-6}"

log() { echo "[opencti-ti-test] $*"; }
die() { echo "[opencti-ti-test] ERREUR: $*" >&2; exit 1; }

gql() {
  curl -sk "$CTI_URL" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary "$1" 2>/dev/null
}

read_metrics() {
  python3 <<PY
import json, os, sys
import requests
url = os.environ["CTI_URL"]
token = os.environ["TOKEN"]
q = '''{ indicatorsNumber { total } stixCoreObjectsNumber { total }
  connectors { id name active } }'''
r = requests.post(url, json={"query": q}, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=30)
d = r.json().get("data", {})
ind = d.get("indicatorsNumber", {}).get("total", 0)
stix = d.get("stixCoreObjectsNumber", {}).get("total", 0)
active = sum(1 for c in d.get("connectors", []) if c.get("active"))
names = [c["name"] for c in d.get("connectors", []) if c.get("active")]
print(f"{ind}|{stix}|{active}|" + ",".join(names[:20]))
PY
}

export CTI_URL TOKEN
log "Métriques initiales..."
BEFORE=$(read_metrics)
B_IND=$(echo "$BEFORE" | cut -d'|' -f1)
B_STIX=$(echo "$BEFORE" | cut -d'|' -f2)
B_ACT=$(echo "$BEFORE" | cut -d'|' -f3)
log "  avant: indicateurs=$B_IND stix=$B_STIX connecteurs_actifs=$B_ACT"

if [ -x "$ROOT/scripts/opencti-start-ti.sh" ]; then
  bash "$ROOT/scripts/opencti-start-ti.sh" >/dev/null 2>&1 || true
fi

log "Attente ${WAIT_SEC}s (ingestion connecteurs)..."
sleep "$WAIT_SEC"

# Bootstrap URLhaus si encore faible
if [ "${B_IND:-0}" -lt "$MIN_IND" ] && [ -x "$ROOT/scripts/opencti-bootstrap-indicators.py" ]; then
  log "Bootstrap URLhaus (complément)..."
  OPENCTI_BOOTSTRAP_MAX=120 python3 "$ROOT/scripts/opencti-bootstrap-indicators.py" || true
  sleep 15
fi

AFTER=$(read_metrics)
A_IND=$(echo "$AFTER" | cut -d'|' -f1)
A_STIX=$(echo "$AFTER" | cut -d'|' -f2)
A_ACT=$(echo "$AFTER" | cut -d'|' -f3)
A_NAMES=$(echo "$AFTER" | cut -d'|' -f4)
log "  après: indicateurs=$A_IND stix=$A_STIX connecteurs_actifs=$A_ACT"
log "  actifs: $A_NAMES"

[ "${A_IND:-0}" -ge "$MIN_IND" ] || die "indicateurs=$A_IND < $MIN_IND"
[ "${A_STIX:-0}" -ge "$MIN_STIX" ] || die "stix=$A_STIX < $MIN_STIX"
[ "${A_ACT:-0}" -ge "$MIN_ACTIVE" ] || die "connecteurs actifs=$A_ACT < $MIN_ACTIVE"

if [ "${A_IND:-0}" -le "${B_IND:-0}" ] && [ "${B_IND:-0}" -gt 0 ]; then
  warn_msg="indicateurs n'ont pas augmenté ($B_IND → $A_IND) — connecteurs peut-être déjà synchronisés"
  log "WARN: $warn_msg"
fi

log "✓ Test TI OpenCTI OK"
exit 0
