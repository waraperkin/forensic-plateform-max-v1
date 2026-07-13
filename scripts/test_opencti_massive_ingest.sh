#!/usr/bin/env bash
# Validation ingestion massive OpenCTI (700k+ ind/obs, cartes malware/vuln/reports)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

CTI_URL="${OPENCTI_GRAPHQL_URL:-https://localhost/cti/graphql}"
TOKEN="${OPENCTI_ADMIN_TOKEN:-}"
MIN_IND="${OPENCTI_TI_MASSIVE_MIN_IND:-700000}"
MIN_OBS="${OPENCTI_TI_MASSIVE_MIN_OBS:-700000}"
MIN_STIX="${OPENCTI_TI_MASSIVE_MIN_STIX:-1000000}"
MIN_MALWARE="${OPENCTI_MIN_MALWARE:-100}"
MIN_VULN="${OPENCTI_MIN_VULN:-100}"
MIN_REPORTS="${OPENCTI_MIN_REPORTS:-50}"
MIN_TI_ACTIVE="${OPENCTI_TI_MASSIVE_MIN_TI_ACTIVE:-12}"
WAIT_SEC="${OPENCTI_TI_MASSIVE_WAIT:-90}"
POPULATE="${OPENCTI_TI_MASSIVE_POPULATE:-1}"
ENTITIES="${OPENCTI_TI_POPULATE_ENTITIES:-1}"
TURBO="${OPENCTI_TI_TURBO_START:-1}"

log() { echo "[opencti-massive] $*"; }
die() { echo "[opencti-massive] ERREUR: $*" >&2; exit 1; }

[ -n "$TOKEN" ] || die "OPENCTI_ADMIN_TOKEN manquant dans .env"

read_metrics() {
  export CTI_URL TOKEN
  python3 <<'PY'
import os, requests
url = os.environ["CTI_URL"]
token = os.environ["TOKEN"]
q = """{
  indicatorsNumber { total }
  stixCyberObservablesNumber { total }
  stixCoreObjectsNumber { total }
  reportsNumber { total }
  connectors { name active }
  malwares(first:1) { pageInfo { globalCount } }
  vulnerabilities(first:1) { pageInfo { globalCount } }
}"""
r = requests.post(url, json={"query": q}, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=90)
d = r.json().get("data", {})
ind = d.get("indicatorsNumber", {}).get("total", 0)
obs = d.get("stixCyberObservablesNumber", {}).get("total", 0)
stix = d.get("stixCoreObjectsNumber", {}).get("total", 0)
rep = d.get("reportsNumber", {}).get("total", 0)
mal = d.get("malwares", {}).get("pageInfo", {}).get("globalCount", 0)
vul = d.get("vulnerabilities", {}).get("pageInfo", {}).get("globalCount", 0)
active = [c["name"] for c in d.get("connectors", []) if c.get("active")]
ti_fragments = ("URLhaus", "VXVault", "MalwareBazaar", "ThreatFox", "SSL", "AbuseIPDB",
                "AlienVault", "Shodan", "IPInfo", "CISA", "MITRE", "ATLAS", "DISARM", "Datasets", "Campaign")
ti_active = [n for n in active if any(f.lower() in n.lower() for f in ti_fragments)]
print(f"{ind}|{obs}|{stix}|{rep}|{mal}|{vul}|{len(ti_active)}|" + ",".join(ti_active[:18]))
PY
}

if [ "$TURBO" = "1" ] && [ -x "$ROOT/scripts/opencti-ti-turbo.sh" ]; then
  log "Démarrage connecteurs TI turbo..."
  bash "$ROOT/scripts/opencti-ti-turbo.sh" >/dev/null 2>&1 || true
fi

log "Attente ${WAIT_SEC}s..."
sleep "$WAIT_SEC"

BEFORE=$(read_metrics)
B_IND=$(echo "$BEFORE" | cut -d'|' -f1)
log "  avant: ind=$B_IND"

if [ "$POPULATE" = "1" ] && [ "${B_IND:-0}" -lt "$MIN_IND" ]; then
  log "Population massive indicateurs (objectif $MIN_IND)..."
  python3 "$ROOT/scripts/opencti-populate-ti-massive.py" || true
fi

if [ "$ENTITIES" = "1" ]; then
  log "Population entités dashboard (malware, vuln, reports)..."
  python3 "$ROOT/scripts/opencti-populate-entities.py" || true
fi

AFTER=$(read_metrics)
A_IND=$(echo "$AFTER" | cut -d'|' -f1)
A_OBS=$(echo "$AFTER" | cut -d'|' -f2)
A_STIX=$(echo "$AFTER" | cut -d'|' -f3)
A_REP=$(echo "$AFTER" | cut -d'|' -f4)
A_MAL=$(echo "$AFTER" | cut -d'|' -f5)
A_VUL=$(echo "$AFTER" | cut -d'|' -f6)
A_TI=$(echo "$AFTER" | cut -d'|' -f7)
A_NAMES=$(echo "$AFTER" | cut -d'|' -f8)
log "  après: ind=$A_IND obs=$A_OBS stix=$A_STIX reports=$A_REP malware=$A_MAL vuln=$A_VUL ti=$A_TI"
log "  TI: $A_NAMES"

python3 "$ROOT/scripts/opencti-sync-connector-ids.py" || die "UUID connecteurs désalignés"

export CTI_URL TOKEN
python3 <<'PY' || die "observables UI vides"
import os, requests
url = os.environ["CTI_URL"]
token = os.environ["TOKEN"]
q = """{ stixCyberObservables(search: "", types: ["Url"], first: 3) {
  edges { node { observable_value } }
} }"""
r = requests.post(url, json={"query": q}, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=60)
edges = r.json().get("data", {}).get("stixCyberObservables", {}).get("edges", [])
if not edges:
    raise SystemExit("no observables")
print(f"[opencti-massive] OK observables sample={len(edges)}")
PY

[ "${A_IND:-0}" -ge "$MIN_IND" ] || die "indicateurs=$A_IND < $MIN_IND"
[ "${A_OBS:-0}" -ge "$MIN_OBS" ] || die "observables=$A_OBS < $MIN_OBS"
[ "${A_STIX:-0}" -ge "$MIN_STIX" ] || die "stix=$A_STIX < $MIN_STIX"
[ "${A_MAL:-0}" -ge "$MIN_MALWARE" ] || die "malware=$A_MAL < $MIN_MALWARE"
[ "${A_VUL:-0}" -ge "$MIN_VULN" ] || die "vulnerabilities=$A_VUL < $MIN_VULN"
[ "${A_REP:-0}" -ge "$MIN_REPORTS" ] || die "reports=$A_REP < $MIN_REPORTS"
[ "${A_TI:-0}" -ge "$MIN_TI_ACTIVE" ] || die "connecteurs TI=$A_TI < $MIN_TI_ACTIVE"

log "✓ test_opencti_massive_ingest OK"
exit 0
