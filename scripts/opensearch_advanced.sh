#!/usr/bin/env bash
# OpenSearch SIEM — ISM, templates, aliases, platform-logs index, métriques cluster
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

OS="${OS_URL:-http://localhost:9200}"
LOG="${OS_ADVANCED_LOG:-$ROOT/logs/opensearch_advanced.log}"
G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
NC='\033[0m'

mkdir -p "$(dirname "$LOG")"
: >"$LOG"

log() { echo -e "${C}[os-advanced]${NC} $*" | tee -a "$LOG"; }
ok()  { echo -e "  ${G}✓${NC} $*" | tee -a "$LOG"; }
bad() { echo -e "  ${R}✗${NC} $*" | tee -a "$LOG"; FAIL=1; }

FAIL=0

log "Journal : $LOG"
log "1/6 — Santé cluster OpenSearch..."
HC=$(curl -sf --max-time 10 "$OS/_cluster/health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
if [ "$HC" = "green" ] || [ "$HC" = "yellow" ]; then
  ok "cluster status=$HC"
else
  bad "cluster inaccessible ou rouge (status=$HC)"
  exit 1
fi

log "2/6 — Policies ISM (events, logs, TI)..."
for pol in fp-events-policy fp-logs-policy fp-ti-policy forensic-lifecycle; do
  f="$ROOT/config/opensearch/ism/${pol}.json"
  [ "$pol" = "forensic-lifecycle" ] && continue
  [ -f "$f" ] || continue
  # Retry robuste : la création ISM écrit dans .opendistro-ism-config, dont la
  # primaire peut être transitoirement "not in primary mode" pendant la recovery
  # des réplicas (HTTP 500). 409 = policy déjà présente → DELETE puis re-PUT.
  pol_ok=0; HTTP=000
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    HTTP=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$OS/_plugins/_ism/policies/${pol}" \
      -H "Content-Type: application/json" --data-binary "@$f")
    if [ "$HTTP" = "200" ] || [ "$HTTP" = "201" ]; then
      ok "ISM policy $pol"; pol_ok=1; break
    fi
    if [ "$HTTP" = "409" ]; then
      curl -sf -X DELETE "$OS/_plugins/_ism/policies/${pol}" >>"$LOG" 2>&1 || true
      sleep 2; continue
    fi
    # 500/503 transitoire : relancer l'allocation et patienter.
    curl -s -X POST "$OS/_cluster/reroute?retry_failed=true" >>"$LOG" 2>&1 || true
    sleep 6
  done
  [ "$pol_ok" = "1" ] || bad "ISM policy $pol HTTP $HTTP"
done
# Legacy policy (init)
curl -sf -X PUT "$OS/_plugins/_ism/policies/forensic-lifecycle" \
  -H "Content-Type: application/json" \
  -d '{"policy":{"description":"legacy rollover 90d","default_state":"hot","states":[
    {"name":"hot","actions":[{"rollover":{"min_size":"5gb","min_index_age":"1d"}}],"transitions":[{"state_name":"warm","conditions":{"min_index_age":"7d"}}]},
    {"name":"warm","actions":[{"replica_count":{"number_of_replicas":0}}],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"90d"}}]},
    {"name":"delete","actions":[{"delete":{}}],"transitions":[]}]}}' >>"$LOG" 2>&1 && ok "ISM forensic-lifecycle (legacy)" || true

log "3/6 — Index templates SIEM..."
# Enrichir forensic-ecs avec policy_id
curl -sf -X PUT "$OS/_index_template/forensic-ecs" -H "Content-Type: application/json" -d '{
  "index_patterns":["forensic-*"],
  "template":{"settings":{"number_of_shards":1,"number_of_replicas":1,"index.refresh_interval":"5s",
    "index.mapping.total_fields.limit":2000,
    "plugins.index_state_management.policy_id":"fp-events-policy"},
  "mappings":{"dynamic_templates":[{"strings_as_keyword":{"match_mapping_type":"string",
    "mapping":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"text"}}}}}],
  "properties":{"@timestamp":{"type":"date"},"datetime":{"type":"date"},
    "upload_id":{"type":"keyword"},"case_id":{"type":"keyword"},"portal":{"type":"keyword"},
    "tags":{"type":"keyword"},"tag":{"type":"keyword"},"message":{"type":"text"},
    "log":{"properties":{"level":{"type":"keyword"}}},
    "event":{"properties":{"code":{"type":"keyword"},"category":{"type":"keyword"},"action":{"type":"keyword"}}},
    "host":{"properties":{"name":{"type":"keyword"},"ip":{"type":"ip"}}},
    "source":{"properties":{"ip":{"type":"ip"}}},"destination":{"properties":{"ip":{"type":"ip"}}},
    "__ts_timeline_id":{"type":"keyword"},"__ts_sketch_id":{"type":"long"}}}},
  "priority":200}' >>"$LOG" 2>&1 && ok "template forensic-ecs (ISM + datetime)" || bad "template forensic-ecs"

for f in "$ROOT/config/opensearch/index-templates/"*.json; do
  [ -f "$f" ] || continue
  name=$(basename "$f" .json)
  if curl -sf -X PUT "$OS/_index_template/${name}" -H "Content-Type: application/json" --data-binary "@$f" >>"$LOG" 2>&1; then
    ok "template $name"
  else
    bad "template $name"
  fi
done

log "4/6 — Index platform-logs + alias..."
DAY=$(date -u +%Y.%m.%d)
PL_INDEX="fp-platform-logs-${DAY}"
if curl -sf -o /dev/null -w '%{http_code}' "$OS/$PL_INDEX" | grep -q 404; then
  curl -sf -X PUT "$OS/$PL_INDEX" -H "Content-Type: application/json" \
    -d '{"aliases":{"fp-platform-logs":{"is_write_index":true}}}' >>"$LOG" 2>&1 \
    && ok "index $PL_INDEX + alias fp-platform-logs" || bad "index platform-logs"
else
  ok "index $PL_INDEX existe"
fi

log "5/6 — Appliquer ISM aux indices forensic-* / fp-* existants..."
python3 - <<'PY' >>"$LOG" 2>&1 || true
import os, requests
OS = os.environ.get("OS_URL", "http://localhost:9200")
POLICIES = [
    ("fp-events-policy", ("forensic-windows", "forensic-linux", "forensic-web", "forensic-network",
                          "forensic-cloud", "forensic-endpoint", "forensic-macos", "forensic-firewall")),
    ("fp-logs-policy", ("forensic-uploads", "fp-platform-logs", "forensic-alerts")),
    ("fp-ti-policy", ("forensic-ti", "fp-ti")),
]
r = requests.get(f"{OS}/_cat/indices?format=json", timeout=30)
r.raise_for_status()
indices = [x["index"] for x in r.json() if not x["index"].startswith(".")]
for policy, prefixes in POLICIES:
    matched = [i for i in indices if any(i.startswith(p) for p in prefixes)]
    for idx in matched[:80]:
        try:
            requests.post(
                f"{OS}/_plugins/_ism/add/{idx}",
                json={"policy_id": policy},
                timeout=15,
            )
        except Exception:
            pass
print(f"[os-advanced] ISM attach: {len(indices)} indices scannés")
PY
ok "ISM attach indices existants"

log "6/6 — Snapshot métriques cluster → fp-platform-logs..."
python3 "$ROOT/scripts/opensearch_collect_platform_logs.py" >>"$LOG" 2>&1 && ok "collect platform logs" || bad "collect platform logs"

echo "" | tee -a "$LOG"
if [ "${FAIL:-0}" -eq 0 ]; then
  echo -e "${G}══ OpenSearch advanced : OK ══${NC}" | tee -a "$LOG"
  exit 0
fi
echo -e "${R}══ OpenSearch advanced : KO ══${NC}" | tee -a "$LOG"
exit 1
