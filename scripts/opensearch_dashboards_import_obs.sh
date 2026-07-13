#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 "$ROOT/scripts/build_opensearch_observability.py"
NDJSON="$ROOT/dashboards/opensearch/fp_observability_saved_objects.ndjson"
IMPORT_BASE="${OSD_NGINX_URL:-https://localhost/dashboards}"
for base in "${OSD_URL:-http://localhost:5601/dashboards}" "$IMPORT_BASE"; do
  if curl -sk -o /dev/null -w '%{http_code}' "${base}/api/status" | grep -q 200; then
    IMPORT_BASE="$base"
    break
  fi
done
curl -sk -X POST "${IMPORT_BASE}/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  -H "securitytenant: global" \
  --form file=@"$NDJSON"
echo ""
echo "Observability dashboard: ${IMPORT_BASE}/app/dashboards#/view/fp-observability-pipeline"
