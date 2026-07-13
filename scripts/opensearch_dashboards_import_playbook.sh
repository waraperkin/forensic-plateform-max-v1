#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OSD="${OSD_URL:-http://localhost:5601/dashboards}"
NDJSON="${ROOT}/dashboards/opensearch/opensearch_playbook.ndjson"

python3 "$ROOT/scripts/build_opensearch_playbook.py"
RESP=$(curl -sk -X POST "${OSD}/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" -H "securitytenant: global" \
  --form file=@"$NDJSON")
echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print('OK', d.get('successCount',0), 'objects') if d.get('successCount',0)>0 else sys.exit(1)"
python3 "$ROOT/scripts/opensearch_restore_dashboard_refs.py"
echo "Playbook: ${OSD}/app/dashboards#/view/fp-analyst-playbook"
