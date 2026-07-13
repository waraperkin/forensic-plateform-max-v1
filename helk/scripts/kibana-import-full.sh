#!/usr/bin/env bash
# Import dashboards HELK full config (sidecar indices)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIBANA="${KIBANA_URL:-http://127.0.0.1:15601/helk/kibana}"
CUSTOM="$ROOT/config/kibana/dashboards"

import_one() {
  local f="$1"
  resp=$(curl -sk -X POST "${KIBANA}/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" --form "file=@${f}" 2>/dev/null || echo '{"success":false}')
  if echo "$resp" | grep -qE '"success"[[:space:]]*:[[:space:]]*true'; then
    echo "  OK $(basename "$f")"
  else
    echo "  SKIP $(basename "$f")"
  fi
}

echo "Import dashboards custom HELK full"
for f in "$CUSTOM"/*.ndjson; do
  [ -f "$f" ] && import_one "$f" || true
done
