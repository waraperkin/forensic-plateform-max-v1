#!/usr/bin/env bash
# Importe dashboards Kibana HELK upstream vers le sidecar.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OBJECTS="$ROOT/docker/helk-kibana/objects"
KIBANA="${KIBANA_URL:-http://127.0.0.1:15601/helk/kibana}"

import_one() {
  local f="$1"
  local name
  name=$(basename "$f")
  resp=$(curl -sk -X POST "${KIBANA}/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form "file=@${f}" 2>/dev/null || echo '{"success":false}')
  if echo "$resp" | grep -q '"success":true'; then
    echo "  OK $name"
    return 0
  fi
  echo "  SKIP $name"
  return 1
}

echo "Import Kibana depuis $OBJECTS"
for dash in \
  "$OBJECTS/dashboard/Global_Dashboard__HELK.ndjson" \
  "$OBJECTS/dashboard/Sysmon_Dashboard__HELK.ndjson" \
  "$OBJECTS/dashboard/ALL_MITRE_ATTACK__HELK.ndjson" \
  "$OBJECTS/index-pattern/logs_endpoint_winevent_sysmon.ndjson" \
  "$OBJECTS/index-pattern/mitre_attack.ndjson"; do
  [ -f "$dash" ] && import_one "$dash" || true
done

# Index patterns sidecar
TMP=$(mktemp -d)
cat > "$TMP/helk-sidecar-patterns.ndjson" <<'NDJSON'
{"attributes":{"title":"helk-sysmon-*","timeFieldName":"@timestamp"},"id":"helk-sysmon-pattern","type":"index-pattern","references":[],"migrationVersion":{"index-pattern":"7.10.0"},"coreMigrationVersion":"7.17.16","updated_at":"2026-06-09T00:00:00.000Z","version":"WzEsMV0="}
{"attributes":{"title":"helk-linux-*","timeFieldName":"@timestamp"},"id":"helk-linux-pattern","type":"index-pattern","references":[],"migrationVersion":{"index-pattern":"7.10.0"},"coreMigrationVersion":"7.17.16","updated_at":"2026-06-09T00:00:00.000Z","version":"WzEsMV0="}
{"attributes":{"title":"helk-detections-*","timeFieldName":"@timestamp"},"id":"helk-detections-pattern","type":"index-pattern","references":[],"migrationVersion":{"index-pattern":"7.10.0"},"coreMigrationVersion":"7.17.16","updated_at":"2026-06-09T00:00:00.000Z","version":"WzEsMV0="}
NDJSON
import_one "$TMP/helk-sidecar-patterns.ndjson"
rm -rf "$TMP"
echo "Import terminé"
