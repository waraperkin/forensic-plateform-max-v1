#!/usr/bin/env bash
# Post-traitement : envoie une collecte Velociraptor vers forensic-minimal bridge.
set -euo pipefail
CASE_ID="${1:-CASE-VR-$(date +%Y%m%d)}"
ARTIFACT="${2:-Custom.Windows.Sysmon.ForensicMinimal}"
OS_TYPE="${3:-windows}"
BRIDGE="${VR_BRIDGE_URL:-http://127.0.0.1:8097}"

payload=$(cat <<EOF
{
  "case_id": "$CASE_ID",
  "artifact": "$ARTIFACT",
  "os_type": "$OS_TYPE",
  "analyst": "velociraptor",
  "events": [{"message": "Post-collection export", "@timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}]
}
EOF
)

curl -sf -X POST "$BRIDGE/export/full" \
  -H 'Content-Type: application/json' \
  -d "$payload" | python3 -m json.tool

echo "Export Velociraptor → plateforme lancé pour $CASE_ID"
