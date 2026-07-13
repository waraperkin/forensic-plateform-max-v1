#!/usr/bin/env bash
# ZONE 4 — shells Management (pas Application Not Found dans HTML initial)
set -euo pipefail
OSD="${OSD_URL:-http://localhost:5601/dashboards}"
paths=(
  "Overview|/app/opensearch_management_overview"
  "Index Management|/app/opensearch_index_management_dashboards"
  "Snapshot Management|/app/opensearch_snapshot_management_dashboards"
  "Integrations|/app/integrations"
  "Dashboards Management|/app/management"
  "Data sources|/app/datasources"
  "Notifications|/app/notifications-dashboards"
  "Dev Tools|/app/dev_tools"
)
fails=0
for entry in "${paths[@]}"; do
  name="${entry%%|*}"
  path="${entry#*|}"
  html=$(curl -sk "${OSD}${path}" || true)
  if echo "$html" | grep -qi "Application Not Found"; then
    echo "[zone4-ui] KO $name — Application Not Found"
    fails=$((fails + 1))
  elif ! echo "$html" | grep -q "OpenSearch Dashboards"; then
    echo "[zone4-ui] KO $name — shell invalide"
    fails=$((fails + 1))
  else
    echo "[zone4-ui] OK $name shell"
  fi
done
echo "[zone4-ui] Bilan: $fails problème(s)"
exit "$fails"
