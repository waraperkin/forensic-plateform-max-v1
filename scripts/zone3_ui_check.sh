#!/usr/bin/env bash
# Vérifie que les shells UI Zone 3 ne contiennent pas "Application Not Found"
set -euo pipefail
OSD="${OSD_URL:-http://localhost:5601/dashboards}"
paths=(
  "Query Workbench|/app/opensearch-query-workbench"
  "Reporting|/app/reports-dashboards"
  "Alerting|/app/alerting#/monitors"
  "Anomaly Detection|/app/anomaly-detection-dashboards"
  "Maps|/app/maps-dashboards#/list"
  "Security Analytics|/app/opensearch_security_analytics_dashboards"
  "Search Relevance|/app/searchRelevance"
  "Machine Learning|/app/ml-commons-dashboards"
)
fails=0
for entry in "${paths[@]}"; do
  name="${entry%%|*}"
  path="${entry#*|}"
  html=$(curl -sk "${OSD}${path}" || true)
  if echo "$html" | grep -qi "Application Not Found"; then
    echo "[zone3-ui] KO $name — Application Not Found"
    fails=$((fails + 1))
  elif ! echo "$html" | grep -q "OpenSearch Dashboards"; then
    echo "[zone3-ui] KO $name — shell invalide"
    fails=$((fails + 1))
  else
    echo "[zone3-ui] OK $name shell"
  fi
done
echo "[zone3-ui] Bilan: $fails problème(s)"
exit "$fails"
