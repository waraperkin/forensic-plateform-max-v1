#!/usr/bin/env bash
# Crée / met à jour le pipeline OpenSearch « attachment » (OpenCTI).
set -euo pipefail
OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
echo "[opensearch-attachment-pipeline] PUT ${OS_URL}/_ingest/pipeline/attachment"
curl -sS -X PUT "${OS_URL}/_ingest/pipeline/attachment" \
  -H 'Content-Type: application/json' \
  -d '{
  "description": "attachment pipeline (ingest-attachment plugin)",
  "processors": [{ "attachment": { "field": "data", "indexed_chars": -1 } }]
}' | head -c 800 || true
echo
echo "[opensearch-attachment-pipeline] OK"
