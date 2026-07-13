#!/usr/bin/env bash
# Répare un sketch Timesketch : réimport pipeline depuis MinIO/OpenSearch
# Usage: ./scripts/repair_timesketch_sketch.sh <sketch_id> | --wara
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
[ -f "$ROOT/.env" ] && set -a && source "$ROOT/.env" && set +a

SKETCH_ID="${1:-}"
if [ -z "$SKETCH_ID" ]; then
  echo "Usage: $0 <sketch_id> | --wara" >&2
  exit 1
fi

bash "$ROOT/scripts/timesketch-patch-explore.sh" 2>/dev/null || true

if [ "$SKETCH_ID" = "--wara" ]; then
  export TS_URL="${TIMESKETCH_URL:-http://localhost:5000}"
  ids=$(python3 -c "
import os,re,requests
from pathlib import Path
for line in Path('$ROOT/.env').read_text().splitlines():
    if '=' in line and not line.strip().startswith('#'):
        k,v=line.split('=',1); os.environ[k.strip()]=v.strip()
TS=os.environ.get('TIMESKETCH_URL','http://localhost:5000')
s=requests.Session()
r=s.get(f'{TS}/login/')
m=re.search(r'csrf-token\" content=\"([^\"]+)\"', r.text)
s.post(f'{TS}/login/',data={'username':os.environ.get('TIMESKETCH_USER','admin'),'password':os.environ.get('TIMESKETCH_PASSWORD','')},headers={'Referer':f'{TS}/login/'})
h={'X-CSRFToken':m.group(1),'Referer':TS}
for x in s.get(f'{TS}/api/v1/sketches/',headers=h).json().get('objects',[]):
    if 'WARA' in (x.get('name') or ''): print(x['id'])
")
  for sid in $ids; do
    bash "$0" "$sid" || exit 1
  done
  echo "[repair-ts] Tous les sketchs WARA OK"
  exit 0
fi

export SKETCH_ID MINIO_ENDPOINT="${MINIO_ENDPOINT:-minio:9000}"
export MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:-forensicadmin}"
export MINIO_SECRET_KEY="${MINIO_SECRET_KEY:-F0r3ns1c_MinIO_2024!}"
export TS_URL="${TIMESKETCH_URL:-http://localhost:5000}"
export OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"

docker compose build ingest-worker -q 2>/dev/null || true

docker exec -e SKETCH_ID -e TS_URL -e OS_URL \
  -e TIMESKETCH_URL="$TS_URL" -e TIMESKETCH_USER="${TIMESKETCH_USER:-admin}" \
  -e TIMESKETCH_PASSWORD="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}" \
  -e MINIO_ENDPOINT -e MINIO_ACCESS_KEY -e MINIO_SECRET_KEY \
  forensic-ingest-worker python3 <<'PY'
import os, re, sys
import requests

sys.path.insert(0, "/app")
from timesketch_pipeline import import_to_timesketch
from worker import download_object, parse_file, os_client

SKETCH_ID = int(os.environ["SKETCH_ID"])
TS = os.environ["TS_URL"].rstrip("/")
USER = os.environ.get("TIMESKETCH_USER", "admin")
PASS = os.environ.get("TIMESKETCH_PASSWORD", "")

s = requests.Session()
r = s.get(f"{TS}/login/")
m = re.search(r'csrf-token" content="([^"]+)"', r.text)
s.post(f"{TS}/login/", data={"username": USER, "password": PASS}, headers={"Referer": f"{TS}/login/"})
h = {"X-CSRFToken": m.group(1), "Referer": TS}
detail = s.get(f"{TS}/api/v1/sketches/{SKETCH_ID}/", headers=h).json()["objects"][0]
name = detail.get("name", "")
case_id = name.replace("[FP] ", "", 1).strip() if name.startswith("[FP]") else name
print(f"[repair] sketch={SKETCH_ID} case={case_id}")

client = os_client()
q = {"query": {"bool": {"should": [
    {"term": {"case_id.keyword": case_id}},
    {"term": {"case_id": case_id}},
], "minimum_should_match": 1}}, "size": 20}
hits = client.search(index="forensic-uploads", body=q).get("hits", {}).get("hits", [])
if not hits:
    sys.exit(f"aucun upload pour {case_id}")

repaired = 0
for hit in hits:
    src = hit.get("_source", {})
    bucket = src.get("bucket") or src.get("minio_bucket")
    key = src.get("key") or src.get("minio_key")
    if not bucket or not key:
        continue
    job = {
        "upload_id": hit.get("_id"),
        "case_id": src.get("case_id") or case_id,
        "filename": src.get("filename") or key.rsplit("/", 1)[-1],
        "bucket": bucket,
        "key": key,
        "os_type": src.get("os_type", "windows"),
    }
    data = download_object(bucket, key)
    events, _ = parse_file(data, job)
    result = import_to_timesketch(events, job, raw_data=data, prune_broken=True)
    print(f"[repair] {job['filename']}: {result}")
    if result.get("ok"):
        repaired += 1

if repaired == 0:
    sys.exit(1)
print(f"[repair-ts] OK sketch {SKETCH_ID} ({repaired} timeline(s))")
PY
