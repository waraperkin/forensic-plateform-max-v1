#!/bin/bash
# Répare Timesketch : supprime timelines en échec / vides, ré-enfile l'ingestion depuis forensic-uploads
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f .env ] && set -a && source .env && set +a

TS_URL="${TIMESKETCH_URL:-http://localhost:5000}"
TS_USER="${TIMESKETCH_USER:-admin}"
TS_PASS="${TIMESKETCH_PASSWORD:-F0r3ns1c_TS_2024!}"
OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
REDIS_URL="${REDIS_URL:-redis://:${REDIS_PASSWORD:-F0r3ns1c_Redis_2024!}@localhost:6379}"
QUEUE_KEY="${INGEST_QUEUE_KEY:-fp:ingest:queue}"

echo "[repair-ts] 1/3 — Suppression timelines fail / index vide..."
export TS_URL TS_USER TS_PASS OS_URL
python3 <<'PY'
import json, re, sys
import requests

TS_URL = __import__("os").environ["TS_URL"]
TS_USER = __import__("os").environ["TS_USER"]
TS_PASS = __import__("os").environ["TS_PASS"]
OS_URL = __import__("os").environ["OS_URL"]

s = requests.Session()
r = s.get(f"{TS_URL}/login/", timeout=20)
m = re.search(r'csrf-token" content="([^"]+)"', r.text)
if not m:
    sys.exit("CSRF introuvable")
csrf = m.group(1)
s.post(f"{TS_URL}/login/", data={"username": TS_USER, "password": TS_PASS},
       headers={"Referer": f"{TS_URL}/login/"}, timeout=25)
h = {"X-CSRFToken": csrf, "Referer": TS_URL}

deleted = 0
for sk in s.get(f"{TS_URL}/api/v1/sketches/", headers=h, timeout=20).json().get("objects", []):
    sid = sk["id"]
    detail = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=20).json().get("objects", [{}])[0]
    for tl in detail.get("timelines", []):
        tid = tl.get("id")
        idx = (tl.get("searchindex") or {}).get("index_name", "")
        st = (tl.get("status") or [{}])[-1].get("status", "")
        cnt = 0
        if idx:
            try:
                cnt = requests.get(f"{OS_URL}/{idx}/_count", timeout=10).json().get("count", 0)
            except Exception:
                cnt = 0
        if st == "fail" or (st != "ready" and cnt == 0) or (st == "ready" and cnt == 0):
            print(f"  DELETE sketch={sid} timeline={tid} name={tl.get('name')} status={st} docs={cnt}")
            s.delete(f"{TS_URL}/api/v1/sketches/{sid}/timelines/{tid}/", headers=h, timeout=60)
            deleted += 1
print(f"[repair-ts] {deleted} timeline(s) supprimée(s)")
PY

echo "[repair-ts] 2/3 — Ré-enfile uploads avec Timesketch KO ou sans events..."
export OS_URL QUEUE_KEY REDIS_PASSWORD
python3 <<'PY'
import json, os, subprocess
import urllib.request

OS = os.environ.get("OS_URL", "http://localhost:9200")
q = os.environ.get("QUEUE_KEY", "fp:ingest:queue")
rpw = os.environ.get("REDIS_PASSWORD", "F0r3ns1c_Redis_2024!")
requeued = 0
req = urllib.request.Request(
    f"{OS}/forensic-uploads*/_search",
    data=json.dumps({"size": 500, "query": {"match_all": {}}}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=30) as resp:
    hits = json.loads(resp.read()).get("hits", {}).get("hits", [])
for hit in hits:
    src = hit["_source"]
    ts = src.get("timesketch") or {}
    status = src.get("ingest_status", "")
    storage = src.get("storage") or {}
    bucket, key = storage.get("bucket"), storage.get("key")
    if not bucket or not key:
        continue
    need = status == "failed" or (ts and not ts.get("ok")) or (status == "completed" and not ts)
    if need:
        ext = (src.get("file", {}).get("name", "").rsplit(".", 1)[-1]).lower()
        if ext not in ("evtx", "evt", "csv", "log", "txt", "jsonl"):
            continue
    else:
        continue
    job = {
        "upload_id": src.get("upload_id") or hit["_id"],
        "case_id": src.get("case_id", "UNKNOWN"),
        "analyst": src.get("analyst", "repair"),
        "os_type": src.get("os_type", "unknown"),
        "portal": src.get("portal", "cert"),
        "bucket": bucket,
        "key": key,
        "filename": src.get("file", {}).get("name", "unknown"),
        "size": src.get("file", {}).get("size", 0),
        "repair": True,
    }
    payload = json.dumps(job).replace("'", "'\\''")
    subprocess.run(
        ["docker", "exec", "forensic-redis", "redis-cli", "-a", rpw, "--no-auth-warning", "LPUSH", q, payload],
        check=True, capture_output=True,
    )
    print(f"  REQUEUE {job['filename']} case={job['case_id']}")
    requeued += 1
print(f"[repair-ts] {requeued} job(s) ré-enfilé(s) sur {q}")
PY

echo "[repair-ts] 3/3 — Attente worker (30s)..."
sleep 30
echo "[repair-ts] Terminé. Vérifier: ./scripts/test_timesketch_e2e.sh"
