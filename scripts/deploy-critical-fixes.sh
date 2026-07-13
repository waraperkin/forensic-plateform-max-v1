#!/usr/bin/env bash
# Déploie les correctifs critiques : cert-portal, ingest-worker, timesketch-web
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

echo "[deploy] Patch explore Timesketch..."
bash "$ROOT/scripts/timesketch-patch-explore.sh" 2>/dev/null || true

echo "[deploy] Build & restart services..."
docker compose build cert-portal ingest-worker
docker compose up -d cert-portal ingest-worker timesketch-web timesketch-worker

sleep 10
echo "[deploy] Vérification credentials API..."
curl -sk http://localhost:3000/api/credentials | python3 -c "
import json,sys
d=json.load(sys.stdin)
masked=sum(1 for c in d.get('credentials',[]) if '•' in str(c.get('password','')))
print('note:', d.get('note'))
print('masked:', masked, '/', len(d.get('credentials',[])))
if masked: sys.exit(1)
print('sample:', d['credentials'][0]['service'], d['credentials'][0]['password'][:20])
"

echo "[deploy] Timesketch verify..."
python3 "$ROOT/scripts/timesketch_verify_all_sketches.py"

echo "[deploy] OK"
