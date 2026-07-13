#!/usr/bin/env bash
# Diagnostic rapide 502 sur /velociraptor/ — à lancer sur la VM.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== Diagnostic Velociraptor 502 ==="
echo ""

echo "--- Conteneurs ---"
docker ps -a --filter 'name=velociraptor' --filter 'name=forensic-nginx' \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo "Docker indisponible"

echo ""
echo "--- nginx forensic.conf (proxy VR) ---"
grep -A3 'location /velociraptor/' "$ROOT/config/nginx/conf.d/forensic.conf" 2>/dev/null | head -6

echo ""
echo "--- Test localhost:8000 (sidecar publié) ---"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8000/velociraptor/ 2>/dev/null || echo "000")
echo "http://127.0.0.1:8000/velociraptor/ → HTTP $code"
if [ "$code" = "000" ]; then
  echo "  → velociraptor-server absent ou pas démarré — lancer: ./forensic.sh repair-vr"
fi

echo ""
echo "--- Test depuis nginx → velociraptor-server:8000 ---"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^forensic-nginx$'; then
  docker exec forensic-nginx wget -S -O /dev/null -T 8 http://velociraptor-server:8000/velociraptor/ 2>&1 | tail -5
else
  echo "forensic-nginx absent"
fi

echo ""
echo "--- Réseaux ---"
docker network inspect velociraptor_net --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null || echo "velociraptor_net absent"

echo ""
echo "Correctif: git pull && ./forensic.sh repair-vr"
