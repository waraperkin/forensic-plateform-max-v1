#!/usr/bin/env bash
# Applique les patches explore.py (fields + sketch vide) puis redémarre timesketch-web.
# Voir config/timesketch/apply-explore-patch.sh (monté dans le conteneur sous /opt/fp-timesketch/).
set -euo pipefail
CONTAINER="${TIMESKETCH_WEB_CONTAINER:-forensic-timesketch-web}"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "[ts-patch] Container $CONTAINER absent"
  exit 1
fi

TARGET="$(docker exec "$CONTAINER" python3 -c "import glob; p=sorted(glob.glob('/opt/venv/lib/python3.*/site-packages/timesketch/api/v1/resources/explore.py')); print(p[0] if p else '')" 2>/dev/null || true)"
if [ -z "$TARGET" ]; then
  echo "[ts-patch] explore.py introuvable dans le conteneur"
  exit 1
fi

AGG="$(docker exec "$CONTAINER" python3 -c "import glob; p=sorted(glob.glob('/opt/venv/lib/python3.*/site-packages/timesketch/api/v1/resources/aggregation.py')); print(p[0] if p else '')" 2>/dev/null || true)"
if [ -z "$AGG" ]; then
  echo "[ts-patch] aggregation.py introuvable dans le conteneur"
  exit 1
fi

ANALYSIS="$(docker exec "$CONTAINER" python3 -c "import glob; p=sorted(glob.glob('/opt/venv/lib/python3.*/site-packages/timesketch/api/v1/resources/analysis.py')); print(p[0] if p else '')" 2>/dev/null || true)"
if [ -z "$ANALYSIS" ]; then
  echo "[ts-patch] analysis.py introuvable"
  exit 1
fi

MANAGER="$(docker exec "$CONTAINER" python3 -c "import glob; p=sorted(glob.glob('/opt/venv/lib/python3.*/site-packages/timesketch/lib/analyzers/manager.py')); print(p[0] if p else '')" 2>/dev/null || true)"

if docker exec "$CONTAINER" grep -q "FP_PATCH_FIELDS_LIST" "$TARGET" 2>/dev/null \
  && docker exec "$CONTAINER" grep -q "FP_PATCH_EMPTY_INDICES" "$TARGET" 2>/dev/null \
  && docker exec "$CONTAINER" grep -q "FP_PATCH_AGG_TYPEERROR" "$AGG" 2>/dev/null \
  && docker exec "$CONTAINER" grep -q "FP_PATCH_ANALYZER_GET" "$ANALYSIS" 2>/dev/null \
  && { [ -z "$MANAGER" ] || docker exec "$CONTAINER" grep -q "FP_PATCH_ANALYZERS_FILTER" "$MANAGER" 2>/dev/null; } \
  && docker exec "$CONTAINER" grep -q "FP_PATCH_ANALYZERS_FILTER_GET" "$ANALYSIS" 2>/dev/null; then
  echo "[ts-patch] Déjà appliqué (explore + aggregation + analyzer + filter)"
  exit 0
fi

docker exec "$CONTAINER" bash /opt/fp-timesketch/apply-explore-patch.sh

docker restart "$CONTAINER" >/dev/null
echo "[ts-patch] Redémarrage $CONTAINER..."
for _ in $(seq 1 40); do
  if docker exec "$CONTAINER" python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login/', timeout=3)" >/dev/null 2>&1; then
    echo "[ts-patch] OK"
    exit 0
  fi
  sleep 2
done
echo "[ts-patch] WARN — healthcheck timeout (patch peut être appliqué)" >&2
exit 0
