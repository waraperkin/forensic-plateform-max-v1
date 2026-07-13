#!/usr/bin/env bash
# Répare tous les sketches Timesketch (patch explore + réimport WARA/cassés)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

echo "[repair-all-ts] Patch explore API (persistant au prochain restart via entrypoint)..."
bash "$ROOT/config/timesketch/apply-explore-patch.sh" 2>/dev/null || \
  bash "$ROOT/scripts/timesketch-patch-explore.sh" || true

echo "[repair-all-ts] Vérification initiale..."
if python3 "$ROOT/scripts/timesketch_verify_all_sketches.py"; then
  echo "[repair-all-ts] Tous les sketches déjà OK"
  exit 0
fi

echo "[repair-all-ts] Réparation sketchs WARA (--wara)..."
bash "$ROOT/scripts/repair_timesketch_sketch.sh" --wara || true

echo "[repair-all-ts] Re-vérification..."
python3 "$ROOT/scripts/timesketch_verify_all_sketches.py"
