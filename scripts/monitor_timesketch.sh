#!/usr/bin/env bash
# Monitoring Timesketch — vérifie tous les sketchs, répare si explore/UI en échec
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f .env ] && set -a && source .env && set +a

LOG="${TS_MONITOR_LOG:-/tmp/timesketch-monitor.log}"
REPAIR="${TS_MONITOR_REPAIR:-1}"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG"; }

bash "$ROOT/scripts/timesketch-patch-explore.sh" >>"$LOG" 2>&1 || \
  bash "$ROOT/config/timesketch/apply-explore-patch.sh" >>"$LOG" 2>&1 || true

if python3 "$ROOT/scripts/timesketch_verify_all_sketches.py" >>"$LOG" 2>&1; then
  log "OK — tous les sketches Timesketch valides"
  exit 0
fi

log "Échec vérification — tentative réparation WARA"
if [ "$REPAIR" = "1" ] && [ -x "$ROOT/scripts/repair_timesketch_sketch.sh" ]; then
  bash "$ROOT/scripts/repair_timesketch_sketch.sh" --wara >>"$LOG" 2>&1 || true
fi

if python3 "$ROOT/scripts/timesketch_verify_all_sketches.py" >>"$LOG" 2>&1; then
  log "OK après réparation"
  exit 0
fi

log "ERREUR — sketches encore en échec, voir $LOG"
exit 1
