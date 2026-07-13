#!/bin/bash
# Ouvre les UIs Forensic Platform (Cursor Simple Browser, xdg-open, ou les deux).
# Appelé par forensic.sh start — utilisable aussi seul : bash scripts/start_open_ui.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
ok()  { echo -e "${GREEN}[ OK ]${NC} $*"; }

# auto | cursor | xdg | both | 0
MODE="${FP_START_OPEN_UI:-auto}"
[ "$MODE" = "0" ] && exit 0

fp_url_encode() {
  python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}

fp_open_cursor() {
  local url="$1"
  local enc scheme opened=0
  enc=$(fp_url_encode "$url")
  for scheme in cursor vscode; do
    if xdg-open "${scheme}://vscode.simple-browser/show?url=${enc}" >/dev/null 2>&1; then
      opened=1
      break
    fi
  done
  [ "$opened" -eq 1 ]
}

fp_open_xdg() {
  local url="$1"
  command -v xdg-open >/dev/null 2>&1 && xdg-open "$url" >/dev/null 2>&1 &
}

fp_open_url() {
  local url="$1"
  local m="$MODE"
  if [ "$m" = "auto" ]; then
    if [ -n "${CURSOR_AGENT:-}" ] || [ -n "${VSCODE_IPC_HOOK:-}" ] || [ -n "${CURSOR_TRACE_ID:-}" ]; then
      m="cursor"
    else
      m="xdg"
    fi
  fi
  case "$m" in
    cursor)
      fp_open_cursor "$url" || fp_open_xdg "$url" || true
      ;;
    xdg|external)
      fp_open_xdg "$url" || true
      ;;
    both)
      fp_open_cursor "$url" || true
      fp_open_xdg "$url" || true
      ;;
    *) ;;
  esac
}

# Sketch E2E récent si disponible
TS_URL="http://localhost:5000/"
if [ -f "$DIR/logs/timesketch_advanced_e2e_sketch.url" ]; then
  TS_URL=$(cat "$DIR/logs/timesketch_advanced_e2e_sketch.url" | head -1)
fi

URLS=(
  "https://localhost/dashboards/app/dashboards#/view/fp-ti-overview"
  "https://localhost/dashboards/app/dashboards#/view/fp-opensearch-overview"
  "https://localhost/grafana/d/timesketch-overview"
  "$TS_URL"
)

info "Ouverture UIs (mode=${MODE}, détecté auto→cursor si terminal Cursor)"
for u in "${URLS[@]}"; do
  info "$u"
  fp_open_url "$u"
  sleep 0.4
done
info "Certificat auto-signé : accepter l'avertissement sur https://localhost"
ok "URLs envoyées au navigateur Cursor / système"
