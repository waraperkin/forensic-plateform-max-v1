#!/bin/sh
set -e
CONFIG="${VR_CONFIG:-/config/server.config.yaml}"
DATA="${VR_DATA:-/data}"
ADMIN_USER="${VELOCIRAPTOR_ADMIN_USER:-admin}"
ADMIN_PASS="${VELOCIRAPTOR_ADMIN_PASSWORD:-F0r3ns1c_VR_2024!}"
mkdir -p "$DATA" /artifacts/custom
if [ ! -f "$CONFIG" ]; then
  echo "ERREUR: $CONFIG introuvable — exécuter scripts/generate-config.sh" >&2
  exit 1
fi
MARKER="$DATA/.admin_bootstrapped"
if [ ! -f "$MARKER" ]; then
  echo "[entrypoint] Création utilisateur GUI $ADMIN_USER…"
  /usr/local/bin/velociraptor --config "$CONFIG" user add --role administrator "$ADMIN_USER" "$ADMIN_PASS" 2>/dev/null || true
  touch "$MARKER"
fi
CMD="${1:-frontend}"
shift || true
DEF_ARGS="--definitions /artifacts/custom"
if [ -d /artifacts/official ] && [ -n "$(ls -A /artifacts/official 2>/dev/null | grep -E '\\.ya?ml$' || true)" ]; then
  DEF_ARGS="--definitions /artifacts/official $DEF_ARGS"
fi
exec /usr/local/bin/velociraptor --config "$CONFIG" $DEF_ARGS "$CMD" "$@"
