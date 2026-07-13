#!/usr/bin/env bash
# Génère config/nginx/snippets/velociraptor-proxy.conf (Basic auth → GUI VR derrière nginx).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SNIP="$ROOT/config/nginx/snippets/velociraptor-proxy.conf"
ENV_FILE="$ROOT/.env"

if [ -f "$ENV_FILE" ]; then
  USER=$(grep -E '^VELOCIRAPTOR_ADMIN_USER=' "$ENV_FILE" | head -1 | cut -d= -f2- || true)
  PASS=$(grep -E '^VELOCIRAPTOR_ADMIN_PASSWORD=' "$ENV_FILE" | head -1 | cut -d= -f2- || true)
fi

USER="${VELOCIRAPTOR_ADMIN_USER:-admin}"
PASS="${VELOCIRAPTOR_ADMIN_PASSWORD:-F0r3ns1c_VR_2024!}"
B64=$(printf '%s:%s' "$USER" "$PASS" | tr -d '\r\n' | base64 | tr -d '\n')

mkdir -p "$(dirname "$SNIP")"
cat > "$SNIP" <<EOF
# Généré par scripts/render-velociraptor-nginx-snippet.sh — lab DFIR uniquement
# Transmet les identifiants GUI Velociraptor au sidecar (évite le popup Basic Auth navigateur).
proxy_set_header Authorization "Basic ${B64}";
EOF

echo "[render-vr-nginx] OK → $SNIP (user=${USER})"
