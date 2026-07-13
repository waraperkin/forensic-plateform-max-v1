#!/usr/bin/env bash
# Génère le snippet nginx : redirection DNS EC2 → IP publique (mode FP_ACCESS_MODE=ip).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/config/nginx/generated"
OUT_FILE="$OUT_DIR/ec2-dns-redirect.conf"

mkdir -p "$OUT_DIR"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
fi

IP=$(fp_detect_public_ip 2>/dev/null || true)
DNS=$(_fp_aws_public_hostname 2>/dev/null || true)
DNS=$(fp_normalize_host "$DNS" 2>/dev/null || true)

if ! _fp_is_ipv4 "$IP" 2>/dev/null || [ -z "$DNS" ] || [ "$DNS" = "$IP" ]; then
  echo "# Pas de redirection DNS EC2 (IP ou hostname indisponible)" > "$OUT_FILE"
  echo "[generate-nginx-access] Skip redirect (ip=$IP dns=$DNS)"
  exit 0
fi

cat > "$OUT_FILE" <<EOF
# Auto-généré — accès uniforme par IP (évite boucles redirect DNS EC2 vs IP)
# Régénérer : bash scripts/generate-nginx-access-snippet.sh
if (\$host = "${DNS}") {
    return 301 https://${IP}\$request_uri;
}
EOF

echo "[generate-nginx-access] Redirect ${DNS} → https://${IP}/"
echo "[generate-nginx-access] Écrit : $OUT_FILE"
