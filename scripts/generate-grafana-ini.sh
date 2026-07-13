#!/usr/bin/env bash
# Génère config/grafana/grafana.ini aligné sur l'IP hôte détectée (.env / host-ip.sh).
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$DIR/config/grafana/grafana.ini"

if [ -f "$DIR/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$DIR/scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi

HOST=$(fp_url_identity 2>/dev/null || fp_detect_public_host 2>/dev/null || echo "localhost")
HOST=$(fp_normalize_host "$HOST")

mkdir -p "$(dirname "$OUT")"
cat > "$OUT" <<EOF
# Forensic Platform — Grafana (généré par scripts/generate-grafana-ini.sh)
# Les variables GF_* dans docker-compose priment si définies.

[server]
protocol = http
domain = ${HOST}
root_url = https://${HOST}/grafana/
serve_from_sub_path = true
enforce_domain = false

[security]
allow_embedding = true
cookie_secure = true
cookie_samesite = none
csrf_trusted_origins = https://${HOST},http://${HOST},https://localhost,http://localhost,https://127.0.0.1,http://127.0.0.1

[live]
allowed_origins = https://${HOST},http://${HOST},https://localhost,http://localhost,https://127.0.0.1,http://127.0.0.1

[cors]
enabled = true
allow_credentials = true
allow_origin = https://${HOST},http://${HOST},https://localhost,http://localhost

[users]
allow_sign_up = false

[auth.anonymous]
enabled = true
org_role = Admin
EOF
echo "[grafana-ini] OK — domain=${HOST}"
