#!/usr/bin/env bash
# Valide les motifs proxy HELK/MISP/VR (évite boucles de redirection).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$ROOT/config/nginx/conf.d/forensic.conf"
MISP_SNIP="$ROOT/config/nginx/snippets/misp-root-paths.conf"
HELK_COMPOSE="$ROOT/helk/docker-compose.helk.yml"
fail=0

check_grep() {
  local label="$1" pattern="$2" file="$3" invert="${4:-0}"
  if [ "$invert" = "1" ]; then
    if grep -qE "$pattern" "$file"; then
      echo "FAIL: $label (présent dans $file)" >&2
      fail=1
    else
      echo "PASS: $label"
    fi
  else
    if grep -qE "$pattern" "$file"; then
      echo "PASS: $label"
    else
      echo "FAIL: $label (absent dans $file)" >&2
      fail=1
    fi
  fi
}

# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"

echo "=== Nginx proxy sous-chemin ==="
check_grep "HELK Kibana même motif qu'OSD (sans double basePath)" \
  'location /helk/kibana \{' "$CONF"
check_grep "HELK proxy_pass racine upstream" \
  'proxy_pass http://\$helk_kibana_upstream;' "$CONF"
check_grep "HELK proxy_redirect off" \
  'proxy_redirect off;' "$CONF"
check_grep "VR proxy HTTP plain (TLS offload nginx)" \
  'proxy_pass http://\$velociraptor_upstream/velociraptor/;' "$CONF"
if grep -A16 'location /velociraptor/' "$CONF" | grep -q 'proxy_redirect off'; then
  echo "PASS: VR proxy_redirect off"
else
  echo "FAIL: VR proxy_redirect off (absent dans block /velociraptor/)" >&2
  fail=1
fi
check_grep "VR sans proxy HTTPS upstream" \
  'proxy_pass https://\$velociraptor_upstream' "$CONF" 1
check_grep "MISP proxy_redirect off (pas de / → /misp/)" \
  'proxy_redirect off;' "$MISP_SNIP"
check_grep "MISP sans proxy_redirect / → /misp/" \
  'proxy_redirect / https://' "$MISP_SNIP" 1
check_grep "Logstash proxy sous-chemin" \
  'location /logstash/' "$CONF"
check_grep "Logstash upstream monitoring" \
  'upstream u_logstash' "$CONF"
check_grep "MISP proxy rewrite strip prefix" \
  'rewrite \^/misp/\?\(\.\*\)\$ /\$1 break;' "$CONF"
check_grep "Docs nginx alias direct" \
  'alias /usr/share/nginx/portal-docs/' "$CONF"

echo ""
echo "=== HELK Kibana public URL ==="
check_grep "SERVER_PUBLICBASEURL dans compose HELK" \
  'SERVER_PUBLICBASEURL' "$HELK_COMPOSE"

echo ""
echo "=== Normalisation URL ==="
assert_norm() {
  local label="$1" in="$2" want="$3"
  local got
  got=$(fp_normalize_host "$in")
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
  else
    echo "FAIL: $label (got='$got' want='$want')" >&2
    fail=1
  fi
}
assert_misp_url() {
  local label="$1" want="$2"
  local got
  got=$(PUBLIC_HOST=203.0.113.10 fp_misp_public_base_url)
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
  else
    echo "FAIL: $label (got='$got' want='$want')" >&2
    fail=1
  fi
}
assert_ip_identity() {
  local got
  got=$(PUBLIC_HOST=203.0.113.10 PUBLIC_HOSTNAME= fp_url_identity)
  if [ "$got" = "203.0.113.10" ]; then
    echo "PASS: fp_url_identity préfère IP"
  else
    echo "FAIL: fp_url_identity (got='$got' want IP)" >&2
    fail=1
  fi
}
assert_norm "fp_normalize_host strip https" "https://ec2.example.com/misp" "ec2.example.com"
assert_misp_url "fp_misp_public_base_url" "https://203.0.113.10/misp"
assert_ip_identity

echo ""
[ "$fail" -eq 0 ] && echo "Proxy sous-chemin OK" || exit 1
