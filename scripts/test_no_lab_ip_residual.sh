#!/usr/bin/env bash
# Garde-fou portabilité (P-15) : échoue si une IP d'infrastructure réelle
# ou le placeholder 192.0.2.9 reste codé en dur dans le code versionné.
# Les plages TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) sont
# tolérées UNIQUEMENT dans les fixtures de test et la documentation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

# 1) Anciennes IP d'infrastructure réelles (lab historique) : bannies partout
#    dans le code versionné, hors documentation et fixtures de test.
LAB_RE='(88\.183\.141\.|192\.168\.2\.|54\.198\.1\.|10\.78\.0\.|185\.234\.15\.|12\.22\.37\.)'
hits=$(git -C "$ROOT" grep -nE "$LAB_RE" -- . \
  ':(exclude)docs/**' ':(exclude)*.md' ':(exclude)*_test*' ':(exclude)*fixture*' \
  ':(exclude)helk/**' ':(exclude)velociraptor/lab-data/**' \
  ':(exclude)scripts/test_*' ':(exclude)tests/**' 2>/dev/null || true)
if [ -n "$hits" ]; then
  echo "FAIL: IP d'infrastructure historique codée en dur :" >&2
  echo "$hits" | head -20 >&2
  fail=1
else
  echo "PASS: aucune IP d'infrastructure historique dans le code"
fi

# 2) Le placeholder 192.0.2.9 ne doit pas rester dans les configs runtime critiques
check_file() {
  local label="$1" file="$2"
  if [ -f "$file" ] && grep -qE '192\.0\.2\.9' "$file" 2>/dev/null; then
    echo "FAIL: $label contient 192.0.2.9 ($file)" >&2
    fail=1
  else
    echo "PASS: $label"
  fi
}

check_file "velociraptor server.config" "$ROOT/velociraptor/config/server.config.yaml"
check_file "docker-compose.yml"        "$ROOT/docker-compose.yml"
check_file "forensic.conf"             "$ROOT/config/nginx/conf.d/forensic.conf"
check_file "grafana.ini"               "$ROOT/config/grafana/grafana.ini"
check_file "portal-cert config"        "$ROOT/portal-cert/public/config.json"
check_file "portal-it config"          "$ROOT/portal-it/public/config.json"

# 3) Scripts de déploiement : aucune URL https://<IP> figée
dep_hits=$(grep -rnE 'https://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  "$ROOT/scripts/apply_tls_full.sh" "$ROOT/scripts/deep_test_global.sh" \
  "$ROOT/scripts/generate_tls_all.sh" 2>/dev/null || true)
if [ -n "$dep_hits" ]; then
  echo "FAIL: URL figée sur une IP dans un script de déploiement :" >&2
  echo "$dep_hits" >&2
  fail=1
else
  echo "PASS: scripts de déploiement sans IP figée"
fi

if [ -f "$ROOT/.env" ] && grep -qE '^PUBLIC_HOST=192\.0\.2\.9' "$ROOT/.env" 2>/dev/null; then
  echo "WARN: .env local PUBLIC_HOST = 192.0.2.9 (fichier non versionné — lancer ./forensic.sh align-host)" >&2
else
  echo "PASS: .env PUBLIC_HOST"
fi

[ "$fail" -eq 0 ] && echo "Aucune IP lab résiduelle dans les configs critiques" || exit 1
