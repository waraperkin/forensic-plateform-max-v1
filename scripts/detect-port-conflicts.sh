#!/usr/bin/env bash
# Détecte les conflits de ports host avant démarrage forensic-minimal.
# N'arrête aucun service externe — propose des ports alternatifs via variables FP_*.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

check_port() {
  local port="$1" var="$2" default="$3"
  if command -v ss >/dev/null 2>&1; then
    if ss -tlnH "sport = :$port" 2>/dev/null | grep -q .; then
      echo "CONFLICT: port $port ($var, défaut $default) déjà utilisé"
      return 1
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -tln 2>/dev/null | grep -qE ":${port}[[:space:]]"; then
      echo "CONFLICT: port $port ($var, défaut $default) déjà utilisé"
      return 1
    fi
  fi
  echo "OK: port $port ($var)"
  return 0
}

echo "=== Inventaire containers Docker (tous projets) ==="
if command -v docker >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
  sudo docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}' 2>/dev/null || docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}' 2>/dev/null || echo "Docker indisponible"
else
  echo "Docker indisponible — vérification ports host uniquement"
fi

echo ""
echo "=== Ports forensic-minimal (défauts production) ==="
fail=0
PORTS=(
  "80:FP_HTTP_PORT"
  "443:FP_HTTPS_PORT"
  "9200:FP_OS_PORT"
  "5601:FP_OSD_PORT"
  "5000:FP_TIMESKETCH_PORT"
  "9000:FP_MINIO_PORT"
  "9001:FP_MINIO_CONSOLE_PORT"
)
for entry in "${PORTS[@]}"; do
  port="${entry%%:*}"
  var="${entry#*:}"
  check_port "$port" "$var" "$port" || fail=1
done

echo ""
if [ "$fail" -eq 1 ]; then
  echo "Conflits détectés — créer un fichier local (non committé) avec des ports alternatifs, ex. :"
  cat <<'EX'
FP_HTTP_PORT=8080
FP_HTTPS_PORT=8443
FP_OS_PORT=9201
FP_OSD_PORT=5602
FP_TIMESKETCH_PORT=5001
FP_MINIO_PORT=9002
FP_MINIO_CONSOLE_PORT=9003
EX
  echo "Puis : export \$(grep -v '^#' config/local-ports.env | xargs) && docker compose up -d"
  exit 1
fi
echo "Aucun conflit sur les ports par défaut — démarrage standard 80/443 possible"
exit 0
