#!/usr/bin/env bash
# Remet en route postgres / redis / cassandra et Timesketch worker après conflit IP Docker.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=/dev/null
[ -f "$ROOT/.env" ] && set -a && source "$ROOT/.env" && set +a

NET="${COMPOSE_PROJECT_NAME:-fp-final2}_forensic-net"
log() { echo "[infra-recover] $*"; }

holder_at() {
  local ip="$1"
  docker network inspect "$NET" -f '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}' 2>/dev/null \
    | awk -v p="${ip}/" '$2 ~ ("^" p) {print $1; exit}'
}

free_ip() {
  local ip="$1"
  local name
  name="$(holder_at "$ip")"
  if [ -n "$name" ] && [ "$name" != "forensic-postgres" ] && [ "$name" != "forensic-redis" ]; then
    log "Libération IP ${ip} — arrêt temporaire de ${name}"
    docker stop "$name" >/dev/null 2>&1 || true
    echo "$name"
  fi
}

stopped=()
while read -r ip svc; do
  h="$(free_ip "$ip")"
  [ -n "$h" ] && stopped+=("$h")
done <<'IPS'
172.25.0.10 postgres
172.25.0.11 redis
172.25.0.15 cassandra
IPS

log "Démarrage postgres / redis / cassandra…"
docker start forensic-postgres forensic-redis forensic-cassandra 2>/dev/null || \
  docker compose up -d postgres redis cassandra

sleep 8
for svc in postgres redis cassandra; do
  if ! docker ps --format '{{.Names}}' | grep -qx "forensic-${svc}"; then
    log "ERREUR — forensic-${svc} absent"
    exit 1
  fi
  log "OK forensic-${svc}"
done

log "Redémarrage Timesketch worker + web…"
docker restart forensic-timesketch-worker forensic-timesketch-web >/dev/null 2>&1 || true
sleep 12

if docker ps --format '{{.Names}}\t{{.Status}}' | grep -q 'forensic-timesketch-worker.*Up'; then
  log "OK timesketch-worker"
else
  log "WARN timesketch-worker — voir docker logs forensic-timesketch-worker"
fi

if [ "${#stopped[@]}" -gt 0 ]; then
  log "Relance connecteurs arrêtés pour conflit IP: ${stopped[*]}"
  docker start "${stopped[@]}" >/dev/null 2>&1 || true
fi

log "Cluster OpenSearch: $(curl -sk 'http://localhost:9200/_cluster/health' | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo '?')"
log "Terminé — lancer ./forensic.sh platform-health-setup puis dashboard-qa"
