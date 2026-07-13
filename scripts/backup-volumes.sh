#!/usr/bin/env bash
# Sauvegarde des volumes Docker nommés (données persistantes) — à lancer depuis la racine du projet.
# Usage : ./scripts/backup-volumes.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
PREFIX="$(basename "$DIR")"
DEST="${1:-$DIR/backups/volumes-$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$DEST"

VOLS=(
  postgres-data
  minio-data
  opensearch-data1
  opensearch-data2
  thehive-data
  misp-db-data
  misp-files
  cassandra-data
  opencti-data
  timesketch-data
  timesketch-uploads
)

echo "[backup-volumes] Destination : $DEST"
for vn in "${VOLS[@]}"; do
  full="${PREFIX}_${vn}"
  if docker volume inspect "$full" &>/dev/null; then
    echo "[backup-volumes] Archivage volume $full ..."
    docker run --rm \
      -v "${full}:/src:ro" \
      -v "${DEST}:/backup" \
      alpine:3.19 \
      tar czf "/backup/${vn}.tgz" -C /src .
    echo "[backup-volumes] OK $vn -> ${vn}.tgz"
  else
    echo "[backup-volumes] SKIP (volume absent) : $full"
  fi
done

echo "[backup-volumes] Terminé."
