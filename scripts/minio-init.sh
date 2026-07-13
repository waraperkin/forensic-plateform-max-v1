#!/bin/sh
# MinIO bucket initialization — robuste
set -e
echo "[minio-init] Connecting to MinIO..."
mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"

BUCKETS="fp-dfir fp-logs fp-ti fp-artifacts fp-cases \
         fp-dr-dfir fp-dr-logs fp-dr-ti fp-dr-artifacts fp-dr-cases \
         logs-raw logs-windows logs-linux logs-macos logs-web logs-db \
         logs-cloud logs-k8s logs-network pcap artefacts timesketch \
         opencti reports iocs kape velociraptor it-uploads"

for b in $BUCKETS; do
  mc mb --ignore-existing "local/$b" && echo "[minio-init] ✓ $b" || echo "[minio-init] EXISTS $b"
done

echo "[minio-init] Done ✓"
