#!/usr/bin/env bash
# Déploie le monitoring lab Velociraptor (collectes périodiques) + label clients lab.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VR_CONTAINER="${VR_CONTAINER:-velociraptor-server}"
PERIOD="${LAB_COLLECTION_PERIOD_SEC:-900}"

echo "==> Import artefact Server.Lab.ScheduledCollections"
docker cp "$ROOT/artifacts/custom/Server.Lab.ScheduledCollections.yaml" \
  "$VR_CONTAINER:/tmp/Server.Lab.ScheduledCollections.yaml"
docker exec "$VR_CONTAINER" velociraptor --config /config/server.config.yaml \
  tools upload --public /tmp/Server.Lab.ScheduledCollections.yaml || true

echo "==> Client monitoring (toutes les ${PERIOD}s)"
docker exec "$VR_CONTAINER" velociraptor --config /config/server.config.yaml \
  query "SELECT * FROM artifact_set(names=['Custom.Server.Lab.ScheduledCollections'], args=dict(period_sec='${PERIOD}'))" \
  || echo "[WARN] Déployer via UI: Settings → Client Monitoring → Add artifact Custom.Server.Lab.ScheduledCollections"

echo "==> Labeller les clients (hostname lab-*)"
docker exec "$VR_CONTAINER" velociraptor --config /config/server.config.yaml \
  query "SELECT client_id, label(client_id=client_id, op='set', labels=['lab']) FROM clients() WHERE os_info.hostname =~ 'lab-.*'" \
  2>/dev/null || echo "[INFO] Aucun client lab connecté — installer agents (docs/LAB-ENDPOINTS.md)"

echo "OK — voir docs/VELOCIRAPTOR-PLAYBOOKS.md (Playbook 4)"
