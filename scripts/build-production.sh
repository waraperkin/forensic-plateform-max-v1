#!/usr/bin/env bash
# Build production CERT CYBERCORP — minify, bundles, gzip, image Docker taguée.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < release/VERSION 2>/dev/null || echo "2026.06.03-final1")"
IMAGE_TAG="${IMAGE_TAG:-cybercorp-portal:${VERSION}}"
PUBLIC_RELEASE="$ROOT/portal-cert/public/release"
MIN_SCRIPT="$ROOT/scripts/minify-portal-assets.sh"

log() { echo "[build-production] $*"; }

log "Version: $VERSION"
mkdir -p "$PUBLIC_RELEASE"
cp -f release/VERSION release/RELEASE-NOTES.md "$PUBLIC_RELEASE/"

if [[ -x "$MIN_SCRIPT" ]] || [[ -f "$MIN_SCRIPT" ]]; then
  log "Minification JS/CSS portal-shared"
  bash "$MIN_SCRIPT"
fi

log "Préparation assets gzip (best-effort)"
GZIP_DIR="$ROOT/portal-cert/public/shared-gzip"
mkdir -p "$GZIP_DIR/js" "$GZIP_DIR/css"
if command -v gzip >/dev/null 2>&1; then
  for f in "$ROOT/portal-shared/js"/*.js; do
    [[ -f "$f" ]] || continue
    gzip -kf -9 "$f" 2>/dev/null && cp -f "${f}.gz" "$GZIP_DIR/js/$(basename "$f").gz" || true
  done
  for f in "$ROOT/portal-shared/css"/*.css; do
    [[ -f "$f" ]] || continue
    gzip -kf -9 "$f" 2>/dev/null && cp -f "${f}.gz" "$GZIP_DIR/css/$(basename "$f").gz" || true
  done
fi

log "Build Docker cert-portal → $IMAGE_TAG"
docker compose build cert-portal
docker tag "$(docker compose images cert-portal -q 2>/dev/null | head -1 || true)" "$IMAGE_TAG" 2>/dev/null \
  || docker tag fp-final2-cert-portal:latest "$IMAGE_TAG" 2>/dev/null \
  || log "Tag manuel si besoin: docker tag <image> $IMAGE_TAG"

log "Écriture release/build-info.json"
mkdir -p "$ROOT/release"
cat > "$ROOT/release/build-info.json" <<EOF
{
  "version": "$VERSION",
  "image": "$IMAGE_TAG",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "portal": "cert-portal"
}
EOF

log "Build production terminé — $IMAGE_TAG"
