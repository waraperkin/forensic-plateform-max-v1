#!/usr/bin/env bash
# Export complet SOC — inventaires, règles, dashboards, vues, audit, version, suggestions IA.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CERT_URL="${CERT_PORTAL_URL:-http://localhost:3000}"
OUT_DIR="${OUT_DIR:-$ROOT/release/exports}"
TS="$(date +%Y%m%d-%H%M%S)"
ZIP_NAME="cybercorp-soc-export-${TS}.zip"
WORK="$OUT_DIR/soc-export-${TS}"
VERSION="$(tr -d '[:space:]' < release/VERSION 2>/dev/null || echo unknown)"

log() { echo "[export-soc] $*"; }

mkdir -p "$WORK"
log "Export vers $WORK"

export CERT_PORTAL_URL="$CERT_URL"
export PYTHONPATH="$ROOT/scripts"
export WORK="$WORK"
export VERSION="$VERSION"

python3 <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("PYTHONPATH", "."))
from portal_cert_master_lib import cert_login_session

work = Path(os.environ["WORK"])
version = os.environ.get("VERSION", "unknown")
cert_url = os.environ["CERT_PORTAL_URL"].rstrip("/")
s = cert_login_session(force=True)
s.verify = False

def get(path):
    r = s.get(f"{cert_url}{path}", timeout=120)
    return {"status": r.status_code, "body": r.json() if r.text.strip() else {}}

endpoints = [
    "/api/threat/sekoia/inventory",
    "/api/threat/sekoia/intakes",
    "/api/threat/sekoia/rules",
    "/api/threat/sekoia/modules",
    "/api/threat/sekoia/playbooks",
    "/api/threat/sekoia/formats",
    "/api/threat/sekoia/apikeys",
    "/api/threat/sekoia/stats",
    "/api/threat/s1/endpoints",
    "/api/threat/s1/groups",
    "/api/threat/s1/policies",
    "/api/threat/s1/rules",
    "/api/threat/s1/apikeys",
    "/api/threat/dashboards",
    "/api/threat/views",
    "/api/threat/audit",
    "/api/threat/apikey-tags",
    "/api/threat/health",
]

manifest = {"version": version, "exported_at": datetime.now(timezone.utc).isoformat(), "portal": cert_url, "files": []}
for ep in endpoints:
    name = ep.strip("/").replace("/", "_") + ".json"
    data = get(ep)
    (work / name).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest["files"].append(name)

(work / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
(work / "VERSION.txt").write_text(version + "\n", encoding="utf-8")

# Suggestions IA (exemples statiques + manifest)
ai_samples = {
    "query_example": "authentifications échouées WIN-DC01",
    "note": "Utiliser window.PortalAI.generateQueries() dans le portail pour suggestions live.",
}
(work / "ai-suggestions.json").write_text(json.dumps(ai_samples, indent=2), encoding="utf-8")
print(f"OK {len(manifest['files'])} fichiers")
PY

if [[ -f "$ROOT/release/RELEASE-NOTES.md" ]]; then
  cp -f "$ROOT/release/RELEASE-NOTES.md" "$WORK/"
fi

mkdir -p "$OUT_DIR"
(
  cd "$(dirname "$WORK")"
  zip -qr "$OUT_DIR/$ZIP_NAME" "$(basename "$WORK")"
)

log "Archive : $OUT_DIR/$ZIP_NAME"
ls -la "$OUT_DIR/$ZIP_NAME"
