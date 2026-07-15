#!/usr/bin/env bash
# Nettoie bootstrap.php MISP depuis l'hôte ou le conteneur MISP.
set -euo pipefail

if [ -f /var/www/MISP/app/Config/bootstrap.php ]; then
  CONTAINER=""
else
  CONTAINER="${MISP_CONTAINER:-forensic-misp}"
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    echo "[misp-sanitize-bootstrap] Container $CONTAINER absent"
    exit 1
  fi
fi

_run() {
  if [ -n "$CONTAINER" ]; then
    docker exec "$CONTAINER" "$@"
  else
    "$@"
  fi
}

_run python3 - <<'PY'
import pathlib
boot = pathlib.Path("/var/www/MISP/app/Config/bootstrap.php")
fix = "/scripts/misp-bootstrap-localhost-fix.php"
marker = "FP_LOCALHOST_BASE_FIX"
t = boot.read_text(errors="replace")
if "?>" in t:
    t = t.split("?>", 1)[0].rstrip() + "\n"
while marker in t:
    t = t.split(marker, 1)[0].rstrip() + "\n"
req = f"require '{fix}';"
if req not in t:
    if not t.lstrip().startswith("<?php"):
        t = "<?php\n" + t.lstrip()
    t = t.rstrip() + f"\n// {marker}\n{req}\n"
boot.write_text(t)
print("[misp-sanitize-bootstrap] bootstrap.php nettoyé")
PY

_run php -l /var/www/MISP/app/Config/bootstrap.php >/dev/null \
  && echo "[misp-sanitize-bootstrap] syntaxe PHP OK" \
  || { echo "[misp-sanitize-bootstrap] ERREUR syntaxe" >&2; exit 1; }
