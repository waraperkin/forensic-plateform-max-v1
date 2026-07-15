#!/bin/sh
# Applique le correctif App.base pour MISP derrière nginx /misp/.
set -eu
BOOTSTRAP="/var/www/MISP/app/Config/bootstrap.php"
FIX="/scripts/misp-bootstrap-localhost-fix.php"
MARKER="FP_LOCALHOST_BASE_FIX"

if [ ! -f "$FIX" ]; then
  echo "[misp-bootstrap-fix] $FIX absent"
  exit 1
fi

if grep -q "$MARKER" "$BOOTSTRAP" 2>/dev/null; then
  echo "[misp-bootstrap-fix] déjà appliqué (require $FIX)"
  exit 0
fi

if ! grep -q '^<?php' "$BOOTSTRAP" 2>/dev/null; then
  sed -i '1s/^/<?php\n/' "$BOOTSTRAP"
fi

{
  echo ""
  echo "// $MARKER — require monté depuis l'hôte (scripts/misp-bootstrap-localhost-fix.php)"
  echo "require '$FIX';"
} >> "$BOOTSTRAP"

echo "[misp-bootstrap-fix] bootstrap.php patché"
