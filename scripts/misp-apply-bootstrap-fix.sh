#!/bin/sh
# Applique App.base inline dans bootstrap.php (sans ?> — sinon PHP affiché dans le navigateur).
set -eu
BOOTSTRAP="/var/www/MISP/app/Config/bootstrap.php"
FIX="/scripts/misp-bootstrap-localhost-fix.php"
MARKER="FP_LOCALHOST_BASE_FIX"

if [ ! -f "$FIX" ]; then
  echo "[misp-bootstrap-fix] $FIX absent"
  exit 1
fi

python3 - "$BOOTSTRAP" "$MARKER" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
marker = sys.argv[2]
text = path.read_text(encoding="utf-8", errors="replace")

if "?>" in text:
    text = text.split("?>", 1)[0].rstrip() + "\n"

while marker in text:
    idx = text.index(marker)
    text = text[:idx].rstrip() + "\n"

path.write_text(text, encoding="utf-8")
PY

if grep -q "$MARKER" "$BOOTSTRAP" 2>/dev/null; then
  echo "[misp-bootstrap-fix] déjà appliqué"
  exit 0
fi

if ! grep -q '^<?php' "$BOOTSTRAP" 2>/dev/null; then
  sed -i '1s/^/<?php\n/' "$BOOTSTRAP"
fi

{
  echo ""
  echo "// $MARKER"
  cat "$FIX"
} >> "$BOOTSTRAP"

php -l "$BOOTSTRAP" >/dev/null \
  && echo "[misp-bootstrap-fix] bootstrap.php patché" \
  || { echo "[misp-bootstrap-fix] ERREUR syntaxe" >&2; exit 1; }
