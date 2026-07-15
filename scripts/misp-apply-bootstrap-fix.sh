#!/bin/sh
# Applique le correctif App.base pour MISP derrière nginx /misp/.
set -eu
BOOT="/var/www/MISP/app/Config/bootstrap.php"
FIX="/scripts/misp-bootstrap-localhost-fix.php"
MARKER="FP_LOCALHOST_BASE_FIX"

if [ ! -f "$FIX" ]; then
  echo "[misp-bootstrap-fix] $FIX absent"
  exit 1
fi

if [ -x /scripts/misp-sanitize-bootstrap.sh ]; then
  exec /scripts/misp-sanitize-bootstrap.sh
fi

python3 - "$BOOT" "$FIX" "$MARKER" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
t = p.read_text(errors="replace")
if "?>" in t:
    t = t.split("?>", 1)[0].rstrip() + "\n"
while sys.argv[3] in t:
    t = t.split(sys.argv[3], 1)[0].rstrip() + "\n"
req = f"require '{sys.argv[2]}';"
if req not in t:
    if not t.lstrip().startswith("<?php"):
        t = "<?php\n" + t.lstrip()
    t = t.rstrip() + f"\n// {sys.argv[3]}\n{req}\n"
p.write_text(t)
print("[misp-bootstrap-fix] bootstrap.php nettoyé (python)")
PY

php -l "$BOOT" >/dev/null || { echo "[misp-bootstrap-fix] ERREUR syntaxe bootstrap.php" >&2; exit 1; }
