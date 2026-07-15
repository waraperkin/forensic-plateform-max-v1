#!/usr/bin/env bash
# Supprime les patches bootstrap.php corrompus (PHP affiché dans le navigateur MISP).
set -euo pipefail

CONTAINER="${MISP_CONTAINER:-forensic-misp}"
BOOT="/var/www/MISP/app/Config/bootstrap.php"
MARKER="FP_LOCALHOST_BASE_FIX"

if [ -f /var/www/MISP/app/Config/bootstrap.php ]; then
  _exec() { "$@"; }
else
  CONTAINER="${MISP_CONTAINER:-forensic-misp}"
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    echo "[misp-sanitize-bootstrap] Container $CONTAINER absent"
    exit 1
  fi
  _exec() { docker exec "$CONTAINER" "$@"; }
fi

_exec python3 - "$BOOT" "$MARKER" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
marker = sys.argv[2]
text = path.read_text(encoding="utf-8", errors="replace")

# Tout après ?> est émis tel quel dans les pages HTML — supprimer
if "?>" in text:
    text = text.split("?>", 1)[0].rstrip() + "\n"

# Supprimer tous les patches FP (inline ou require)
while marker in text:
    text = text.split(marker, 1)[0].rstrip() + "\n"

# Supprimer les require orphelins du fix
lines = []
for line in text.splitlines():
    if "misp-bootstrap-localhost-fix.php" in line:
        continue
    lines.append(line)
text = "\n".join(lines).rstrip() + "\n"

if not text.lstrip().startswith("<?php"):
    text = "<?php\n" + text.lstrip()

path.write_text(text, encoding="utf-8")
print("[misp-sanitize-bootstrap] bootstrap.php restauré (sans patch FP)")
PY

_exec php -l "$BOOT" >/dev/null \
  && echo "[misp-sanitize-bootstrap] syntaxe OK" \
  || { echo "[misp-sanitize-bootstrap] ERREUR syntaxe" >&2; exit 1; }
