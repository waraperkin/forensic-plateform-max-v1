#!/usr/bin/env bash
# Nettoie bootstrap.php corrompu (?> ou patch dupliqué) — réappliquer via misp-apply-bootstrap-fix.sh ensuite.
set -euo pipefail

CONTAINER="${MISP_CONTAINER:-forensic-misp}"
BOOT="/var/www/MISP/app/Config/bootstrap.php"
MARKER="FP_LOCALHOST_BASE_FIX"

if [ -f /var/www/MISP/app/Config/bootstrap.php ]; then
  _exec() { "$@"; }
else
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    echo "[misp-sanitize-bootstrap] Container $CONTAINER absent"
    exit 1
  fi
  # -i obligatoire : le heredoc python ci-dessous est passé via stdin
  _exec() { docker exec -i "$CONTAINER" "$@"; }
fi

_exec python3 - "$BOOT" "$MARKER" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
marker = sys.argv[2]
text = path.read_text(encoding="utf-8", errors="replace")
changed = False

if "?>" in text:
    text = text.split("?>", 1)[0].rstrip() + "\n"
    changed = True

while marker in text:
    text = text.split(marker, 1)[0].rstrip() + "\n"
    changed = True

lines = []
for line in text.splitlines():
    if "misp-bootstrap-localhost-fix.php" in line:
        changed = True
        continue
    lines.append(line)
text = "\n".join(lines).rstrip() + "\n"

if not text.lstrip().startswith("<?php"):
    text = "<?php\n" + text.lstrip()
    changed = True

path.write_text(text, encoding="utf-8")
print("[misp-sanitize-bootstrap] bootstrap.php nettoyé" if changed else "[misp-sanitize-bootstrap] déjà propre")
PY

_exec php -l "$BOOT" >/dev/null \
  && echo "[misp-sanitize-bootstrap] syntaxe OK" \
  || { echo "[misp-sanitize-bootstrap] ERREUR syntaxe" >&2; exit 1; }
