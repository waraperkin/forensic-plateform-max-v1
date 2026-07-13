#!/usr/bin/env bash
# Importe les définitions d'artefacts officielles Velociraptor (upstream YAML).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${ROOT}/artifacts/official"
TMP="${TMPDIR:-/tmp}/vr-artifacts-import-$$"
REPO="${VR_ARTIFACTS_REPO:-https://github.com/Velocidex/velociraptor.git}"
REF="${VR_ARTIFACTS_REF:-master}"

mkdir -p "$TARGET"
rm -rf "$TMP"
echo "[import] Clone shallow $REPO ($REF)…"
git clone --depth 1 --branch "$REF" "$REPO" "$TMP"

copied=0
for sub in artifacts/definitions artifacts/pro_definitions artifact_definitions; do
  if [ -d "$TMP/$sub" ]; then
    echo "[import] Copie récursive $sub → $TARGET"
    find "$TMP/$sub" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 | while IFS= read -r -d '' f; do
      rel="${f#"$TMP/$sub/"}"
      dest="$TARGET/$rel"
      mkdir -p "$(dirname "$dest")"
      cp "$f" "$dest"
    done
  fi
done

count="$(find "$TARGET" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l | tr -d ' ')"
rm -rf "$TMP"
echo "[import] Terminé — $count fichier(s) YAML dans $TARGET"
if [ "$count" = "0" ]; then
  echo "[import] AVERTISSEMENT: aucun artefact copié — vérifier la structure du dépôt upstream." >&2
  exit 1
fi
