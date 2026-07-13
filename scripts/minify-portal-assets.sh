#!/usr/bin/env bash
# Minification additif des assets portal-shared (JS + CSS).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JS_DIR="$ROOT/portal-shared/js"
CSS_DIR="$ROOT/portal-shared/css"
MIN_JS="$JS_DIR/min"
MIN_CSS="$CSS_DIR/min"
mkdir -p "$MIN_JS" "$MIN_CSS"

minify_js() {
  local src="$1"
  local base
  base="$(basename "$src")"
  local out="$MIN_JS/${base%.js}.min.js"
  if command -v terser >/dev/null 2>&1; then
    terser "$src" -c -m -o "$out"
  elif command -v npx >/dev/null 2>&1; then
    npx --yes terser "$src" -c -m -o "$out" 2>/dev/null || cp "$src" "$out"
  else
    tr -d '\n' < "$src" | sed 's/  */ /g' > "$out" || cp "$src" "$out"
  fi
}

minify_css() {
  local src="$1"
  local base
  base="$(basename "$src")"
  local out="$MIN_CSS/${base%.css}.min.css"
  if command -v npx >/dev/null 2>&1; then
    npx --yes clean-css-cli -o "$out" "$src" 2>/dev/null || cp "$src" "$out"
  else
    tr -d '\n' < "$src" | sed 's/  */ /g' > "$out" || cp "$src" "$out"
  fi
}

for f in "$JS_DIR"/*.js; do
  [[ -f "$f" ]] || continue
  [[ "$f" == *"/min/"* ]] && continue
  minify_js "$f"
done

for f in "$CSS_DIR"/*.css; do
  [[ -f "$f" ]] || continue
  [[ "$f" == *"/min/"* ]] && continue
  minify_css "$f"
done

echo "Minified assets → $MIN_JS and $MIN_CSS"
