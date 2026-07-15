#!/usr/bin/env bash
# Vérifie que .env.example utilise les clés Docker canoniques (pas de traduction FR).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EX="$ROOT/.env.example"
fail=0

for key in POSTGRES_PASSWORD PUBLIC_HOST CERT_PORTAL_SECRET MINIO_ROOT_PASSWORD; do
  if grep -qE "^${key}=" "$EX"; then
    echo "PASS: $key présent dans .env.example"
  else
    echo "FAIL: $key absent de .env.example" >&2
    fail=1
  fi
done

for bad in MOT_DE_PASSE HÔTE_PUBLIC CONNECTEUR_ NOM_HÔTE; do
  if grep -qE "^${bad}" "$EX" 2>/dev/null; then
    echo "FAIL: clé traduite '$bad' dans .env.example" >&2
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "Env canonical OK"
else
  exit 1
fi
