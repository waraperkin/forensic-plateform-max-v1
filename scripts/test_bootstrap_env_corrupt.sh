#!/usr/bin/env bash
# Simule un .env corrompu (clés traduites) et vérifie la réparation bootstrap.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$(mktemp -d)"
TEST_IP="192.168.2.99"
trap 'rm -rf "$WORKDIR"' EXIT

export DIR="$WORKDIR"
export FP_LOG_INSTALL="$WORKDIR/install.log"
mkdir -p "$WORKDIR/logs"
cp "$ROOT/.env.example" "$WORKDIR/.env.example"
cp "$ROOT/.env.example" "$WORKDIR/.env"
{
  echo "MOT_DE_PASSE_POSTGRES=legacy-should-vanish"
  echo "HÔTE_PUBLIC=203.0.113.99"
  echo "CONNECTEUR_CISA_KEV_ID=00000000-0000-0000-0000-000000000099"
} >> "$WORKDIR/.env"

# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/installer.sh"

fp_detect_public_host() { echo "$TEST_IP"; }
fp_detect_public_ip() { echo "$TEST_IP"; }
fp_url_identity() { echo "$TEST_IP"; }

_fp_bootstrap_env_complete

# P-04 : les secrets sont générés ALÉATOIREMENT à chaque bootstrap — on vérifie
# qu'ils sont remplis, différents de la valeur legacy migrée, jamais vides.
pg=$(grep -E '^POSTGRES_PASSWORD=' "$WORKDIR/.env" | cut -d= -f2-)
[ -n "$pg" ] || { echo "FAIL: POSTGRES_PASSWORD vide"; exit 1; }
[ "$pg" != "legacy-should-vanish" ] || { echo "FAIL: POSTGRES_PASSWORD = valeur legacy migrée"; exit 1; }
portal=$(grep -E '^CERT_PORTAL_SECRET=' "$WORKDIR/.env" | cut -d= -f2-)
[ -n "$portal" ] || { echo "FAIL: CERT_PORTAL_SECRET vide"; exit 1; }
grep -qE "^PUBLIC_HOST=${TEST_IP}" "$WORKDIR/.env" || { echo "FAIL: PUBLIC_HOST=$TEST_IP"; exit 1; }
grep -qE '^CONNECTOR_CISA_KEV_ID=' "$WORKDIR/.env" || { echo "FAIL: CONNECTOR_CISA_KEV_ID absent"; exit 1; }

for bad in '^MOT_DE_PASSE_POSTGRES=' '^HÔTE_PUBLIC=' '^HOTE_PUBLIC=' '^CONNECTEUR_'; do
  if grep -qE "$bad" "$WORKDIR/.env"; then
    echo "FAIL: clé legacy encore présente ($bad)" >&2
    exit 1
  fi
done

echo "PASS: bootstrap répare .env corrompu (clés FR → canoniques + secrets aléatoires P-04)"
