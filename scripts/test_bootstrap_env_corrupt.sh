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

grep -qE '^POSTGRES_PASSWORD=F0r3ns1c_PG_2024!' "$WORKDIR/.env" || { echo "FAIL: POSTGRES_PASSWORD"; exit 1; }
grep -qE '^CERT_PORTAL_SECRET=F0r3ns1c_Portal_2024!' "$WORKDIR/.env" || { echo "FAIL: CERT_PORTAL_SECRET"; exit 1; }
grep -qE "^PUBLIC_HOST=${TEST_IP}" "$WORKDIR/.env" || { echo "FAIL: PUBLIC_HOST=$TEST_IP"; exit 1; }
grep -qE '^CONNECTOR_CISA_KEV_ID=' "$WORKDIR/.env" || { echo "FAIL: CONNECTOR_CISA_KEV_ID absent"; exit 1; }

for bad in '^MOT_DE_PASSE_POSTGRES=' '^HÔTE_PUBLIC=' '^HOTE_PUBLIC=' '^CONNECTEUR_'; do
  if grep -qE "$bad" "$WORKDIR/.env"; then
    echo "FAIL: clé legacy encore présente ($bad)" >&2
    exit 1
  fi
done

echo "PASS: bootstrap répare .env corrompu (clés FR → canoniques + secrets labo)"
