#!/bin/sh
# Wrapper AlienVault : les clés placeholder installer (Fp_*) ou invalides OTX
# font planter le connecteur en boucle SIGTERM (exit 143) dès "Fetching subscribed
# pulses..." (validation V06). Sans clé réelle on reste Up en idle au lieu de
# restart-looper ; avec une clé valide on lance le binaire officiel.
set -eu
cd /opt/opencti-connector-alienvault

key="${ALIENVAULT_API_KEY:-}"
is_placeholder=0
case "$key" in
  ""|Fp_*) is_placeholder=1 ;;
esac

probe_otx() {
  # 0 = clé acceptée par OTX ; 1 = absente/placeholder/refusée/réseau
  [ "$is_placeholder" -eq 1 ] && return 1
  python3 - "$key" <<'PY'
import sys, urllib.request
key = sys.argv[1]
req = urllib.request.Request(
    "https://otx.alienvault.com/api/v1/user/me",
    headers={"X-OTX-API-KEY": key},
)
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        sys.exit(0 if 200 <= r.status < 300 else 1)
except Exception:
    sys.exit(1)
PY
}

if ! probe_otx; then
  echo "[alienvault-entrypoint] ALIENVAULT_API_KEY absente, placeholder (Fp_*) ou refusée par OTX."
  echo "[alienvault-entrypoint] Idle stable (pas de crash-loop). Fournissez une clé OTX réelle puis recreate."
  # Boucle idle : garde le conteneur Up (restart: unless-stopped) sans appeler OTX.
  while true; do
    sleep 3600
  done
fi

echo "[alienvault-entrypoint] Clé OTX acceptée — démarrage connecteur."
exec python main.py
