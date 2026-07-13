#!/usr/bin/env bash
set -euo pipefail
export TIMESKETCH_CONFIG_FILE="${TIMESKETCH_CONFIG_FILE:-/etc/timesketch/timesketch.conf}"
export PATH="/opt/venv/bin:${PATH}"
echo "[timesketch-init] attente API timesketch-web..."
for _ in $(seq 1 120); do
  if python3 -c "import urllib.request; urllib.request.urlopen('http://timesketch-web:5000/login', timeout=3).read(1)" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
sleep 8
set +e
tsctl create-user --password "${TIMESKETCH_PASSWORD}" "${TIMESKETCH_USER}"
rc=$?
set -e
if [[ "${rc}" -ne 0 ]]; then
  echo "[timesketch-init] tsctl create-user code=${rc} (utilisateur peut déjà exister)"
fi
echo "[timesketch-init] OK"
exit 0
