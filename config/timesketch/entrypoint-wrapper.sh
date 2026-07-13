#!/bin/bash
# Applique le patch explore (évite Server side error UI) puis démarre Timesketch
set -e
if [ -f /opt/fp-timesketch/apply-explore-patch.sh ]; then
  bash /opt/fp-timesketch/apply-explore-patch.sh || true
fi
exec /docker-entrypoint.sh "$@"
