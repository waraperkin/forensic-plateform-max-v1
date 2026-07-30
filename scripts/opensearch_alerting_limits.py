#!/usr/bin/env python3
"""Monte la limite de monitors OpenSearch Alerting (défaut 1000 → 10000).

Cause racine P07 (audit déploiement) : le cluster atteignait 1000 monitors
actifs (détection rules + TI + …) AVANT la passe Sigma — chaque création
FP-SIGMA-* était alors rejetée en HTTP 400 (« exceeds the maximum number of
monitors »), bloquant les monitors Sigma à 290/400.

Le réglage `plugins.alerting.monitor.max_monitors` est dynamique : on le pousse
en persistent + transient via _cluster/settings (idempotent). opensearch.yml
porte aussi la valeur statique pour les clusters frais.
"""
from __future__ import annotations

import os
import sys

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
MAX_MONITORS = int(os.environ.get("FP_ALERTING_OS_MAX", "10000"))


def main() -> int:
    s = requests.Session()
    s.verify = False
    body = {
        "persistent": {"plugins.alerting.monitor.max_monitors": MAX_MONITORS},
        "transient": {"plugins.alerting.monitor.max_monitors": MAX_MONITORS},
    }
    try:
        r = s.put(f"{OS}/_cluster/settings", json=body, timeout=20)
    except requests.RequestException as exc:
        print(f"[alerting-limits] KO OpenSearch injoignable ({exc})", file=sys.stderr)
        return 1
    if r.status_code != 200:
        print(f"[alerting-limits] KO PUT _cluster/settings HTTP {r.status_code}: {r.text[:200]}", file=sys.stderr)
        return 1
    # Vérification réelle de la prise en compte.
    g = s.get(f"{OS}/_cluster/settings?include_defaults=true", timeout=20)
    effective = None
    if g.status_code == 200:
        for section in ("persistent", "transient", "defaults"):
            effective = (
                g.json().get(section, {}).get("plugins", {}).get("alerting", {}).get("monitor", {}).get("max_monitors")
                or effective
            )
    print(f"[alerting-limits] OK plugins.alerting.monitor.max_monitors={MAX_MONITORS} (effectif: {effective})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
