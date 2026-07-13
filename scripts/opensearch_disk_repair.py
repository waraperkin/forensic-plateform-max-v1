#!/usr/bin/env python3
"""Réparation disque OpenSearch — NON DESTRUCTIVE.

Cause fréquente d'un cluster RED / nœuds "unhealthy" sur une VM : le disque
dépasse le *flood stage watermark* (95% par défaut), OpenSearch passe alors
TOUS les index en lecture seule et bloque l'allocation des shards.

Ce script (aucune suppression d'index ni de volume) :
  1. configure les watermarks disque en valeurs absolues adaptées aux disques
     contraints (low/high/flood) — réglage de production recommandé ;
  2. lève le blocage read-only (`index.blocks.read_only_allow_delete`) ;
  3. relance l'allocation des shards (`reroute?retry_failed`).

Variables d'environnement :
  OS_URL        (def: http://localhost:9200)
  FP_WM_LOW     (def: 5gb)
  FP_WM_HIGH    (def: 3gb)
  FP_WM_FLOOD   (def: 2gb)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

OS_URL = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
# Valeurs ABSOLUES basses : permettent l'allocation des réplicas même sur un
# disque contraint (VM dont le disque est bien rempli). En dessous de FLOOD
# d'espace libre seulement, OpenSearch passe les index en lecture seule.
LOW = os.environ.get("FP_WM_LOW", "2gb")
HIGH = os.environ.get("FP_WM_HIGH", "1gb")
FLOOD = os.environ.get("FP_WM_FLOOD", "512mb")


def _req(method: str, path: str, payload=None, timeout: int = 30):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        OS_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode()


def main() -> int:
    wm = {
        "cluster.routing.allocation.disk.threshold_enabled": True,
        "cluster.routing.allocation.disk.watermark.low": LOW,
        "cluster.routing.allocation.disk.watermark.high": HIGH,
        "cluster.routing.allocation.disk.watermark.flood_stage": FLOOD,
    }
    try:
        st, _ = _req("PUT", "/_cluster/settings", {"persistent": wm, "transient": dict(wm)})
        print(f"[os-disk] watermarks low={LOW} high={HIGH} flood={FLOOD} -> HTTP {st}")
    except Exception as exc:  # noqa: BLE001
        print(f"[os-disk] ERREUR maj watermarks: {exc}", file=sys.stderr)
        return 1

    # Lever le blocage read-only (flood stage). Possible même en flood.
    for setting in ("index.blocks.read_only_allow_delete", "index.blocks.read_only"):
        try:
            st, _ = _req("PUT", "/_all/_settings", {setting: None})
            print(f"[os-disk] {setting}=null -> HTTP {st}")
        except Exception as exc:  # noqa: BLE001
            print(f"[os-disk] WARN clear {setting}: {exc}", file=sys.stderr)

    # Relancer l'allocation des shards en échec.
    try:
        _req("POST", "/_cluster/reroute?retry_failed=true", {})
        print("[os-disk] reroute?retry_failed envoyé")
    except Exception as exc:  # noqa: BLE001
        print(f"[os-disk] WARN reroute: {exc}", file=sys.stderr)

    try:
        _, body = _req("GET", "/_cluster/health")
        h = json.loads(body)
        print(
            f"[os-disk] health: {h.get('status')} "
            f"unassigned={h.get('unassigned_shards')} "
            f"active%={h.get('active_shards_percent_as_number')}"
        )
    except Exception:  # noqa: BLE001
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
