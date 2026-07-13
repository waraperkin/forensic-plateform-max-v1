#!/usr/bin/env python3
"""Cluster Repair & Shard Recovery — indices cassés, reroute, index patterns FP."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
ROOT = Path(__file__).resolve().parent.parent

# Patterns FP autorisés (évite opencti_inferred_* / indices internes UUID)
FP_SAFE_PATTERNS = {
    "fp-events": "forensic-windows-*,forensic-linux-*,forensic-web-*,forensic-network-*,forensic-cloud-*,forensic-endpoint-*,forensic-macos-*,forensic-firewall-*",
    "fp-logs": "forensic-uploads*,fp-platform-logs*,forensic-alerts*",
    "fp-ti": "forensic-ti-opencti-*,forensic-ti-misp-*",
    "fp-ti-opencti": "forensic-ti-opencti-*",
    "fp-ti-misp": "forensic-ti-misp-*",
    "fp-timesketch": "forensic-timesketch*,forensic-tokens-*",
    "fp-fusion": "forensic-fusion-*",
    "fp-mitre": "fp-mitre-*",
    "fp-ti-enriched": "forensic-ti-enriched-*",
}

UUID_INDEX = re.compile(r"^[0-9a-f]{32}$")


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def cluster_health(s: requests.Session) -> dict:
    r = s.get(f"{OS}/_cluster/health", timeout=30)
    r.raise_for_status()
    return r.json()


def list_indices(s: requests.Session) -> list[dict]:
    r = s.get(f"{OS}/_cat/indices?format=json&bytes=b", timeout=60)
    r.raise_for_status()
    return r.json()


def list_shards(s: requests.Session) -> list[dict]:
    r = s.get(f"{OS}/_cat/shards?format=json", timeout=60)
    r.raise_for_status()
    return r.json()


def delete_index(s: requests.Session, name: str) -> bool:
    r = s.delete(f"{OS}/{name}", timeout=30)
    return r.status_code in (200, 404)


def reroute_retry(s: requests.Session) -> None:
    s.post(
        f"{OS}/_cluster/reroute",
        json={"commands": [{"retry_failed": True}]},
        timeout=30,
    )


def disk_repair_and_unblock(s: requests.Session) -> None:
    """Watermarks bas + déblocage read-only : indispensable sur disque contraint
    où les réplicas restent UNASSIGNED (low watermark). Non destructif."""
    import subprocess

    try:
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "opensearch_disk_repair.py")],
            cwd=str(ROOT), timeout=90, check=False,
        )
    except Exception:  # noqa: BLE001
        pass
    # Accélère la récupération des réplicas.
    try:
        s.put(
            f"{OS}/_cluster/settings",
            json={"transient": {
                "cluster.routing.allocation.node_concurrent_recoveries": 8,
                "indices.recovery.max_bytes_per_sec": "200mb",
            }},
            timeout=20,
        )
    except requests.RequestException:
        pass


def wait_allocation(s: requests.Session, timeout: int = 180) -> dict:
    """Attend (avec reroute périodique) que unassigned tombe à 0."""
    import time

    deadline = time.time() + timeout
    h = cluster_health(s)
    while time.time() < deadline:
        if int(h.get("unassigned_shards", 0)) == 0 and int(h.get("initializing_shards", 0)) == 0:
            return h
        reroute_retry(s)
        time.sleep(6)
        h = cluster_health(s)
    return h


def ensure_green_via_replica_tuning(s: requests.Session, timeout: int = 120) -> dict:
    """Garantit un cluster GREEN même sur disque/ressources contraints.

    Si — après attente — il reste des shards UNASSIGNED qui sont TOUS des
    réplicas (primaires actifs, donc YELLOW et données 100% disponibles), on
    réduit `number_of_replicas` à 0 sur les index concernés. C'est :
      • NON destructif (les primaires restent actifs, aucune donnée perdue) ;
      • réversible (on peut réaugmenter les réplicas quand le disque le permet) ;
      • cohérent avec le design du projet (la policy ISM réduit déjà les
        réplicas à 0 en état "warm").
    Sur une VM vierge avec assez de disque, les réplicas s'allouent dans le
    délai et cette fonction ne change RIEN (cluster déjà GREEN).
    """
    h = cluster_health(s)
    if h.get("status") == "green":
        return h
    shards = list_shards(s)
    # Réplicas (prirep == "r") non démarrés : UNASSIGNED ou INITIALIZING bloqués.
    bad_replicas = [
        x for x in shards
        if x.get("prirep") == "r" and x.get("state") in ("UNASSIGNED", "INITIALIZING")
    ]
    ua_primaries = [x for x in shards if x.get("state") == "UNASSIGNED" and x.get("prirep") == "p"]
    # On n'intervient QUE si le problème se limite aux réplicas (jamais si une
    # primaire est non allouée — cela relèverait d'un vrai incident à investiguer).
    if ua_primaries or not bad_replicas:
        return h
    idxs = sorted({x.get("index") for x in bad_replicas if x.get("index")})
    if not idxs:
        return h
    print(f"[cluster-repair] disque/ressources contraints : réduction réplicas→0 "
          f"sur {len(idxs)} index (réplicas non allouables) pour atteindre GREEN")
    # auto_expand_replicas (index système .opendistro-*/.kibana/...) force un
    # nombre de réplicas selon la taille du cluster et IGNORE number_of_replicas :
    # on le désactive AVANT de fixer les réplicas à 0. Non destructif, réversible.
    for i in range(0, len(idxs), 40):
        batch = ",".join(idxs[i:i + 40])
        try:
            s.put(f"{OS}/{batch}/_settings",
                  json={"index": {"auto_expand_replicas": "false", "number_of_replicas": 0}},
                  timeout=60)
        except requests.RequestException:
            pass
    reroute_retry(s)
    return wait_allocation(s, timeout)


def repair_closed_uuid_indices(s: requests.Session) -> list[str]:
    """Supprime indices internes fermés (UUID) — source fréquente de shard failed en UI."""
    removed: list[str] = []
    for row in list_indices(s):
        name = row.get("index", "")
        status = row.get("status", "")
        if status != "close":
            continue
        if UUID_INDEX.match(name) or name.startswith("."):
            if delete_index(s, name):
                removed.append(name)
                print(f"[cluster-repair] OK supprimé index fermé {name}")
    return removed


def repair_red_indices(s: requests.Session) -> list[str]:
    fixed: list[str] = []
    for row in list_indices(s):
        name = row.get("index", "")
        health = row.get("health", "")
        if health != "red":
            continue
        docs = int(row.get("docs.count", 0) or 0)
        if docs == 0 and not name.startswith("."):
            if delete_index(s, name):
                fixed.append(name)
                print(f"[cluster-repair] OK supprimé index red vide {name}")
    return fixed


def shard_report(s: requests.Session) -> dict:
    shards = list_shards(s)
    bad = [x for x in shards if x.get("state") not in ("STARTED", "UNASSIGNED")]
    unassigned = [x for x in shards if x.get("state") == "UNASSIGNED"]
    return {"total": len(shards), "bad": len(bad), "unassigned": len(unassigned), "bad_samples": bad[:10]}


def refresh_fp_index_patterns() -> int:
    import subprocess

    ids = list(FP_SAFE_PATTERNS.keys())
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opensearch_refresh_index_pattern.py"), *ids],
        cwd=str(ROOT),
        timeout=300,
    )
    return 0 if r.returncode == 0 else 1


def main() -> int:
    s = session()
    h0 = cluster_health(s)
    print(f"[cluster-repair] health initial: {h0.get('status')} unassigned={h0.get('unassigned_shards')}")

    removed = repair_closed_uuid_indices(s)
    fixed_red = repair_red_indices(s)
    # Auto-réparation disque/watermark + attente d'allocation des réplicas
    # (résout les UNASSIGNED dus au low watermark sur disque bien rempli).
    disk_repair_and_unblock(s)
    reroute_retry(s)
    wait_allocation(s, timeout=180)
    # Dernier recours pour GREEN sur hôte contraint : réduire les réplicas non
    # allouables (primaires intacts). No-op sur VM vierge (déjà GREEN).
    ensure_green_via_replica_tuning(s, timeout=120)

    sr = shard_report(s)
    print(f"[cluster-repair] shards: total={sr['total']} bad={sr['bad']} unassigned={sr['unassigned']}")
    if sr["bad_samples"]:
        for b in sr["bad_samples"]:
            print(f"  bad: {b.get('index')} shard={b.get('shard')} state={b.get('state')}")

    refresh_fp_index_patterns()

    h1 = cluster_health(s)
    status = h1.get("status", "red")
    print(f"[cluster-repair] health final: {status} active_shards={h1.get('active_shards')}")

    problems = []
    if status == "red":
        problems.append("cluster RED")
    if sr["unassigned"] > 0:
        problems.append(f"{sr['unassigned']} shard(s) unassigned")
    if sr["bad"] > 0:
        problems.append(f"{sr['bad']} shard(s) non-STARTED")

    summary = {
        "removed_closed": len(removed),
        "removed_red": len(fixed_red),
        "shard_report": sr,
        "health": h1,
    }
    print(json.dumps(summary, indent=2, default=str))

    if problems:
        print(f"[cluster-repair] WARN: {'; '.join(problems)}", file=sys.stderr)
        # YELLOW + réplicas UNASSIGNED seulement (disque/ressources) : données OK.
        shards = list_shards(s)
        ua_primaries = [
            x for x in shards
            if x.get("state") == "UNASSIGNED" and x.get("prirep") == "p"
        ]
        if status in ("green", "yellow") and sr["bad"] == 0 and not ua_primaries:
            print("[cluster-repair] OK cluster stable (primaires actives, réplicas optionnels)")
            return 0
        if status in ("green", "yellow") and sr["bad"] == 0 and sr["unassigned"] == 0:
            print("[cluster-repair] OK cluster stable (yellow acceptable)")
            return 0
        return 1
    print("[cluster-repair] OK cluster GREEN/YELLOW stable, 0 shard failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
