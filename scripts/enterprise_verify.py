#!/usr/bin/env python3
"""Vérifie les 5 modules Enterprise FP."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests
from fp_runtime_env import OPENSEARCH_URL, OSD_URL

ROOT = Path(__file__).resolve().parent.parent
OS = OPENSEARCH_URL
OSD = OSD_URL

sys.path.insert(0, str(ROOT / "scripts"))


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def main() -> int:
    s = session()
    problems: list[str] = []

    # 1. Cluster
    h = s.get(f"{OS}/_cluster/health", timeout=20).json()
    status = h.get("status", "red")
    unassigned = h.get("unassigned_shards", 99)
    print(f"[enterprise] cluster: {status} unassigned={unassigned}")
    if status == "red":
        problems.append("cluster RED")
    if unassigned > 0:
        problems.append(f"{unassigned} unassigned shards")
    shards = s.get(f"{OS}/_cat/shards?format=json", timeout=30).json()
    bad = [x for x in shards if x.get("state") not in ("STARTED", "UNASSIGNED")]
    if bad:
        problems.append(f"{len(bad)} shards non-STARTED")
    else:
        print("[enterprise] OK 0 shard failed")

    # 2. MITRE
    mr = s.post(f"{OS}/fp-mitre-coverage/_count", timeout=15)
    if mr.status_code == 200 and mr.json().get("count", 0) >= 10:
        print(f"[enterprise] OK MITRE docs={mr.json()['count']}")
    else:
        problems.append("MITRE index vide")

    # 3. Sigma monitors
    sr = s.post(f"{OS}/_plugins/_alerting/monitors/_search", json={"size": 1000, "query": {"match_all": {}}}, timeout=60)
    n = sum(1 for h in sr.json().get("hits", {}).get("hits", []) if "FP-SIGMA" in h.get("_source", {}).get("name", "")) if sr.status_code == 200 else 0
    yaml_n = len(list((ROOT / "rules" / "sigma" / "generated").glob("*.yml"))) if (ROOT / "rules" / "sigma" / "generated").exists() else 0
    if n >= 50 and yaml_n >= 50:
        print(f"[enterprise] OK Sigma monitors={n} yaml={yaml_n}")
    else:
        problems.append(f"Sigma monitors={n} yaml={yaml_n}")

    # 4. Threat hunting
    from osd_enterprise_lib import THREAT_HUNTS  # noqa: E402

    hunt_ok = 0
    for sid, *_ in THREAT_HUNTS:
        r = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=15)
        if r.status_code == 200:
            hunt_ok += 1
    if hunt_ok >= 5:
        print(f"[enterprise] OK hunts={hunt_ok}")
    else:
        problems.append(f"hunts OSD={hunt_ok}")

    # 5. Forensic fusion
    fr = s.post(f"{OS}/forensic-fusion-metrics/_count", timeout=15)
    if fr.status_code == 200 and fr.json().get("count", 0) > 0:
        print(f"[enterprise] OK fusion events={fr.json()['count']}")
    else:
        problems.append("fusion index vide")

    # 6. CTI enrich
    er = s.post(f"{OS}/forensic-ti-enriched/_count", timeout=15)
    if er.status_code == 200 and er.json().get("count", 0) > 0:
        print(f"[enterprise] OK CTI enriched={er.json()['count']}")
    else:
        problems.append("CTI enriched vide")

    # 7. UX / dashboards
    for dash_id, label in [
        ("fp-mitre-dashboard", "MITRE"),
        ("fp-threat-hunting", "Threat Hunting"),
        ("fp-ti-overview", "TI Overview"),
        ("fp-opensearch-security", "Security"),
    ]:
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"dashboard {label} absent")
        else:
            ui = s.get(f"{OSD}/app/dashboards#/view/{dash_id}", headers=hdrs(), timeout=25)
            if ui.status_code != 200:
                problems.append(f"UI {label} HTTP {ui.status_code}")
            else:
                print(f"[enterprise] OK dashboard {label}")

    # 8. Enrich viz
    for vid in ("fp-ti-viz-threat-score", "fp-mitre-heatmap", "fp-fusion-open"):
        r = s.get(f"{OSD}/api/saved_objects/{'search' if 'fusion' in vid else 'visualization'}/{vid}", headers=hdrs(), timeout=15)
        if r.status_code != 200:
            problems.append(f"objet {vid} absent")

    # 9. cross-pivot verify (restore refs puis re-patch barres 18 playbooks)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "opensearch_restore_dashboard_refs.py")], cwd=str(ROOT), timeout=120)
    from fp_playbooks_common import patch_all_fp_dashboards  # noqa: E402

    patch_all_fp_dashboards(s)
    pr = subprocess.run([sys.executable, str(ROOT / "scripts" / "opensearch_cross_pivot_ir_verify.py")], capture_output=True, text=True, timeout=120)
    if pr.returncode != 0:
        problems.append("cross-pivot-ir-verify failed")

    if problems:
        print(f"[enterprise] Bilan: {len(problems)} problème(s)", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[enterprise] Bilan: 0 problème(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
