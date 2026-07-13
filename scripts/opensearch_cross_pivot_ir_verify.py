#!/usr/bin/env python3
"""Vérifie cross-tool, pivots SOC, IR, cohérence IOC OpenCTI/MISP."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests
from fp_runtime_env import OPENSEARCH_URL, OSD_URL

ROOT = Path(__file__).resolve().parent.parent
OSD = OSD_URL

sys.path.insert(0, str(ROOT / "scripts"))
from opensearch_ti_truth import collect_truth  # noqa: E402
from osd_cross_pivot_lib import CROSS_TOOL_SEARCHES, PIVOT_SEARCHES  # noqa: E402
from osd_drilldown_lib import FP_DASHBOARDS, is_drill_panel_id  # noqa: E402


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def get_panel_metric_value(s: requests.Session, dash_id: str, panel_id: str) -> int | None:
    """Approximation via search API sur viz - lit le visState type metric/cardinality."""
    r = s.get(f"{OSD}/api/saved_objects/visualization/{panel_id}", headers=hdrs(), timeout=20)
    if r.status_code != 200:
        return None
    return 0  # présence OK


def main() -> int:
    s = requests.Session()
    s.verify = False
    problems: list[str] = []

    truth = collect_truth()
    print("[cross-pivot-ir] Truth:", json.dumps(truth, indent=2)[:800])

    # Cohérence IOC : dashboard doit utiliser index canoniques
    for pid in ("fp-ti-viz-opencti-count", "fp-ti-viz-misp-count", "fp-ti-viz-opencti-docs", "fp-ti-viz-misp-docs"):
        r = s.get(f"{OSD}/api/saved_objects/visualization/{pid}", headers=hdrs(), timeout=20)
        if r.status_code != 200:
            problems.append(f"viz {pid} manquante")
            continue
        ss = json.loads(r.json()["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
        idx = ss.get("index", "")
        if pid.startswith("fp-ti-viz-opencti") and idx != "fp-ti-opencti":
            problems.append(f"{pid} index={idx} attendu fp-ti-opencti")
        if pid.startswith("fp-ti-viz-misp") and idx != "fp-ti-misp":
            problems.append(f"{pid} index={idx} attendu fp-ti-misp")
        print(f"[cross-pivot-ir] OK {pid} -> index {idx}")

    # Pas de pattern forensic-ti-* sur métriques TI (inclut unified)
    r = s.get(f"{OSD}/api/saved_objects/visualization/fp-ti-viz-opencti-count", headers=hdrs(), timeout=20)
    if r.status_code == 200:
        refs = r.json().get("references", [])
        ref_idx = next((x["id"] for x in refs if x["type"] == "index-pattern"), "")
        if ref_idx == "fp-ti":
            problems.append("opencti count utilise encore fp-ti (inclut unified)")

    unified = truth.get("warning_unified_docs", 0)
    all_pat = truth.get("warning_all_ti_pattern_docs", 0)
    opencti_docs = truth["opencti"]["os_docs_canonical"]
    if all_pat > 0 and opencti_docs > 0:
        ratio = all_pat / max(opencti_docs, 1)
        if ratio > 1.5:
            print(f"[cross-pivot-ir] WARN pattern forensic-ti-* ({all_pat}) >> canonique opencti ({opencti_docs}) - dashboards exclus unified")

    # Cross-tool searches
    for sid, title, idx, q, cols in CROSS_TOOL_SEARCHES:
        sr = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=15)
        if sr.status_code != 200:
            problems.append(f"cross-tool search {sid} manquant")

    # Pivot searches
    for sid, title, idx, q, cols in PIVOT_SEARCHES:
        sr = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=15)
        if sr.status_code != 200:
            problems.append(f"pivot search {sid} manquant")

    # Dashboards : cross bar + drill
    for dash_id in FP_DASHBOARDS:
        dr = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=20)
        if dr.status_code != 200:
            problems.append(f"dashboard {dash_id} HTTP {dr.status_code}")
            continue
        panels = json.loads(dr.json()["attributes"]["panelsJSON"])
        pids = [p["panelIndex"] for p in panels]
        if dash_id == "fp-ti-overview" and "fp-cross-discover" not in pids:
            problems.append(f"{dash_id}: barre cross-tool absente")
        if dash_id == "fp-opensearch-security" and "fp-pivot-ip" not in pids:
            problems.append(f"{dash_id}: pivots absents")
        if not any(is_drill_panel_id(x) for x in pids):
            problems.append(f"{dash_id}: aucun drill-down/cross")
        print(f"[cross-pivot-ir] OK {dash_id} ({len(panels)} panels)")

    # IR metadata index
    tr = __import__("requests").Session()
    tr.verify = False
    trr = tr.post(
        f"{OPENSEARCH_URL}/forensic-timesketch*/_search",
        json={"size": 1, "query": {"term": {"metric_type": "ir_case"}}},
        timeout=20,
    )
    if trr.status_code == 200 and trr.json()["hits"]["total"]["value"] == 0:
        print("[cross-pivot-ir] WARN aucun ir_case dans timesketch-metrics (lancer ir-auto-case)")

    # drilldown verify subprocess
    pr = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opensearch_drilldown_verify.py")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if pr.returncode != 0:
        problems.append("opensearch_drilldown_verify a échoué")

    # UI shells
    for path, label in [
        ("/app/dashboards#/view/fp-ti-overview", "TI Overview"),
        ("/app/dashboards#/view/fp-opensearch-security", "Security"),
        ("/app/alerting#/dashboard?alertState=ALL", "Alerting"),
    ]:
        code = s.get(f"{OSD}{path}", headers=hdrs(), timeout=25).status_code
        if code != 200:
            problems.append(f"UI {label} HTTP {code}")

    if problems:
        print(f"[cross-pivot-ir] Bilan: {len(problems)} problème(s)", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[cross-pivot-ir] Bilan: 0 problème(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
