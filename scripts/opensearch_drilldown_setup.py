#!/usr/bin/env python3
"""
Applique le drill-down premium sur tous les dashboards / visualisations FP.
Rebuild NDJSON → import → patch API live.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OSD_NGINX = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")

sys.path.insert(0, str(ROOT / "scripts"))
from fp_http_lib import request_retry, wait_osd  # noqa: E402
from osd_drilldown_lib import (  # noqa: E402
    FP_DASHBOARDS,
    SAMPLE_VIZ_UUID_DRILL,
    VIZ_DRILL,
    apply_drill_panels_to_dashboard_json,
    drill_search_id,
    saved_search_attrs,
    viz_embeddable_config,
)
from osd_vis_lib import vis_histogram, vis_pie  # noqa: E402


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def ok(msg: str) -> None:
    print(f"[drilldown-setup] OK {msg}")


def ko(msg: str) -> None:
    print(f"[drilldown-setup] KO {msg}", file=sys.stderr)


def upsert_search(s: requests.Session, sid: str, title: str, idx: str, q: str, cols: list[str]) -> bool:
    attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
    for method in ("PUT", "POST"):
        r = s.request(
            method,
            f"{OSD}/api/saved_objects/search/{sid}",
            headers=hdrs(),
            json={"attributes": attrs, "references": refs},
            timeout=60,
            verify=False,
        )
        if r.status_code in (200, 201):
            return True
    return False


def enrich_visualization(s: requests.Session, vid: str) -> bool:
    r = s.get(f"{OSD}/api/saved_objects/visualization/{vid}", headers=hdrs(), timeout=60, verify=False)
    if r.status_code != 200:
        return False
    body = r.json()
    attrs = body["attributes"]
    ui = json.loads(attrs.get("uiStateJSON") or "{}")
    ui["drilldown"] = {"enabled": True, "note": "Clic segment → filtre dashboard ; panel Discover associé"}
    attrs["uiStateJSON"] = json.dumps(ui)
    attrs["description"] = (
        (attrs.get("description") or "")
        + " [FP drill-down: clic chart → filtre ; panel Discover ↳ ci-dessous]"
    ).strip()
    pr = s.put(
        f"{OSD}/api/saved_objects/visualization/{vid}",
        headers=hdrs(),
        json={"attributes": attrs, "references": body.get("references", [])},
        timeout=25,
        verify=False,
    )
    return pr.status_code in (200, 201)


def apply_dashboard_drill(s: requests.Session, dash_id: str) -> int:
    r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=25, verify=False)
    if r.status_code != 200:
        ko(f"dashboard {dash_id} introuvable")
        return 1

    dash = r.json()
    panels = json.loads(dash["attributes"]["panelsJSON"])
    refs = list(dash.get("references", []))
    ref_names = {x["name"] for x in refs}

    # Upsert toutes les searches nécessaires
    for p in panels:
        pid = p["panelIndex"]
        if pid in VIZ_DRILL:
            idx, q, cols = VIZ_DRILL[pid]
            sid = drill_search_id(pid)
            if not upsert_search(s, sid, f"Discover ↳ {pid}", idx, q, cols):
                ko(f"search {sid}")
                return 1

    from osd_drilldown_lib import DASHBOARD_GLOBAL_SEARCHES  # noqa: E402

    for spec in DASHBOARD_GLOBAL_SEARCHES.get(dash_id, []):
        sid, title, idx, q, cols = spec
        if not upsert_search(s, sid, title, idx, q, cols):
            ko(f"search globale {sid}")
            return 1

    enriched, extra_refs = apply_drill_panels_to_dashboard_json(panels, dash_id)
    dash["attributes"]["panelsJSON"] = json.dumps(enriched)

    for p in enriched:
        pid = p["panelIndex"]
        rn = f"panel_{pid}"
        if pid.startswith(
            ("fp-drill-", "fp-search-", "fp-obs-search-", "fp-cross-", "fp-pivot-", "fp-hunt-", "fp-fusion-", "fp-nav-", "fp-story-", "fp-ir-")
        ):
            rtype, rid = "search", pid
        else:
            rtype, rid = "visualization", pid
        if rn not in ref_names:
            refs.append({"name": rn, "type": rtype, "id": rid})
            ref_names.add(rn)
    for er in extra_refs:
        if er["name"] not in ref_names:
            refs.append(er)
            ref_names.add(er["name"])

    ur = s.put(
        f"{OSD}/api/saved_objects/dashboard/{dash_id}",
        headers=hdrs(),
        json={"attributes": dash["attributes"], "references": refs},
        timeout=40,
        verify=False,
    )
    if ur.status_code in (200, 201):
        n_search = sum(1 for p in enriched if p["panelIndex"].startswith(("fp-drill-", "fp-search-", "fp-obs-search-")))
        ok(f"{dash_id} — {len(enriched)} panels ({n_search} Discover)")
        return 0
    ko(f"{dash_id} PUT {ur.status_code}")
    return 1


def fix_sample_uuid_viz(s: requests.Session) -> int:
    fails = 0
    specs = {
        "19717e00-228f-11ee-b88b-47a93b5c527c": ("pie", "FP — Windows event.code", "fp-events", "_index:forensic-windows*", "event.code"),
        "fa54ce40-eb7b-11ed-8e00-17d7d50cd7b2": ("histogram", "FP — Events per day", "fp-events", "*", "@timestamp"),
        "009fd930-22a8-11ee-b88b-47a93b5c527c": ("pie", "FP — Linux top tags", "fp-events", "_index:forensic-linux*", "tags.keyword"),
        "571745a0-eb99-11ed-8e00-17d7d50cd7b2": ("pie", "FP — TI by source", "fp-ti", "*", "source"),
        "9482ed20-eb9b-11ed-8e00-17d7d50cd7b2": ("histogram", "FP — TI matches per day", "fp-events", "ti_match: true", "@timestamp"),
    }
    for vid, spec in specs.items():
        kind, title, idx, q, field = spec
        if kind == "pie":
            obj = vis_pie(vid, title, idx, q, field)
        else:
            obj = vis_histogram(vid, title, idx, q, field)
        obj["attributes"]["description"] = "FP drill-down — clic segment pour filtrer ; ouvrir Discover"
        for method in ("PUT", "POST"):
            r = s.request(
                method,
                f"{OSD}/api/saved_objects/visualization/{vid}",
                headers=hdrs(),
                json={"attributes": obj["attributes"], "references": obj["references"]},
                timeout=25,
                verify=False,
            )
            if r.status_code in (200, 201):
                ok(f"viz UUID {vid[:8]}…")
                break
        else:
            ko(f"viz UUID {vid}")
            fails += 1
        if vid in SAMPLE_VIZ_UUID_DRILL:
            idx2, q2, cols = SAMPLE_VIZ_UUID_DRILL[vid]
            sid = f"fp-drill-uuid-{vid[:8]}"
            upsert_search(s, sid, f"Discover ↳ {title}", idx2, q2, cols)
    return fails


def run_imports() -> int:
    fails = 0
    scripts = [
        "build_opensearch_dashboards.py",
        "build_opensearch_siem_ti_dashboards.py",
        "build_opensearch_observability.py",
    ]
    for sc in scripts:
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / sc)], cwd=str(ROOT), timeout=120)
        if r.returncode != 0:
            ko(f"{sc}")
            fails += 1
        else:
            ok(sc)

    imports = [
        "opensearch_dashboards_import_fp.sh",
        "opensearch_dashboards_import_ti.sh",
        "opensearch_dashboards_import_obs.sh",
        "opensearch_dashboards_import_enterprise.sh",
        "opensearch_dashboards_import_playbook.sh",
    ]
    for sh in imports:
        path = ROOT / "scripts" / sh
        if not path.exists():
            continue
        r = subprocess.run(["bash", str(path)], cwd=str(ROOT), timeout=300)
        if r.returncode != 0:
            ko(sh)
            fails += 1
        else:
            ok(sh)
    return fails


def main() -> int:
    global OSD
    s = requests.Session()
    s.verify = False
    base = wait_osd(s, [OSD, OSD_NGINX], timeout_total=300)
    if not base:
        ko("OpenSearch Dashboards inaccessible — abandon drilldown")
        return 1
    OSD = base
    ok(f"OSD prêt — {base}")

    fails = run_imports()

    for dash_id in FP_DASHBOARDS:
        fails += apply_dashboard_drill(s, dash_id)

    for vid in VIZ_DRILL:
        if not enrich_visualization(s, vid):
            ko(f"enrich viz {vid}")

    fails += fix_sample_uuid_viz(s)

    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opensearch_observability_setup.py")],
        cwd=str(ROOT),
        timeout=120,
        check=False,
    )
    ok("observability setup")

    # Map TI (depuis analyst fix)
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "osd_analyst_targets_fix.py")],
        cwd=str(ROOT),
        timeout=300,
        check=False,
    )

    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opensearch_refresh_index_pattern.py")],
        cwd=str(ROOT),
        timeout=180,
        check=False,
    )

    print(f"[drilldown-setup] Bilan: {fails} étape(s) en échec")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
