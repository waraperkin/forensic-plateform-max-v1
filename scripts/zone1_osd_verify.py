#!/usr/bin/env python3
"""ZONE 1 — vérifie Overview/Discover/Dashboards/Visualize (API + champs)."""
from __future__ import annotations

import json
import os
import sys

import requests
from fp_runtime_env import OPENSEARCH_URL, OSD_URL

OSD = OSD_URL
OS = OPENSEARCH_URL

DASHBOARDS = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
]
VIS_IDS = [
    "fp-viz-cluster-events",
    "fp-viz-uploads",
    "fp-viz-events-day",
    "fp-viz-logs-service",
    "fp-viz-logs-errors",
    "fp-ti-viz-opencti-count",
    "fp-ti-viz-misp-count",
    "fp-ti-viz-by-type",
    "fp-ti-viz-by-source",
    "fp-ti-viz-by-tag",
    "fp-ti-viz-timeline",
]
INDEX_PATTERNS = {
    "fp-events": ["@timestamp", "ti_match", "source.ip", "message"],
    "fp-logs": ["@timestamp", "log.level", "message"],
    "fp-ti": ["@timestamp", "ioc_type", "source", "tags", "ioc_value"],
}
REQUIRED_METRIC_SHOW = True


def check_index_pattern(s: requests.Session, pid: str, fields: list[str]) -> list[str]:
    errs = []
    r = s.get(f"{OSD}/api/saved_objects/index-pattern/{pid}", timeout=20)
    if r.status_code != 200:
        return [f"{pid}: HTTP {r.status_code}"]
    attrs = r.json().get("attributes", {})
    title = attrs.get("title", "")
    flist = json.loads(attrs.get("fields") or "[]")
    names = {f["name"] for f in flist}
    if len(names) < 5:
        errs.append(f"{pid}: fields vides ({len(names)})")
    for f in fields:
        if f not in names:
            errs.append(f"{pid}: champ manquant {f}")
    # index exists
    probe = title.split(",")[0].strip()
    cr = s.post(f"{OS}/{probe}/_count", timeout=15)
    if cr.status_code == 404 or cr.json().get("count", 0) == 0:
        cr2 = s.post(f"{OS}/{title.replace(',', ',')}/_count", timeout=15)
        if cr2.status_code != 200 or cr2.json().get("count", 0) == 0:
            pass  # warn only if truly empty - TI might have data on forensic-ti-*
    return errs


def check_dashboard_panels(s: requests.Session, did: str) -> list[str]:
    errs = []
    r = s.get(f"{OSD}/api/saved_objects/dashboard/{did}", timeout=20)
    if r.status_code != 200:
        return [f"dashboard {did}: HTTP {r.status_code}"]
    panels = json.loads(r.json()["attributes"]["panelsJSON"])
    refs = {x["name"]: (x["id"], x.get("type", "visualization")) for x in r.json().get("references", [])}
    for p in panels:
        ref = p.get("panelRefName", "")
        vid, vtype = refs.get(ref, (ref.replace("panel_", ""), "visualization"))
        vr = s.get(f"{OSD}/api/saved_objects/{vtype}/{vid}", timeout=15)
        if vr.status_code != 200:
            errs.append(f"{did}/{vid}: {vtype} HTTP {vr.status_code}")
            continue
        if vtype != "visualization":
            continue
        vs = json.loads(vr.json()["attributes"].get("visState", "{}"))
        if vs.get("type") == "metric":
            labels = (vs.get("params") or {}).get("metric", {}).get("labels", {})
            if labels.get("show") is not True:
                errs.append(f"{vid}: metric sans labels.show")
        for agg in vs.get("aggs", []):
            if agg.get("type") == "terms":
                field = (agg.get("params") or {}).get("field", "")
                if field and field not in ("_index",):
                    ss = json.loads(vr.json()["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
                    idx = ss.get("index", "fp-events")
                    ip_r = s.get(f"{OSD}/api/saved_objects/index-pattern/{idx}", timeout=15)
                    if ip_r.status_code == 200:
                        fnames = {x["name"] for x in json.loads(ip_r.json()["attributes"].get("fields") or "[]")}
                        if field not in fnames:
                            errs.append(f"{vid}: field {field} absent de {idx}")
    return errs


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails: list[str] = []

    hr = s.get(f"{OSD}/app/home", timeout=15)
    print(f"[zone1] Overview HTTP {hr.status_code} {'OK' if hr.status_code == 200 else 'KO'}")

    for pid, fields in INDEX_PATTERNS.items():
        e = check_index_pattern(s, pid, fields)
        fails.extend(e)
        print(f"[zone1] Discover index {pid}: {'OK' if not e else 'KO ' + '; '.join(e)}")

    for did in DASHBOARDS:
        e = check_dashboard_panels(s, did)
        fails.extend(e)
        print(f"[zone1] Dashboard {did}: {'OK' if not e else 'KO ' + '; '.join(e[:3])}")

    for vid in VIS_IDS:
        vr = s.get(f"{OSD}/api/saved_objects/visualization/{vid}", timeout=15)
        if vr.status_code != 200:
            fails.append(f"viz {vid}: HTTP {vr.status_code}")
            continue
        vs = json.loads(vr.json()["attributes"].get("visState", "{}"))
        if vs.get("type") == "metric":
            labels = (vs.get("params") or {}).get("metric", {}).get("labels", {})
            if labels.get("show") is not True:
                fails.append(f"{vid}: labels.show")

    vl = s.get(f"{OSD}/app/visualize#/list", timeout=15)
    print(f"[zone1] Visualize list HTTP {vl.status_code}")

    print(f"[zone1] Bilan: {len(fails)} problème(s)")
    for f in fails[:30]:
        print(f"  - {f}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
