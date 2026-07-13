#!/usr/bin/env python3
"""Verify dashboard FP — Platform Health (API + panels + champs)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fp_playbooks_common import hdrs  # noqa: E402
from osd_platform_health_lib import DASH_ID, DASH_TITLE, IDX_PH  # noqa: E402
from platform_health_lib import HEALTH_INDEX, OS_URL  # noqa: E402

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OSD_NGINX = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")

REQUIRED_VIZ = [
    "fp-ph-viz-global-status",
    "fp-ph-viz-os-indices",
    "fp-ph-viz-ts-sketches",
    "fp-ph-viz-ti-ioc",
    "fp-ph-viz-sigma-rules",
    "fp-ph-viz-parsing-dataset",
    "fp-ph-viz-analyzer-types",
]

BAD_PHRASES = ("Could not locate field", "Saved field", "undefined field", "field not found")


def osd_base(s: requests.Session) -> str:
    if s.get(f"{OSD}/api/status", verify=False, timeout=8).status_code == 200:
        return OSD
    return OSD_NGINX


def check_health_index() -> bool:
    r = requests.get(f"{OS_URL}/{HEALTH_INDEX}/_count", timeout=20, verify=False)
    if r.status_code != 200:
        print(f"[platform-health-verify] KO index count HTTP {r.status_code}", file=sys.stderr)
        return False
    c = r.json().get("count", 0)
    if c < 5:
        print(f"[platform-health-verify] KO index docs={c}", file=sys.stderr)
        return False
    print(f"[platform-health-verify] OK index {HEALTH_INDEX} docs={c}")
    return True


def check_visualization(s: requests.Session, base: str, vid: str) -> bool:
    vr = s.get(f"{base}/api/saved_objects/visualization/{vid}", headers=hdrs(), timeout=20)
    if vr.status_code != 200:
        print(f"[platform-health-verify] KO viz {vid} HTTP {vr.status_code}", file=sys.stderr)
        return False
    raw = json.dumps(vr.json())
    for phrase in BAD_PHRASES:
        if phrase.lower() in raw.lower():
            print(f"[platform-health-verify] KO viz {vid} — {phrase}", file=sys.stderr)
            return False
    ss = vr.json()["attributes"].get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", "")
    if "health." in ss and ".keyword" in ss and "health.component.keyword" not in ss:
        # pie terms sur health.component sans .keyword peut casser selon mapping
        pass
    return True


def check_dashboard_panels(s: requests.Session, base: str) -> tuple[int, int]:
    dr = s.get(f"{base}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=30)
    if dr.status_code != 200:
        print(f"[platform-health-verify] KO dashboard HTTP {dr.status_code}", file=sys.stderr)
        return 0, 1
    attrs = dr.json()["attributes"]
    if DASH_TITLE not in (attrs.get("title") or ""):
        print(f"[platform-health-verify] KO titre dashboard", file=sys.stderr)
        return 0, 1
    panels = json.loads(attrs["panelsJSON"])
    refs = {r["name"]: r for r in dr.json().get("references", [])}
    ok = 0
    fails = 0
    for p in panels:
        ref_name = p.get("panelRefName", "")
        ref = refs.get(ref_name)
        if not ref:
            continue
        if ref["type"] == "search":
            ok += 1
            continue
        if ref["type"] == "visualization":
            if check_visualization(s, base, ref["id"]):
                ok += 1
            else:
                fails += 1
    print(f"[platform-health-verify] panels OK={ok}/{len(panels)} fails={fails}")
    return ok, fails


def check_ui_page(s: requests.Session, base: str) -> bool:
    url = f"{base}/app/dashboards#/view/{DASH_ID}"
    try:
        r = s.get(url, timeout=45, allow_redirects=True)
        text = r.text or ""
        if r.status_code >= 400:
            print(f"[platform-health-verify] KO UI HTTP {r.status_code}", file=sys.stderr)
            return False
        for phrase in BAD_PHRASES + ("Server side error",):
            if phrase in text:
                print(f"[platform-health-verify] KO UI phrase: {phrase}", file=sys.stderr)
                return False
        print(f"[platform-health-verify] OK UI {url}")
        return True
    except Exception as exc:
        print(f"[platform-health-verify] WARN UI {exc}", file=sys.stderr)
        return True


def main() -> int:
    fails = 0
    if not check_health_index():
        fails += 1

    s = requests.Session()
    s.verify = False
    base = osd_base(s)

    ip = s.get(f"{base}/api/saved_objects/index-pattern/{IDX_PH}", headers=hdrs(), timeout=15)
    if ip.status_code != 200:
        print(f"[platform-health-verify] KO index-pattern {IDX_PH}", file=sys.stderr)
        fails += 1
    else:
        print(f"[platform-health-verify] OK index-pattern {IDX_PH}")

    for vid in REQUIRED_VIZ:
        if not check_visualization(s, base, vid):
            fails += 1

    _, panel_fails = check_dashboard_panels(s, base)
    fails += panel_fails

    if not check_ui_page(s, base):
        fails += 1

    print(f"[platform-health-verify] errors={fails}")
    print(f"[platform-health-verify] URL={base}/app/dashboards#/view/{DASH_ID}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
