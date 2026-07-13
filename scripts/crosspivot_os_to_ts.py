#!/usr/bin/env python3
"""Cross-Pivot OS→TS — saved searches + side-panel Timesketch sur dashboards FP."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import (  # noqa: E402
    PIVOT_BUILDERS,
    opensearch_discover_url,
    save_state,
    verify_pivot,
)
from fp_playbooks_common import OSD, hdrs, import_ndjson  # noqa: E402
from osd_drilldown_lib import saved_search_attrs, search_panel  # noqa: E402
from osd_vis_lib import saved_object as obj  # noqa: E402

NDJSON = ROOT / "dashboards" / "opensearch" / "crosspivot_os_to_ts.ndjson"

TARGET_DASHBOARDS = [
    "fp-opensearch-security",
    "fp-threat-hunting",
    "fp-dfir-senior-playbook",
    "fp-incident-commander-playbook",
]

CPX_PANELS = [
    ("fp-cpx-side-timesketch", "📋 Timesketch Pivot — Side panel", "fp-events", "*"),
    ("fp-cpx-open-ts-host", "⏭ Open in Timesketch — Host", "fp-events", "host.name: *"),
    ("fp-cpx-open-ts-user", "⏭ Open in Timesketch — User", "fp-events", "user.name: *"),
    ("fp-cpx-open-ts-ip", "⏭ Open in Timesketch — IP", "fp-events", "ti_match: true"),
    ("fp-cpx-open-ts-ioc", "⏭ Open in Timesketch — IOC", "fp-events", "ti_match: true"),
    ("fp-cpx-open-ts-process", "⏭ Open in Timesketch — Process", "fp-events", "process.name: *"),
    ("fp-cpx-open-ts-file", "⏭ Open in Timesketch — File/DFIR", "fp-events", "file.path: * OR message:*dfir*"),
    ("fp-cpx-open-ts-alert", "⏭ Open in Timesketch — Alert", "fp-events", "event.dataset: security.detection"),
    ("fp-cpx-open-ts-cti", "⏭ Open in Timesketch — CTI", "fp-ti-opencti", "*"),
]


def build_ndjson() -> list[dict]:
    objects: list[dict] = []
    pivot_results = []
    for kind in PIVOT_BUILDERS:
        pr = verify_pivot(kind)
        pivot_results.append(pr)

    for sid, title, idx, base_q in CPX_PANELS:
        desc_lines = [f"Cross-Pivot FP — {title}"]
        if "open-ts" in sid:
            kind = sid.replace("fp-cpx-open-ts-", "")
            if kind in PIVOT_BUILDERS:
                pr = next((p for p in pivot_results if p.kind == kind), None)
                if pr:
                    desc_lines.append(f"TIMESKETCH_URL={pr.ts_url}")
                    desc_lines.append(f"OS_MIRROR={opensearch_discover_url(pr.os_query, pr.os_index)}")
        else:
            for pr in pivot_results:
                desc_lines.append(f"{pr.kind.upper()}: {pr.ts_url}")
        attrs, refs = saved_search_attrs(sid, title, idx, base_q, ["@timestamp", "message", "host.name", "user.name", "ti_ioc_value"])
        attrs["description"] = "\n".join(desc_lines)[:2000]
        objects.append(obj("search", sid, attrs, refs))

    save_state(pivot_results, {"osd_objects": len(objects)})
    return objects


def write_ndjson(objects: list[dict]) -> None:
    NDJSON.parent.mkdir(parents=True, exist_ok=True)
    with NDJSON.open("w", encoding="utf-8") as fh:
        for o in objects:
            fh.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"[crosspivot-os-ts] wrote {NDJSON} ({len(objects)} objects)")


def inject_dashboard_panels(s: requests.Session) -> int:
    fails = 0
    panel_specs = []
    w = 6
    for i, (sid, title, _idx, _q) in enumerate(CPX_PANELS):
        panel_specs.append(search_panel(sid, (i % 8) * w, 0 if i < 8 else 4, w, 4, title))

    for dash_id in TARGET_DASHBOARDS:
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=30)
        if r.status_code != 200:
            print(f"[crosspivot-os-ts] KO dashboard {dash_id} HTTP {r.status_code}", file=sys.stderr)
            fails += 1
            continue
        body = r.json()
        attrs = body["attributes"]
        panels = json.loads(attrs["panelsJSON"])
        existing = {p["panelIndex"] for p in panels}
        new_panels = [p for p in panel_specs if p["panelIndex"] not in existing]
        if not new_panels:
            print(f"[crosspivot-os-ts] OK {dash_id} (déjà patché)")
            continue
        max_y = max((p["gridData"]["y"] + p["gridData"]["h"] for p in panels), default=0)
        for p in new_panels:
            p["gridData"]["y"] += max_y
        panels = new_panels + panels
        attrs["panelsJSON"] = json.dumps(panels)
        refs = body.get("references") or []
        for p in new_panels:
            refs.append({"name": p["panelRefName"], "type": "search", "id": p["panelIndex"]})
        pr = s.put(
            f"{OSD}/api/saved_objects/dashboard/{dash_id}",
            json={"attributes": attrs, "references": refs},
            headers=hdrs(),
            timeout=60,
        )
        if pr.status_code not in (200, 201):
            print(f"[crosspivot-os-ts] KO patch {dash_id}", file=sys.stderr)
            fails += 1
        else:
            print(f"[crosspivot-os-ts] OK patch {dash_id} (+{len(new_panels)} panels)")
    return fails


def main() -> int:
    objects = build_ndjson()
    write_ndjson(objects)
    if not import_ndjson(NDJSON):
        return 1
    s = requests.Session()
    s.verify = False
    if inject_dashboard_panels(s) != 0:
        return 1
    print("[crosspivot-os-ts] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
