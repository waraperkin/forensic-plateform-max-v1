#!/usr/bin/env python3
"""Génère fp-ti-lead-playbook.ndjson."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "opensearch"
NDJSON = OUT / "fp-ti-lead-playbook.ndjson"
sys.path.insert(0, str(ROOT / "scripts"))

from build_opensearch_dashboards import dashboard, finalize_dashboard  # noqa: E402
from osd_ti_lead_playbook_lib import DASH_ID, DASH_TITLE, append_searches, dashboard_panels  # noqa: E402
from osd_vis_lib import saved_object as obj  # noqa: E402


def build() -> list[dict]:
    objects: list[dict] = []
    for pid, pattern, tfield in [
        ("fp-fusion", "forensic-fusion-metrics", "@timestamp"),
        ("fp-ti-enriched", "forensic-ti-enriched", "@timestamp"),
        ("fp-mitre", "fp-mitre-*", "@timestamp"),
        ("fp-obs-logs", "fp-platform-logs*,forensic-uploads*", "@timestamp"),
    ]:
        if not any(o.get("id") == pid and o.get("type") == "index-pattern" for o in objects):
            objects.append(obj("index-pattern", pid, {"title": pattern, "timeFieldName": tfield, "fields": "[]", "fieldFormatMap": "{}"}))
    append_searches(objects)
    panels, panel_refs = dashboard_panels()
    dash = dashboard(DASH_ID, DASH_TITLE, panels)
    for r in panel_refs:
        if not any(x["name"] == r["name"] for x in dash["references"]):
            dash["references"].append(r)
    finalize_dashboard(dash, panels, DASH_ID)
    objects.append(dash)
    return objects


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    objects = build()
    with NDJSON.open("w", encoding="utf-8") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {NDJSON} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
