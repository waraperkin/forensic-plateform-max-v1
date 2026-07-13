#!/usr/bin/env python3
"""Génère fp-soc-automation-playbook.ndjson."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "opensearch"
NDJSON = OUT / "fp-soc-automation-playbook.ndjson"
sys.path.insert(0, str(ROOT / "scripts"))

from build_opensearch_dashboards import dashboard, finalize_dashboard  # noqa: E402
from osd_soc_automation_playbook_lib import DASH_ID, DASH_TITLE, append_searches, dashboard_panels  # noqa: E402
from osd_vis_lib import saved_object as obj  # noqa: E402


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    objects: list[dict] = []
    for pid, pattern, tfield in [("fp-obs-logs", "fp-platform-logs*,forensic-uploads*", "@timestamp")]:
        objects.append(obj("index-pattern", pid, {"title": pattern, "timeFieldName": tfield, "fields": "[]", "fieldFormatMap": "{}"}))
    append_searches(objects)
    panels, panel_refs = dashboard_panels()
    dash = dashboard(DASH_ID, DASH_TITLE, panels)
    for r in panel_refs:
        if not any(x["name"] == r["name"] for x in dash["references"]):
            dash["references"].append(r)
    finalize_dashboard(dash, panels, DASH_ID)
    objects.append(dash)
    with NDJSON.open("w", encoding="utf-8") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {NDJSON} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
