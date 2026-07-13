#!/usr/bin/env python3
"""Génère NDJSON Analyst Playbook — dashboard, saved searches, index patterns."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "opensearch"
sys.path.insert(0, str(ROOT / "scripts"))

from build_opensearch_dashboards import dashboard, finalize_dashboard  # noqa: E402
from osd_analyst_playbook_lib import (  # noqa: E402
    PLAYBOOK_DASH_ID,
    PLAYBOOK_DASH_TITLE,
    append_playbook_searches,
    playbook_dashboard_panels,
)
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
            objects.append(
                obj(
                    "index-pattern",
                    pid,
                    {"title": pattern, "timeFieldName": tfield, "fields": "[]", "fieldFormatMap": "{}"},
                )
            )

    append_playbook_searches(objects)

    panels, panel_refs = playbook_dashboard_panels()
    dash = dashboard(PLAYBOOK_DASH_ID, PLAYBOOK_DASH_TITLE, panels)
    for r in panel_refs:
        if not any(x["name"] == r["name"] for x in dash["references"]):
            dash["references"].append(r)
    finalize_dashboard(dash, panels, PLAYBOOK_DASH_ID)
    objects.append(dash)
    return objects


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    objects = build()
    path = OUT / "opensearch_playbook.ndjson"
    with path.open("w", encoding="utf-8") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    manifest = {
        "version": "2.12.0",
        "dashboard": PLAYBOOK_DASH_ID,
        "searches": len([o for o in objects if o.get("type") == "search"]),
        "objects": len(objects),
    }
    (OUT / "playbook_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
