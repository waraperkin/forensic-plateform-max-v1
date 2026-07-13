#!/usr/bin/env python3
"""Dashboards Observability FP (logs plateforme, santé pipeline)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "opensearch"
sys.path.insert(0, str(ROOT / "scripts"))
from build_opensearch_dashboards import (  # noqa: E402
    append_drill_searches,
    dashboard,
    finalize_dashboard,
    panel,
    search,
)
from osd_vis_lib import saved_object as obj, vis_histogram, vis_metric, vis_pie  # noqa: E402


def build() -> list[dict]:
    objects: list[dict] = []
    objects.append(
        obj(
            "index-pattern",
            "fp-obs-logs",
            {
                "title": "fp-platform-logs*,forensic-uploads*",
                "timeFieldName": "@timestamp",
                "fields": "[]",
                "fieldFormatMap": "{}",
            },
        )
    )
    objects.append(search("fp-obs-search-logs", "FP Obs — Platform logs", "fp-obs-logs", "*"))
    objects.append(search("fp-obs-search-errors", "FP Obs — Errors", "fp-obs-logs", "log.level:error OR message:*error*"))
    objects.append(vis_metric("fp-obs-viz-total", "Obs — Log events (24h)", "fp-obs-logs", "*"))
    objects.append(vis_histogram("fp-obs-viz-timeline", "Obs — Logs over time", "fp-obs-logs", "*"))
    objects.append(vis_pie("fp-obs-viz-service", "Obs — By source index", "fp-obs-logs", "*", "_index"))
    objects.append(vis_pie("fp-obs-viz-container", "Obs — By container", "fp-obs-logs", "*", "container.keyword"))
    objects.append(vis_histogram("fp-obs-viz-errors", "Obs — Errors timeline", "fp-obs-logs", "log.level:error"))

    panels = [
        panel("fp-obs-viz-total", 0, 0, 8, 8),
        panel("fp-obs-viz-service", 8, 0, 16, 8),
        panel("fp-obs-viz-timeline", 0, 8, 24, 10),
        panel("fp-obs-viz-errors", 0, 18, 24, 10),
        panel("fp-obs-viz-container", 0, 28, 24, 10),
    ]
    append_drill_searches(objects)
    dash = dashboard("fp-observability-pipeline", "Platform Health — Ingestion Status", panels)
    finalize_dashboard(dash, panels, "fp-observability-pipeline")
    objects.append(dash)
    return objects


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    objects = build()
    # Déduplication par (type, id) : append_drill_searches peut réintroduire des
    # searches déjà déclarés (ex. fp-obs-search-logs/errors). OSD refuse l'import
    # entier (400 "Non-unique import objects detected") si des doublons existent.
    seen: set[tuple] = set()
    deduped = []
    for o in objects:
        key = (o.get("type"), o.get("id"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(o)
    objects = deduped
    path = OUT / "fp_observability_saved_objects.ndjson"
    with path.open("w", encoding="utf-8") as f:
        for o in objects:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"wrote {path} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
