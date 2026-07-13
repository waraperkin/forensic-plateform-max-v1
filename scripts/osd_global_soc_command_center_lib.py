#!/usr/bin/env python3
"""Playbook Global SOC Command Center — opérations mondiales 24/7."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-global-soc-command-center"
DASH_TITLE = "SOC Operations — Command Center"
NOTEBOOK_NAME = "Global SOC Command Center"
APP_NAME = "Global SOC Command Center"
LAUNCHER_ID = "fp-global-soc-command-center-launcher"
SIDE_ID = "fp-global-soc-command-center-side"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or title)


S1_OPS: list[PlaybookEntry] = [
    _e("fp-gscc-s1-regions", "S1 — Multi-régions", "fp-events", "*", ["@timestamp", "host.name", "source.geo.country", "message"]),
    _e("fp-gscc-s1-timezones", "S1 — Multi-fuseaux", "fp-timesketch", "*", ["@timestamp", "metric_type", "sketch_name"]),
    _e("fp-gscc-s1-teams", "S1 — Multi-équipes", "fp-timesketch", "sketch_name: *", ["@timestamp", "sketch_name", "case_id"]),
    _e("fp-gscc-s1-tenants", "S1 — Multi-tenants", "fp-obs-logs", "*", ["@timestamp", "service", "container", "message"]),
]

S2_THREAT: list[PlaybookEntry] = [
    _e("fp-gscc-s2-global-attacks", "S2 — Attaques globales", "fp-events", "ti_match: true", ["@timestamp", "ti_ioc_value", "host.name"]),
    _e("fp-gscc-s2-campaigns", "S2 — Campagnes multi-pays", "fp-ti", "tags: *campaign* OR tags: *apt*", ["@timestamp", "ioc_value", "tags", "source"]),
    _e("fp-gscc-s2-geo-ioc", "S2 — IOC géopolitiques", "fp-ti-enriched", "geoip.country: *", ["@timestamp", "ioc_value", "geoip.country", "threat_score"]),
    _e("fp-gscc-s2-heatmap", "S2 — Heatmap mondiale", "fp-events", "source.geo.country: *", ["@timestamp", "source.geo.country", "source.ip"]),
]

S3_KPIS: list[PlaybookEntry] = [
    _e("fp-gscc-s3-mtta", "S3 — MTTA global", "fp-logs", "_index:forensic-alerts*", ["@timestamp", "message", "level"]),
    _e("fp-gscc-s3-mttr", "S3 — MTTR global", "fp-timesketch", "metric_type:ir_case", ["@timestamp", "case_id", "events_count"]),
    _e("fp-gscc-s3-inc-region", "S3 — Incidents par région", "fp-events", "case_id: *", ["@timestamp", "case_id", "host.name"]),
    _e("fp-gscc-s3-attack-region", "S3 — Attaques par région", "fp-events", "ti_match: true", ["@timestamp", "source.geo.country", "ti_ioc_value"]),
    _e("fp-gscc-s3-ioc-region", "S3 — IOC par région", "fp-ti-enriched", "geoip.country: *", ["@timestamp", "ioc_value", "geoip.country"]),
]

S4_CMD: list[PlaybookEntry] = [
    _e("fp-gscc-s4-escalation", "S4 — Escalade", "fp-logs", "level: critical", ["@timestamp", "message", "level"]),
    _e("fp-gscc-s4-priority", "S4 — Priorisation", "fp-events", "ti_match: true AND case_id: *", ["@timestamp", "case_id", "ti_ioc_value"]),
    _e("fp-gscc-s4-coordination", "S4 — Coordination multi-équipes", "fp-fusion", "*", ["@timestamp", "fusion_type", "host.name", "message"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Global Operations", S1_OPS),
    ("2", "Global Threat Monitoring", S2_THREAT),
    ("3", "Global KPIs", S3_KPIS),
    ("4", "Global Command Center", S4_CMD),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🌍 Global SOC Command", "fp-events", "*",
    ["@timestamp", "message", "host.name"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 Global SOC Side panel", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "host.name", "message"],
    "Panneau latéral Global SOC Command Center",
)


def all_entries() -> list[PlaybookEntry]:
    out = [LAUNCHER, SIDE]
    for _, _, entries in PLAYBOOK_SECTIONS:
        out.extend(entries)
    return out


def search_specs() -> list[tuple[str, str, str, str, list[str]]]:
    return [(e[0], e[1], e[2], e[3], e[4]) for e in all_entries()]


def append_searches(objects: list[dict]) -> None:
    from osd_drilldown_lib import saved_search_attrs  # noqa: E402
    from osd_vis_lib import saved_object as obj  # noqa: E402

    seen = {o["id"] for o in objects if o.get("type") == "search"}
    for entry in all_entries():
        sid, title, idx, q, cols, desc = entry
        if sid in seen:
            continue
        attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
        attrs["description"] = desc
        objects.append(obj("search", sid, attrs, refs))
        seen.add(sid)


def dashboard_panels() -> tuple[list[dict], list[dict]]:
    from osd_drilldown_lib import search_panel  # noqa: E402
    from osd_fp_playbooks_bars_lib import fp_playbooks_bar_panels  # noqa: E402

    panels, refs = [], []
    y = 0
    bar, bar_refs = fp_playbooks_bar_panels(y, 9)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += 9
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 Global SOC Side panel"))
    refs.append({"name": f"panel_{SIDE_ID}", "type": "search", "id": SIDE_ID})
    cx, cw, ry = 12, 36, y
    for _, _, entries in PLAYBOOK_SECTIONS:
        n, cols = len(entries), 3
        for i, (sid, title, *_r) in enumerate(entries):
            col, row = i % cols, i // cols
            pw = cw // cols
            panels.append(search_panel(sid, cx + col * pw, ry + row * 5, pw, 5, title))
            refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        ry += ((n + cols - 1) // cols) * 5 + 1
    return panels, refs


def notebook_paragraphs() -> list[tuple[str, str]]:
    lines = [
        ("%md\n# Global SOC Command Center\nSOC mondial 24/7 — opérations, menaces, KPIs, commandement.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-platform-logs | stats count() by service | head 20", "PPL"))
    return lines
