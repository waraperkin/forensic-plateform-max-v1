#!/usr/bin/env python3
"""Playbook SOC Automation Engineer — automations, SOAR, pipelines, monitoring."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-soc-automation-playbook"
DASH_TITLE = "SOC Operations — Automation Playbook"
NOTEBOOK_NAME = "SOC Automation Playbook"
APP_NAME = "SOC Automation Engineer"
LAUNCHER_ID = "fp-soc-automation-launcher"
SIDE_ID = "fp-soc-automation-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"SOC Automation — {title}")


S1_AUTO: list[PlaybookEntry] = [
    _e("fp-soca-s1-ingest", "S1 — Auto ingestion", "fp-obs-logs", "message:*ingest* OR message:*logstash*",
       ["@timestamp", "message", "service"]),
    _e("fp-soca-s1-ti", "S1 — Auto TI", "fp-ti", "*", ["@timestamp", "ioc_type", "source"]),
    _e("fp-soca-s1-alert", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-soca-s1-ir", "S1 — Auto IR", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "sketch_name"]),
    _e("fp-soca-s1-cti", "S1 — Auto CTI", "fp-ti-opencti", "*", ["@timestamp", "ioc_value", "source"]),
    _e("fp-soca-s1-hunt", "S1 — Auto hunts", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-soca-s1-dash", "S1 — Auto dashboards", "fp-obs-logs", "service: opensearch-dashboards",
       ["@timestamp", "message", "container"]),
]

S2_SOAR: list[PlaybookEntry] = [
    _e("fp-soca-s2-auto-act", "S2 — Actions automatiques", "fp-logs", "message:*automated* OR message:*SOAR*",
       ["@timestamp", "message"]),
    _e("fp-soca-s2-semi", "S2 — Actions semi-auto", "fp-events", "case_id: *",
       ["@timestamp", "case_id", "message"]),
    _e("fp-soca-s2-guided", "S2 — Actions guidées", "fp-timesketch", "sketch_name: *",
       ["@timestamp", "sketch_name", "events_count"]),
]

S3_PIPE: list[PlaybookEntry] = [
    _e("fp-soca-s3-logs-pipe", "S3 — Pipeline logs", "fp-obs-logs", "*",
       ["@timestamp", "message", "service", "container"]),
    _e("fp-soca-s3-ti-pipe", "S3 — Pipeline TI", "fp-ti", "*", ["@timestamp", "ioc_value", "source"]),
    _e("fp-soca-s3-alert-pipe", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-soca-s3-fusion-pipe", "S3 — Pipeline fusion", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "message"]),
]

S4_MON: list[PlaybookEntry] = [
    _e("fp-soca-s4-pipe-err", "S4 — Erreurs pipelines", "fp-obs-logs", "level:error",
       ["@timestamp", "message", "service"]),
    _e("fp-soca-s4-ingest-err", "S4 — Erreurs ingestion", "fp-logs", "message:*ingest* AND level:error",
       ["@timestamp", "message"]),
    _e("fp-soca-s4-ti-err", "S4 — Erreurs TI", "fp-obs-logs", "message:*opencti* AND level:error",
       ["@timestamp", "message"]),
    _e("fp-soca-s4-alert-err", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts* AND level:error",
       ["@timestamp", "message", "level"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Automations", S1_AUTO),
    ("2", "SOAR", S2_SOAR),
    ("3", "Pipelines", S3_PIPE),
    ("4", "Monitoring", S4_MON),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "⚙️ SOC Automation — Hub", "fp-obs-logs", "level:error OR message:*pipeline*",
    ["@timestamp", "message", "service"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 SOC Automation — Side panel", "fp-obs-logs", "level:error",
    ["@timestamp", "message", "service", "level"],
    "Panneau latéral SOC Automation",
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
    bar, bar_refs = fp_playbooks_bar_panels(y, 6)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += 6
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 SOC Auto Side panel"))
    refs.append({"name": f"panel_{SIDE_ID}", "type": "search", "id": SIDE_ID})
    content_x, content_w, row_y = 12, 36, y
    for _, _title, entries in PLAYBOOK_SECTIONS:
        n, cols = len(entries), 3
        for i, (sid, title, *_rest) in enumerate(entries):
            col, row = i % cols, i // cols
            pw = content_w // cols
            panels.append(search_panel(sid, content_x + col * pw, row_y + row * 5, pw, 5, title))
            refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
        row_y += ((n + cols - 1) // cols) * 5 + 1
    return panels, refs


def notebook_paragraphs() -> list[tuple[str, str]]:
    lines = [
        ("%md\n# SOC Automation Playbook\nAutomations, SOAR, pipelines, monitoring.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-platform-logs | where level = 'error' | head 50", "PPL"))
    return lines
