#!/usr/bin/env python3
"""Playbook Threat Hunting Lead — strategy, execution, automation, metrics."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-threat-hunting-lead-playbook"
DASH_TITLE = "Security Operations — Threat Hunting Lead"
NOTEBOOK_NAME = "Threat Hunting Lead Playbook"
APP_NAME = "Threat Hunting Lead"
LAUNCHER_ID = "fp-threat-hunting-lead-launcher"
SIDE_ID = "fp-threat-hunting-lead-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"TH Lead — {title}")


S1_STRAT: list[PlaybookEntry] = [
    _e("fp-thl-s1-priority", "S1 — Hunts prioritaires", "fp-events", "ti_match: true OR level: critical",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-thl-s1-recurrent", "S1 — Hunts récurrents", "fp-events", "event.code:4625 OR event.code:4698",
       ["@timestamp", "event.code", "host.name"]),
    _e("fp-thl-s1-ti-hunt", "S1 — Hunts TI", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-thl-s1-behav", "S1 — Hunts comportementaux", "fp-events", "message:*anomal* OR message:*suspicious*",
       ["@timestamp", "message", "user.name"]),
    _e("fp-thl-s1-mitre", "S1 — Hunts MITRE", "fp-mitre", "coverage_count >= 2",
       ["@timestamp", "technique_id", "tactic"]),
]

S2_EXEC: list[PlaybookEntry] = [
    _e("fp-thl-s2-logs", "S2 — Hunt logs", "fp-events", "*", ["@timestamp", "message", "host.name"]),
    _e("fp-thl-s2-ioc", "S2 — Hunt IOC", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name"]),
    _e("fp-thl-s2-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-thl-s2-anomaly", "S2 — Hunt anomalies", "fp-events", "message:*anomal* OR event.code:4625",
       ["@timestamp", "message", "event.code"]),
    _e("fp-thl-s2-fusion", "Analyze — Timeline — Timesketch", "fp-fusion", "*",
       ["@timestamp", "fusion_type", "message"]),
]

S3_AUTO: list[PlaybookEntry] = [
    _e("fp-thl-s3-scheduled", "S3 — Hunts programmés", "fp-obs-logs", "message:*hunt* OR message:*cron*",
       ["@timestamp", "message", "service"]),
    _e("fp-thl-s3-ti-trigger", "S3 — Hunts déclenchés TI", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-thl-s3-anom-trigger", "S3 — Hunts déclenchés anomalies", "fp-events", "message:*anomal*",
       ["@timestamp", "message", "host.name"]),
]

S4_METRICS: list[PlaybookEntry] = [
    _e("fp-thl-s4-success", "S4 — Hunts réussis", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value"]),
    _e("fp-thl-s4-critical", "S4 — Hunts critiques", "fp-events", "ti_match: true AND event.code:4625",
       ["@timestamp", "ti_ioc_value", "event.code"]),
    _e("fp-thl-s4-fp", "S4 — Hunts faux positifs", "fp-logs", "message:*false*positive*",
       ["@timestamp", "message"]),
    _e("fp-thl-s4-coverage", "S4 — Hunts coverage", "fp-mitre", "*",
       ["@timestamp", "technique_id", "coverage_count"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Hunting Strategy", S1_STRAT),
    ("2", "Hunting Execution", S2_EXEC),
    ("3", "Hunting Automation", S3_AUTO),
    ("4", "Hunting Metrics", S4_METRICS),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🏹 TH Lead — Hub", "fp-events", "ti_match: true OR event.code:4625",
    ["@timestamp", "message", "host.name"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 TH Lead — Side panel", "fp-events", "ti_match: true",
    ["@timestamp", "ti_ioc_value", "host.name", "message"],
    "Panneau latéral Threat Hunting Lead",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 TH Lead Side panel"))
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
        ("%md\n# Threat Hunting Lead Playbook\nStrategy, execution, automation, metrics.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-windows-* | where ti_match = true | head 30", "PPL"))
    return lines
