#!/usr/bin/env python3
"""Playbook Blue Team Lead — détection, réponse, durcissement, métriques défense."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-blue-team-lead-playbook"
DASH_TITLE = "SOC Operations — Blue Team Lead"
NOTEBOOK_NAME = "Blue Team Lead Playbook"
APP_NAME = "Blue Team Lead"
LAUNCHER_ID = "fp-blue-team-lead-launcher"
SIDE_ID = "fp-blue-team-lead-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"Blue Team Lead — {title}")


S1_DET: list[PlaybookEntry] = [
    _e("fp-btl-s1-alerts", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-btl-s1-sigma", "Detect — Sigma — Windows Logon", "fp-logs", "message:*FP-SIGMA*",
       ["@timestamp", "message", "level"]),
    _e("fp-btl-s1-ti-det", "S1 — Détection TI", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "host.name"]),
    _e("fp-btl-s1-behav", "S1 — Comportemental", "fp-events", "event.code:4625 OR message:*anomal*",
       ["@timestamp", "event.code", "message"]),
]

S2_RESP: list[PlaybookEntry] = [
    _e("fp-btl-s2-cases", "S2 — Cas IR", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "events_count"]),
    _e("fp-btl-s2-contain", "S2 — Containment", "fp-events", "message:*block* OR message:*isolat*",
       ["@timestamp", "host.name", "message"]),
    _e("fp-btl-s2-erad", "S2 — Eradication", "fp-ti", "tags: revoked",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-btl-s2-recover", "S2 — Recovery", "fp-events", "message:*restore* OR message:*recover*",
       ["@timestamp", "host.name", "message"]),
]

S3_HARD: list[PlaybookEntry] = [
    _e("fp-btl-s3-assets", "S3 — Assets critiques", "fp-events", "host.name: * AND ti_match: true",
       ["@timestamp", "host.name", "ti_ioc_value"]),
    _e("fp-btl-s3-vuln", "S3 — Vulnérabilités", "fp-logs", "message:*CVE* OR message:*vulnerab*",
       ["@timestamp", "message", "level"]),
    _e("fp-btl-s3-harden", "S3 — Durcissement", "fp-obs-logs", "message:*patch* OR message:*harden*",
       ["@timestamp", "service", "message"]),
]

S4_METRICS: list[PlaybookEntry] = [
    _e("fp-btl-s4-mtta", "S4 — MTTA", "fp-logs", "_index:forensic-alerts* AND level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-btl-s4-mttr", "S4 — MTTR", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "events_count"]),
    _e("fp-btl-s4-coverage", "S4 — Coverage MITRE", "fp-mitre", "*",
       ["@timestamp", "technique_id", "coverage_count"]),
    _e("fp-btl-s4-hunt", "S4 — Hunts actifs", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Détection", S1_DET),
    ("2", "Réponse", S2_RESP),
    ("3", "Durcissement", S3_HARD),
    ("4", "Métriques défense", S4_METRICS),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🔵 Blue Team — Hub", "fp-logs", "_index:forensic-alerts*",
    ["@timestamp", "message", "level"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 Blue Team Lead — Side panel", "fp-logs", "_index:forensic-alerts*",
    ["@timestamp", "message", "level"],
    "Panneau latéral Blue Team Lead",
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
    from osd_fp_playbooks_bars_lib import BAR_HEIGHT, fp_playbooks_bar_panels  # noqa: E402

    panels, refs = [], []
    y = 0
    bar, bar_refs = fp_playbooks_bar_panels(y, BAR_HEIGHT)
    panels.extend(bar)
    refs.extend(bar_refs)
    y += BAR_HEIGHT
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 Blue Team Lead Side panel"))
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
        ("%md\n# Blue Team Lead Playbook\nDétection, réponse, durcissement et métriques défense.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-events | stats count() by ti_match | sort - count()", "PPL"))
    return lines
