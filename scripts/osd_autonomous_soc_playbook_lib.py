#!/usr/bin/env python3
"""Playbook Autonomous SOC (AI-Driven)."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-autonomous-soc-playbook"
DASH_TITLE = "SOC Operations — Autonomous Mode"
NOTEBOOK_NAME = "Autonomous SOC Playbook"
APP_NAME = "Autonomous SOC"
LAUNCHER_ID = "fp-autonomous-soc-launcher"
SIDE_ID = "fp-autonomous-soc-side"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or title)


S1_DETECT: list[PlaybookEntry] = [
    _e("fp-asoc-s1-anomaly", "S1 — Anomalies IA", "fp-events", "message:*anomal* OR message:*ml* OR message:*ai*", ["@timestamp", "message", "host.name"]),
    _e("fp-asoc-s1-corr", "S1 — Corrélation IA", "fp-fusion", "*", ["@timestamp", "fusion_type", "message", "threat_score"]),
    _e("fp-asoc-s1-score", "S1 — Scoring IA", "fp-ti-enriched", "threat_score: *", ["@timestamp", "ioc_value", "threat_score"]),
]

S2_INVEST: list[PlaybookEntry] = [
    _e("fp-asoc-s2-pivot", "S2 — Pivot IA", "fp-events", "ti_match: true", ["@timestamp", "ti_ioc_value", "host.name", "user.name"]),
    _e("fp-asoc-s2-timeline", "Analyze — Timeline — Timesketch", "fp-fusion", "*", ["@timestamp", "fusion_type", "host.name", "message"]),
    _e("fp-asoc-s2-cti", "S2 — CTI IA", "fp-ti-enriched", "*", ["@timestamp", "ioc_value", "threat_score", "source"]),
    _e("fp-asoc-s2-hunt", "S2 — Hunts IA", "fp-events", "ti_match: true OR event.code:4625", ["@timestamp", "message", "event.code"]),
]

S3_RESPOND: list[PlaybookEntry] = [
    _e("fp-asoc-s3-contain", "S3 — Containment auto", "fp-events", "message:*automated* AND message:*block*", ["@timestamp", "host.name", "message"]),
    _e("fp-asoc-s3-erad", "S3 — Eradication auto", "fp-logs", "message:*remediat* OR message:*clean*", ["@timestamp", "message", "level"]),
    _e("fp-asoc-s3-remed", "S3 — Remédiation auto", "fp-obs-logs", "message:*restart* OR message:*recover*", ["@timestamp", "service", "message"]),
]

S4_SUPERV: list[PlaybookEntry] = [
    _e("fp-asoc-s4-transparency", "S4 — Transparence IA", "fp-fusion", "fusion_type: *", ["@timestamp", "fusion_type", "message"]),
    _e("fp-asoc-s4-explain", "S4 — Explication IA", "fp-events", "ti_match: true", ["@timestamp", "ti_ioc_value", "ti_sources", "message"]),
    _e("fp-asoc-s4-audit", "S4 — Audit IA", "fp-logs", "message:*audit* OR message:*FP-*", ["@timestamp", "message", "level"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Détection autonome", S1_DETECT),
    ("2", "Investigation autonome", S2_INVEST),
    ("3", "Réponse autonome", S3_RESPOND),
    ("4", "Supervision IA", S4_SUPERV),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🤖 Autonomous SOC", "fp-fusion", "*",
    ["@timestamp", "fusion_type", "message", "threat_score"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 Autonomous SOC Side panel", "fp-fusion", "fusion_type: *",
    ["@timestamp", "fusion_type", "message", "threat_score"],
    "Panneau latéral Autonomous SOC",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 Autonomous SOC Side panel"))
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
        ("%md\n# Autonomous SOC Playbook\nSOC autonome piloté par IA — détection, investigation, réponse, supervision.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-fusion-metrics | head 40", "PPL"))
    return lines
