#!/usr/bin/env python3
"""Playbook Cyber Crisis Management."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-cyber-crisis-management"
DASH_TITLE = "CERT — Crisis Management"
NOTEBOOK_NAME = "Cyber Crisis Management"
APP_NAME = "Cyber Crisis Management"
LAUNCHER_ID = "fp-cyber-crisis-management-launcher"
SIDE_ID = "fp-cyber-crisis-management-side"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or title)


S1_DETECT: list[PlaybookEntry] = [
    _e("fp-ccm-s1-weak", "S1 — Signaux faibles", "fp-events", "message:*suspicious* OR ti_match: true", ["@timestamp", "message", "ti_ioc_value"]),
    _e("fp-ccm-s1-strong", "S1 — Signaux forts", "fp-logs", "level: critical", ["@timestamp", "message", "level"]),
    _e("fp-ccm-s1-mass-anomaly", "S1 — Anomalies massives", "fp-events", "event.code:4625 OR message:*anomal*", ["@timestamp", "event.code", "message"]),
    _e("fp-ccm-s1-simultaneous", "S1 — Attaques simultanées", "fp-events", "ti_match: true", ["@timestamp", "ti_ioc_value", "host.name"]),
]

S2_ACTIVATE: list[PlaybookEntry] = [
    _e("fp-ccm-s2-cell", "S2 — Cellule crise", "fp-timesketch", "metric_type:ir_case", ["@timestamp", "case_id", "sketch_name"]),
    _e("fp-ccm-s2-com-int", "S2 — Communication interne", "fp-obs-logs", "service: *", ["@timestamp", "service", "message"]),
    _e("fp-ccm-s2-com-ext", "S2 — Communication externe", "fp-logs", "message:*incident* OR message:*breach*", ["@timestamp", "message"]),
    _e("fp-ccm-s2-governance", "S2 — Gouvernance", "fp-timesketch", "case_id: *", ["@timestamp", "case_id", "events_count"]),
]

S3_MANAGE: list[PlaybookEntry] = [
    _e("fp-ccm-s3-contain", "S3 — Containment global", "fp-events", "message:*isolat* OR message:*block*", ["@timestamp", "host.name", "message"]),
    _e("fp-ccm-s3-eradicate", "S3 — Eradication globale", "fp-ti", "tags: revoked OR tags: expired", ["@timestamp", "ioc_value", "tags"]),
    _e("fp-ccm-s3-restore", "S3 — Restauration globale", "fp-events", "message:*restore* OR message:*recover*", ["@timestamp", "host.name", "message"]),
]

S4_POST: list[PlaybookEntry] = [
    _e("fp-ccm-s4-lessons", "S4 — Lessons learned", "fp-timesketch", "metric_type:ir_case", ["@timestamp", "case_id", "sketch_name"]),
    _e("fp-ccm-s4-mitre-gap", "S4 — Gaps MITRE", "fp-mitre", "coverage_count: 0", ["@timestamp", "technique_id", "tactic"]),
    _e("fp-ccm-s4-soc-gap", "S4 — Gaps SOC", "fp-logs", "_index:forensic-alerts*", ["@timestamp", "message", "level"]),
    _e("fp-ccm-s4-ti-gap", "S4 — Gaps TI", "fp-ti-enriched", "threat_score: *", ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-ccm-s4-dfir-gap", "S4 — Gaps DFIR", "fp-fusion", "fusion_type:case", ["@timestamp", "case_id", "message"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Détection crise", S1_DETECT),
    ("2", "Activation crise", S2_ACTIVATE),
    ("3", "Gestion crise", S3_MANAGE),
    ("4", "Post-crise", S4_POST),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🚨 Cyber Crisis", "fp-logs", "level: critical OR level: error",
    ["@timestamp", "message", "level"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 Cyber Crisis Side panel", "fp-logs", "_index:forensic-alerts* AND level: critical",
    ["@timestamp", "message", "level"],
    "Panneau latéral Cyber Crisis Management",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 Cyber Crisis Side panel"))
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
        ("%md\n# Cyber Crisis Management\nDétection, activation, gestion et post-crise.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = forensic-alerts* | where level = 'critical' | head 30", "PPL"))
    return lines
