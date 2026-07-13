#!/usr/bin/env python3
"""Playbook Purple Team — adversary sim, detection engineering, validation."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-purple-team-playbook"
DASH_TITLE = "Purple Teaming — Operations"
NOTEBOOK_NAME = "Purple Team Playbook"
APP_NAME = "Purple Team"
LAUNCHER_ID = "fp-purple-team-launcher"
SIDE_ID = "fp-purple-team-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"Purple Team — {title}")


S1_ADV: list[PlaybookEntry] = [
    _e("fp-pt-s1-mitre-ttp", "S1 — TTP MITRE", "fp-mitre", "*", ["@timestamp", "technique_id", "tactic"]),
    _e("fp-pt-s1-attack-chain", "S1 — Chaînes d'attaque", "fp-fusion", "fusion_type:case OR fusion_type:alert",
       ["@timestamp", "fusion_type", "message"]),
    _e("fp-pt-s1-offensive", "S1 — Scénarios offensifs", "fp-events", "message:*simulat* OR message:*red*team*",
       ["@timestamp", "message", "host.name"]),
    _e("fp-pt-s1-det-test", "S1 — Tests détection", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-pt-s1-corr-test", "S1 — Tests corrélation", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "message"]),
    _e("fp-pt-s1-pivot-test", "S1 — Tests pivot", "fp-events", "host.name: * AND user.name: *",
       ["@timestamp", "host.name", "user.name"]),
]

S2_DET: list[PlaybookEntry] = [
    _e("fp-pt-s2-sigma", "Detect — Sigma — Windows Logon", "fp-logs", "message:*FP-SIGMA*",
       ["@timestamp", "message", "level"]),
    _e("fp-pt-s2-behav", "S2 — Règles comportementales", "fp-events", "event.code:4625 OR message:*anomal*",
       ["@timestamp", "event.code", "message"]),
    _e("fp-pt-s2-ti-rules", "S2 — Règles TI", "fp-events", "ti_match: true",
       ["@timestamp", "ti_ioc_value", "ti_sources"]),
    _e("fp-pt-s2-corr-rules", "S2 — Règles corrélées", "fp-fusion", "fusion_type:alert",
       ["@timestamp", "alert_name", "message"]),
    _e("fp-pt-s2-mitre-cov", "S2 — Coverage MITRE", "fp-mitre", "coverage_count >= 1",
       ["@timestamp", "technique_id", "coverage_count"]),
]

S3_VAL: list[PlaybookEntry] = [
    _e("fp-pt-s3-auto-test", "S3 — Tests automatisés", "fp-logs", "message:*test* OR message:*validate*",
       ["@timestamp", "message", "service"]),
    _e("fp-pt-s3-replay-logs", "Replay — Attack — Purple Team", "fp-events", "*",
       ["@timestamp", "message", "host.name"]),
    _e("fp-pt-s3-replay-ioc", "Replay — Attack — Purple Team", "fp-ti", "*", ["@timestamp", "ioc_value", "ioc_type"]),
    _e("fp-pt-s3-replay-alerts", "Replay — Attack — Purple Team", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
]

S4_IMPROVE: list[PlaybookEntry] = [
    _e("fp-pt-s4-mitre-gap", "S4 — Gaps MITRE", "fp-mitre", "coverage_count: 0",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-pt-s4-sigma-gap", "Detect — Sigma — Windows Logon", "fp-mitre", "rule_prefix: unmapped",
       ["@timestamp", "technique_id", "rule_prefix"]),
    _e("fp-pt-s4-hunt-gap", "S4 — Gaps hunts", "fp-events", "NOT ti_match: true AND event.code:4625",
       ["@timestamp", "event.code", "message"]),
    _e("fp-pt-s4-ti-gap", "S4 — Gaps TI", "fp-ti", "NOT tags: *",
       ["@timestamp", "ioc_value", "tags"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Adversary Simulation", S1_ADV),
    ("2", "Detection Engineering", S2_DET),
    ("3", "Validation", S3_VAL),
    ("4", "Amélioration continue", S4_IMPROVE),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🟣 Purple Team — Hub", "fp-mitre", "*",
    ["@timestamp", "technique_id", "tactic"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 Purple Team — Side panel", "fp-mitre", "coverage_count >= 1",
    ["@timestamp", "technique_id", "tactic", "coverage_count"],
    "Panneau latéral Purple Team",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 30, "📋 Purple Team Side panel"))
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
        ("%md\n# Purple Team Playbook\nAdversary simulation, detection engineering, validation.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-mitre-coverage | stats count() by technique_id | head 30", "PPL"))
    return lines
