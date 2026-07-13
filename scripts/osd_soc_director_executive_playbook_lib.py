#!/usr/bin/env python3
"""Playbook SOC Director Executive — vision exécutive, KPIs board, risques, conformité."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-soc-director-executive-playbook"
DASH_TITLE = "SOC Operations — Executive Playbook"
NOTEBOOK_NAME = "SOC Director Executive Playbook"
APP_NAME = "SOC Director Executive"
LAUNCHER_ID = "fp-soc-director-executive-launcher"
SIDE_ID = "fp-soc-director-executive-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"SOC Director Executive — {title}")


S1_EXEC: list[PlaybookEntry] = [
    _e("fp-sde-s1-board-kpi", "S1 — KPIs board", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "events_count"]),
    _e("fp-sde-s1-risk-appetite", "S1 — Appétit risque", "fp-ti-enriched", "threat_score >= 70",
       ["@timestamp", "ioc_value", "threat_score"]),
    _e("fp-sde-s1-exposure", "S1 — Exposition entreprise", "fp-events", "ti_match: true",
       ["@timestamp", "host.name", "ti_ioc_value"]),
    _e("fp-sde-s1-compliance", "S1 — Conformité", "fp-logs", "message:*compliance* OR message:*audit*",
       ["@timestamp", "message", "level"]),
]

S2_PERF: list[PlaybookEntry] = [
    _e("fp-sde-s2-mtta-exec", "S2 — MTTA exécutif", "fp-logs", "_index:forensic-alerts* AND level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-sde-s2-mttr-exec", "S2 — MTTR exécutif", "fp-timesketch", "metric_type:ir_case",
       ["@timestamp", "case_id", "events_count"]),
    _e("fp-sde-s2-inc-trend", "S2 — Tendance incidents", "fp-events", "case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value"]),
    _e("fp-sde-s2-breach-risk", "S2 — Risque breach", "fp-logs", "message:*breach* OR message:*exfil*",
       ["@timestamp", "message", "level"]),
]

S3_STRAT: list[PlaybookEntry] = [
    _e("fp-sde-s3-threat-land", "S3 — Paysage menaces", "fp-ti", "*", ["@timestamp", "ioc_type", "tags", "source"]),
    _e("fp-sde-s3-apt-exec", "S3 — APT exécutif", "fp-ti-opencti", "tags: *apt*",
       ["@timestamp", "ioc_value", "tags"]),
    _e("fp-sde-s3-mitre-exec", "S3 — MITRE exécutif", "fp-mitre", "*",
       ["@timestamp", "technique_id", "tactic", "coverage_count"]),
    _e("fp-sde-s3-invest", "S3 — Investissements SOC", "fp-obs-logs", "service: *",
       ["@timestamp", "service", "message"]),
]

S4_GOVERN: list[PlaybookEntry] = [
    _e("fp-sde-s4-escal-exec", "S4 — Escalade exécutive", "fp-logs", "level: critical",
       ["@timestamp", "message", "level"]),
    _e("fp-sde-s4-crisis", "S4 — Crises actives", "fp-events", "ti_match: true AND case_id: *",
       ["@timestamp", "case_id", "ti_ioc_value"]),
    _e("fp-sde-s4-roadmap", "S4 — Roadmap SOC", "fp-mitre", "coverage_count: 0",
       ["@timestamp", "technique_id", "tactic"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Vision exécutive", S1_EXEC),
    ("2", "Performance & risques", S2_PERF),
    ("3", "Stratégie menaces", S3_STRAT),
    ("4", "Gouvernance & crises", S4_GOVERN),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "👔 SOC Exec — Hub", "fp-timesketch", "metric_type:ir_case",
    ["@timestamp", "case_id", "events_count"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 SOC Director Executive — Side panel", "fp-timesketch", "metric_type:ir_case",
    ["@timestamp", "case_id", "sketch_name", "events_count"],
    "Panneau latéral SOC Director Executive",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 SOC Director Executive Side panel"))
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
        ("%md\n# SOC Director Executive Playbook\nVision exécutive, KPIs board, stratégie et gouvernance.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-timesketch | stats count() by metric_type | sort - count()", "PPL"))
    return lines
