#!/usr/bin/env python3
"""Playbook Red Team Lead — opérations offensives, TTP, campagnes, gaps détection."""
from __future__ import annotations

import os

OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
DASH_ID = "fp-red-team-lead-playbook"
DASH_TITLE = "Purple Teaming — Red Team Lead"
NOTEBOOK_NAME = "Red Team Lead Playbook"
APP_NAME = "Red Team Lead"
LAUNCHER_ID = "fp-red-team-lead-launcher"
SIDE_ID = "fp-red-team-lead-side-panel"

PlaybookEntry = tuple[str, str, str, str, list[str], str]


def _e(sid: str, title: str, idx: str, q: str, cols: list[str], desc: str = "") -> PlaybookEntry:
    return (sid, title, idx, q, cols, desc or f"Red Team Lead — {title}")


S1_OPS: list[PlaybookEntry] = [
    _e("fp-rtl-s1-campaigns", "S1 — Campagnes offensives", "fp-events", "message:*red*team* OR message:*simulat*",
       ["@timestamp", "message", "host.name"]),
    _e("fp-rtl-s1-ttp", "S1 — TTP offensives", "fp-mitre", "*", ["@timestamp", "technique_id", "tactic"]),
    _e("fp-rtl-s1-tools", "S1 — Outils & payloads", "fp-events", "message:*payload* OR message:*c2*",
       ["@timestamp", "message", "host.name"]),
    _e("fp-rtl-s1-infra", "S1 — Infra attaquant", "fp-ti", "ioc_type: domain OR ioc_type: ip",
       ["@timestamp", "ioc_value", "ioc_type"]),
]

S2_SIM: list[PlaybookEntry] = [
    _e("fp-rtl-s2-scenarios", "S2 — Scénarios", "fp-fusion", "fusion_type:case",
       ["@timestamp", "fusion_type", "message"]),
    _e("fp-rtl-s2-chain", "S2 — Kill chain", "fp-mitre", "coverage_count >= 1",
       ["@timestamp", "technique_id", "tactic"]),
    _e("fp-rtl-s2-lateral", "S2 — Mouvement latéral", "fp-events", "event.code:4624 OR event.code:4625",
       ["@timestamp", "event.code", "user.name", "host.name"]),
    _e("fp-rtl-s2-exfil", "S2 — Exfiltration", "fp-events", "message:*exfil* OR message:*upload*",
       ["@timestamp", "message", "host.name"]),
]

S3_VAL: list[PlaybookEntry] = [
    _e("fp-rtl-s3-det-miss", "S3 — Détections manquées", "fp-events", "NOT ti_match: true AND message:*red*team*",
       ["@timestamp", "message", "host.name"]),
    _e("fp-rtl-s3-alert-miss", "Respond — Alert — SOC", "fp-logs", "_index:forensic-alerts*",
       ["@timestamp", "message", "level"]),
    _e("fp-rtl-s3-sigma-miss", "Detect — Sigma — Windows Logon", "fp-mitre", "rule_prefix: unmapped",
       ["@timestamp", "technique_id", "rule_prefix"]),
]

S4_REPORT: list[PlaybookEntry] = [
    _e("fp-rtl-s4-findings", "S4 — Findings", "fp-fusion", "fusion_type:alert",
       ["@timestamp", "alert_name", "message"]),
    _e("fp-rtl-s4-reco", "S4 — Recommandations", "fp-logs", "message:*recommend* OR message:*finding*",
       ["@timestamp", "message", "level"]),
    _e("fp-rtl-s4-mitre-gap", "S4 — Gaps MITRE", "fp-mitre", "coverage_count: 0",
       ["@timestamp", "technique_id", "tactic"]),
]

PLAYBOOK_SECTIONS = [
    ("1", "Opérations offensives", S1_OPS),
    ("2", "Simulation & kill chain", S2_SIM),
    ("3", "Validation détection", S3_VAL),
    ("4", "Reporting", S4_REPORT),
]

LAUNCHER: PlaybookEntry = (
    LAUNCHER_ID, "🔴 Red Team — Hub", "fp-mitre", "*",
    ["@timestamp", "technique_id", "tactic"],
    f"Hub — {OSD}/app/dashboards#/view/{DASH_ID}",
)

SIDE: PlaybookEntry = (
    SIDE_ID, "📋 Red Team Lead — Side panel", "fp-mitre", "coverage_count >= 1",
    ["@timestamp", "technique_id", "tactic", "coverage_count"],
    "Panneau latéral Red Team Lead",
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
    panels.append(search_panel(SIDE_ID, 0, y, 12, 28, "📋 Red Team Lead Side panel"))
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
        ("%md\n# Red Team Lead Playbook\nOpérations offensives, simulation, validation et reporting.", "MARKDOWN"),
        (f"%md\nDashboard: {DASH_TITLE}", "MARKDOWN"),
    ]
    for _n, title, entries in PLAYBOOK_SECTIONS:
        lines.append((f"%md\n## {title}", "MARKDOWN"))
        for sid, etitle, *_ in entries[:2]:
            lines.append((f"%md\n- {etitle} (`{sid}`)", "MARKDOWN"))
    lines.append(("source = fp-mitre-coverage | stats count() by tactic | sort - count()", "PPL"))
    return lines
