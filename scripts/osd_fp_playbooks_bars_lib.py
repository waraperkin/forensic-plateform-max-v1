#!/usr/bin/env python3
"""Barre supérieure FP — 18 playbooks premium (3 lignes × 6)."""
from __future__ import annotations

from osd_analyst_playbook_lib import PLAYBOOK_LAUNCHER_ID, shift_panels_down

ANALYST_LAUNCHER = PLAYBOOK_LAUNCHER_ID
SOC_MANAGER_LAUNCHER = "fp-soc-manager-launcher"
INCIDENT_COMMANDER_LAUNCHER = "fp-incident-commander-launcher"
SOC_DIRECTOR_LAUNCHER = "fp-soc-director-launcher"
SOC_DIRECTOR_EXEC_LAUNCHER = "fp-soc-director-executive-launcher"
TI_LEAD_LAUNCHER = "fp-ti-lead-launcher"
DFIR_SENIOR_LAUNCHER = "fp-dfir-senior-launcher"
PURPLE_TEAM_LAUNCHER = "fp-purple-team-launcher"
TH_HUNT_LEAD_LAUNCHER = "fp-threat-hunting-lead-launcher"
SOC_AUTOMATION_LAUNCHER = "fp-soc-automation-launcher"
CTI_FUSION_LAUNCHER = "fp-cti-fusion-launcher"
CTI_FUSION_GLOBAL_LAUNCHER = "fp-cti-fusion-global-launcher"
GLOBAL_SOC_LAUNCHER = "fp-global-soc-command-center-launcher"
CYBER_CRISIS_LAUNCHER = "fp-cyber-crisis-management-launcher"
NATION_STATE_LAUNCHER = "fp-nation-state-cti-launcher"
AUTONOMOUS_SOC_LAUNCHER = "fp-autonomous-soc-launcher"
RED_TEAM_LAUNCHER = "fp-red-team-lead-launcher"
BLUE_TEAM_LAUNCHER = "fp-blue-team-lead-launcher"

ALL_LAUNCHERS = [
    ANALYST_LAUNCHER,
    SOC_MANAGER_LAUNCHER,
    INCIDENT_COMMANDER_LAUNCHER,
    SOC_DIRECTOR_LAUNCHER,
    SOC_DIRECTOR_EXEC_LAUNCHER,
    TI_LEAD_LAUNCHER,
    DFIR_SENIOR_LAUNCHER,
    PURPLE_TEAM_LAUNCHER,
    TH_HUNT_LEAD_LAUNCHER,
    SOC_AUTOMATION_LAUNCHER,
    CTI_FUSION_LAUNCHER,
    CTI_FUSION_GLOBAL_LAUNCHER,
    GLOBAL_SOC_LAUNCHER,
    CYBER_CRISIS_LAUNCHER,
    NATION_STATE_LAUNCHER,
    AUTONOMOUS_SOC_LAUNCHER,
    RED_TEAM_LAUNCHER,
    BLUE_TEAM_LAUNCHER,
]

ROW_H = 3
BAR_HEIGHT = 9
PER_ROW = 6
COL_W = 8

FP_DASHBOARDS_ALL = [
    "fp-opensearch-overview",
    "fp-opensearch-security",
    "fp-ti-overview",
    "fp-ioc-matches",
    "fp-ioc-threat-map",
    "fp-case-ioc-view",
    "fp-observability-pipeline",
    "fp-mitre-dashboard",
    "fp-threat-hunting",
    "fp-analyst-playbook",
    "fp-soc-manager-playbook",
    "fp-incident-commander-playbook",
    "fp-soc-director-playbook",
    "fp-soc-director-executive-playbook",
    "fp-ti-lead-playbook",
    "fp-dfir-senior-playbook",
    "fp-purple-team-playbook",
    "fp-threat-hunting-lead-playbook",
    "fp-soc-automation-playbook",
    "fp-cti-fusion-center-playbook",
    "fp-cti-fusion-global-playbook",
    "fp-global-soc-command-center",
    "fp-cyber-crisis-management",
    "fp-nation-state-cti-playbook",
    "fp-autonomous-soc-playbook",
    "fp-red-team-lead-playbook",
    "fp-blue-team-lead-playbook",
    "fp-platform-health",
]

BAR_BUTTONS = [
    (ANALYST_LAUNCHER, "📘 Analyst"),
    (SOC_MANAGER_LAUNCHER, "👔 SOC Mgr"),
    (INCIDENT_COMMANDER_LAUNCHER, "🚨 IC"),
    (SOC_DIRECTOR_LAUNCHER, "🎯 SOC Dir"),
    (SOC_DIRECTOR_EXEC_LAUNCHER, "👔 SOC Exec"),
    (TI_LEAD_LAUNCHER, "🛡️ TI Lead"),
    (DFIR_SENIOR_LAUNCHER, "🔬 DFIR"),
    (PURPLE_TEAM_LAUNCHER, "🟣 Purple"),
    (TH_HUNT_LEAD_LAUNCHER, "🏹 TH Lead"),
    (SOC_AUTOMATION_LAUNCHER, "⚙️ SOC Auto"),
    (CTI_FUSION_LAUNCHER, "🔗 CTI Fusion"),
    (CTI_FUSION_GLOBAL_LAUNCHER, "🌐 CTI Global"),
    (GLOBAL_SOC_LAUNCHER, "🌍 Global SOC"),
    (CYBER_CRISIS_LAUNCHER, "🚨 Crisis"),
    (NATION_STATE_LAUNCHER, "🏛️ Nation CTI"),
    (AUTONOMOUS_SOC_LAUNCHER, "🤖 Autonomous"),
    (RED_TEAM_LAUNCHER, "🔴 Red Team"),
    (BLUE_TEAM_LAUNCHER, "🔵 Blue Team"),
]


def fp_playbooks_bar_panels(y: int = 0, h: int = BAR_HEIGHT) -> tuple[list[dict], list[dict]]:
    from osd_drilldown_lib import search_panel  # noqa: E402

    panels: list[dict] = []
    refs: list[dict] = []
    for row_idx in range(3):
        row_buttons = BAR_BUTTONS[row_idx * PER_ROW : (row_idx + 1) * PER_ROW]
        for col_idx, (sid, title) in enumerate(row_buttons):
            panels.append(search_panel(sid, col_idx * COL_W, y + row_idx * ROW_H, COL_W, ROW_H, title))
            refs.append({"name": f"panel_{sid}", "type": "search", "id": sid})
    return panels, refs


fp_triple_bar_panels = fp_playbooks_bar_panels


def has_full_playbooks_bar(panels: list[dict]) -> bool:
    ids = {p.get("panelIndex") for p in panels}
    return all(lid in ids for lid in ALL_LAUNCHERS)


has_triple_bar = has_full_playbooks_bar


def _bar_shift_amount(panels: list[dict]) -> int:
    shift_y = 0
    for p in panels:
        if p.get("panelIndex") in ALL_LAUNCHERS:
            g = p["gridData"]
            shift_y = max(shift_y, g.get("y", 0) + g.get("h", ROW_H))
    return shift_y if shift_y else BAR_HEIGHT


def inject_fp_playbooks_bar(panels: list[dict]) -> tuple[list[dict], list[dict]]:
    if has_full_playbooks_bar(panels):
        return panels, []

    strip_ids = set(ALL_LAUNCHERS) | {
        "fp-pb-s1-ioc-discover",
        "fp-pb-s2-alert-case",
        "fp-pb-s8-fusion-all",
        "fp-pb-s9-mitre-heatmap",
    }
    shift_y = _bar_shift_amount(panels)
    had_bar = shift_y > 0
    filtered = [p for p in panels if p.get("panelIndex") not in strip_ids]
    if had_bar:
        out = []
        for p in filtered:
            p2 = dict(p)
            g = dict(p2["gridData"])
            if g.get("y", 0) >= shift_y:
                g["y"] = g["y"] - shift_y
            p2["gridData"] = g
            out.append(p2)
        filtered = out

    bar, refs = fp_playbooks_bar_panels(0, BAR_HEIGHT)
    shifted = shift_panels_down(filtered, BAR_HEIGHT)
    return bar + shifted, refs


inject_fp_triple_bar = inject_fp_playbooks_bar
