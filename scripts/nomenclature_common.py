#!/usr/bin/env python3
"""Utilitaires communs refactor nomenclature FP (titres uniquement, IDs préservés)."""
from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_PATH = ROOT / "config" / "nomenclature_official.yaml"
PLAN_PATH = ROOT / "config" / "nomenclature_refactor_plan.yaml"
INVENTORY_PATH = Path("/tmp/fp-nomenclature-inventory.json")
BACKUP_ROOT = ROOT / "backups" / "nomenclature"


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    if yaml:
        return yaml.safe_load(text) or {}
    return json.loads(text)


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if yaml:
        path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")
    else:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def collect_dashboard_title_map(official: dict[str, Any]) -> dict[str, str]:
    """object_id -> new_title (IDs inchangés)."""
    out: dict[str, str] = {}
    for section in (
        "osd_security",
        "osd_threat_intel",
        "osd_incident",
        "osd_purple",
        "osd_platform",
        "playbook_dashboards",
    ):
        block = official.get(section) or {}
        if section == "osd_purple" and "fp-purple-team-playbook" in block:
            out["fp-purple-team-playbook"] = block["fp-purple-team-playbook"]["new_title"]
            continue
        for k, v in block.items():
            if k in ("panel_sections", "panel_aliases"):
                continue
            if isinstance(v, dict) and "new_title" in v:
                out[k] = v["new_title"]
            elif isinstance(v, str):
                out[k] = v
    g = official.get("grafana") or {}
    for uid, v in g.items():
        if isinstance(v, dict):
            out[uid] = v.get("new_title", "")
        elif isinstance(v, str):
            out[uid] = v
    pb = official.get("playbook_dashboards") or {}
    for k, v in pb.items():
        out[k] = v if isinstance(v, str) else v.get("new_title", "")
    return {k: v for k, v in out.items() if v}


def collect_old_new_pairs(official: dict[str, Any]) -> list[tuple[str, str]]:
    """Paires (ancien_titre, nouveau_titre) pour remplacement dans les sources."""
    pairs: list[tuple[str, str]] = []
    title_map = collect_dashboard_title_map(official)
    # Anciens titres connus
    legacy = {
        "fp-opensearch-security": "FP — Security Events & TI",
        "fp-ti-overview": "FP — TI Overview",
        "fp-incident-commander-playbook": "FP — Incident Commander Playbook",
        "fp-purple-team-playbook": "FP — Purple Team Playbook",
        "fp-platform-health": "FP — Platform Health",
        "fp-opensearch-overview": "FP — OpenSearch Overview",
        "fp-ioc-matches": "FP — IOC Matches",
        "fp-ioc-threat-map": "FP — IOC Threat Map",
        "fp-case-ioc-view": "FP — Case IOC View",
        "fp-threat-hunting": "FP — Threat Hunting",
        "fp-mitre-dashboard": "FP — MITRE ATT&CK Coverage",
        "fp-observability-pipeline": "FP — Observability Pipeline Health",
        "fp-platform-health-gf": "FP — Platform Health",
        "fp-opensearch-metrics": "FP — OpenSearch Metrics",
        "fp-timesketch-metrics": "FP — Timesketch Metrics",
        "fp-cti-metrics": "FP — CTI Metrics",
        "fp-misp-metrics": "FP — MISP Metrics",
        "fp-thehive-metrics": "FP — TheHive Metrics",
        "fp-cortex-metrics": "FP — Cortex Metrics",
        "fp-grafana-metrics": "FP — Grafana Metrics",
        "fp-soc-autonomous-metrics": "FP — SOC Autonomous Mode Metrics",
        "fp-pipelines-parsing-metrics": "FP — Pipelines & Parsing Metrics",
        "fp-alerts-metrics": "FP — Alerts Metrics",
    }
    for oid, old in legacy.items():
        new = title_map.get(oid)
        if new and new != old:
            pairs.append((old, new))
    for oid, new in title_map.items():
        if oid in legacy:
            continue
        if oid.startswith("fp-") and "Playbook" in new:
            guess_old = f"FP — {oid.replace('fp-', '').replace('-', ' ').title()}"
            pairs.append((guess_old, new))
    # Playbooks hub
    for oid, new in (official.get("playbook_dashboards") or {}).items():
        old_guess = {
            "fp-analyst-playbook": "FP — Analyst Playbook",
            "fp-soc-manager-playbook": "FP — SOC Manager Playbook",
            "fp-incident-commander-playbook": "FP — Incident Commander Playbook",
            "fp-soc-director-playbook": "FP — SOC Director Playbook",
            "fp-soc-director-executive-playbook": "FP — SOC Director Executive Playbook",
            "fp-ti-lead-playbook": "FP — TI Lead Playbook",
            "fp-dfir-senior-playbook": "FP — DFIR Senior Playbook",
            "fp-purple-team-playbook": "FP — Purple Team Playbook",
            "fp-threat-hunting-lead-playbook": "FP — Threat Hunting Lead Playbook",
            "fp-soc-automation-playbook": "FP — SOC Automation Playbook",
            "fp-cti-fusion-center-playbook": "FP — CTI Fusion Center Playbook",
            "fp-cti-fusion-global-playbook": "FP — CTI Fusion Global Playbook",
            "fp-global-soc-command-center": "FP — Global SOC Command Center",
            "fp-cyber-crisis-management": "FP — Cyber Crisis Management",
            "fp-nation-state-cti-playbook": "FP — Nation-State CTI Playbook",
            "fp-autonomous-soc-playbook": "FP — Autonomous SOC Playbook",
            "fp-red-team-lead-playbook": "FP — Red Team Lead Playbook",
            "fp-blue-team-lead-playbook": "FP — Blue Team Lead Playbook",
        }.get(oid)
        if old_guess and (old_guess, new) not in pairs:
            pairs.append((old_guess, new))
    # QA / Timesketch labels
    ts = official.get("timesketch") or {}
    ts_old = {
        "explore": "Timesketch — Explore",
        "overview": "Timesketch — Overview",
        "intelligence": "Timesketch — Intelligence",
        "stories": "Timesketch — Stories",
    }
    for key, old in ts_old.items():
        lab = (ts.get(key) or {}).get("new_label")
        if lab:
            pairs.append((old, lab))
    pairs.append(("FP — Platform Health (Grafana)", title_map.get("fp-platform-health-gf", "Metrics — Platform Overview")))
    pairs.append(("Portail CERT — accueil stats", "CERT — Situation Overview"))
    pairs.append(("Portail CERT — Dashboard CERT", "CERT — Situation Overview"))
    pairs.append(("Portail IT — Dashboard IT", "IT — Exposure Overview"))
    pairs.append(("FP — Incident Commander", title_map.get("fp-incident-commander-playbook", "Incident Response — Commander")))
    pairs.append(("FP — Purple Team", title_map.get("fp-purple-team-playbook", "Purple Teaming — Operations")))
    # dédup, plus long d'abord
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for a, b in sorted(pairs, key=lambda x: -len(x[0])):
        if (a, b) not in seen and a != b:
            seen.add((a, b))
            out.append((a, b))
    return out


def transform_playbook_panel_title(old: str, patterns: list[dict[str, str]]) -> str:
    """Convertit S1 — IOC → Discover vers format Action — Object — Context si possible."""
    m = re.match(r"^S(\d+)\s*—\s*(.+)$", old.strip())
    if not m:
        return old
    body = m.group(2).strip()
    for p in patterns:
        if p["match"].lower() in body.lower():
            return p["replace"]
    if "→" in body:
        parts = [x.strip() for x in body.split("→", 1)]
        action = "Investigate"
        if "ioc" in parts[0].lower() or "enrich" in parts[0].lower():
            action = "Enrich"
        elif "alert" in parts[0].lower():
            action = "Respond"
        elif "timeline" in parts[0].lower() or "fusion" in parts[0].lower():
            action = "Analyze"
        elif "sigma" in parts[0].lower() or "hunt" in parts[0].lower():
            action = "Detect"
        elif "replay" in parts[0].lower():
            action = "Replay"
        obj = parts[0] if len(parts) == 1 else parts[0]
        ctx = parts[1] if len(parts) > 1 else "SOC"
        return f"{action} — {obj} — {ctx}"
    return old


def backup_paths(paths: list[Path], backup_dir: Path) -> None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    for p in paths:
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT) if p.is_relative_to(ROOT) else p.name
        dest = backup_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)


def rollback_from(backup_dir: Path) -> int:
    if not backup_dir.is_dir():
        return 0
    n = 0
    for src in backup_dir.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(backup_dir)
        dest = ROOT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        n += 1
    return n


def replace_in_file(path: Path, pairs: list[tuple[str, str]], dry_run: bool = False) -> int:
    if not path.is_file():
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    original = text
    for old, new in pairs:
        if old in text:
            text = text.replace(old, new)
    if text == original:
        return 0
    if not dry_run:
        path.write_text(text, encoding="utf-8")
    return 1


def log(msg: str) -> None:
    print(f"[nomenclature] {msg}", flush=True)
