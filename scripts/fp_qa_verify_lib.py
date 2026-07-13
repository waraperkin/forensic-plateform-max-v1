#!/usr/bin/env python3
"""Vérification stricte post-exécution — impossible de valider sans preuves."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_browser_qa_lib import (  # noqa: E402
    BROWSER_RESULTS,
    EXPECTATIONS_PATH,
    load_qa_expectations,
    log_qa,
)


def verify_browser_results_strict(results_path: Path, label: str) -> int:
    if not results_path.is_file():
        log_qa(label, f"KO — fichier absent: {results_path}")
        return 1

    raw = json.loads(results_path.read_text(encoding="utf-8"))
    exp = load_qa_expectations()
    critical = exp.get("critical_views", [])
    steps = {s.get("name"): s for s in raw.get("steps", [])}
    fails = 0

    if raw.get("global_status") == "OK" and not exp.get("meta", {}).get("pessimistic"):
        log_qa(label, "WARN: mode non pessimiste")

  # Chaque vue critique doit avoir une étape explicite OK + screenshot
    for view in critical:
        step_name = _critical_to_step_name(view)
        candidates = [
            k
            for k in steps
            if k == step_name
            or step_name.rstrip(":") in k
            or view.split(".")[-1].lower() in k.lower()
        ]
        if not candidates:
            log_qa(label, f"KO vue critique non testée: {view}")
            fails += 1
            continue
        best = steps.get(candidates[0])
        if not best or not best.get("ok"):
            log_qa(label, f"KO vue critique FAIL: {view} — {best.get('detail') if best else 'absent'}")
            fails += 1
            continue
        shot = best.get("screenshot") or ""
        if exp.get("meta", {}).get("require_screenshot_critical") and not shot:
            log_qa(label, f"KO screenshot manquant: {view}")
            fails += 1
        elif shot and not Path(shot).is_file():
            log_qa(label, f"KO screenshot introuvable: {shot}")
            fails += 1

    # Attentes YAML référencées dans steps
    for s in raw.get("steps", []):
        if s.get("expectation_key") and not s.get("ok"):
            log_qa(label, f"KO attente {s.get('expectation_key')}: {s.get('detail', '')[:100]}")
            fails += 1

    if raw.get("global_status") != "OK":
        log_qa(label, f"KO global_status={raw.get('global_status')} errors={raw.get('error_count')}")
        fails += 1

    if fails:
        log_qa(label, f"VERIFY FAIL — {fails} problème(s) bloquant(s)")
        return 1

    log_qa(label, f"verify technique OK ({len(critical)} vues critiques avec preuves) — validation humaine requise")
    return 0


def _critical_to_step_name(view: str) -> str:
    """timesketch.explore -> ts:Explore ou timesketch.explore"""
    parts = view.split(".")
    if parts[0] == "timesketch" and len(parts) > 1:
        return f"ts:{parts[1].capitalize()}"
    if parts[0] == "osd":
        if parts[1] == "discover":
            return "osd:Discover"
        return "osd:FP"
    if parts[0] == "grafana":
        return "grafana:Platform"
    if parts[0] == "portal_cert":
        if "dashboard_cert" in view:
            return "portal:tab-dashboard-cert"
        if "dashboard_it" in view:
            return "portal:tab-dashboard-it"
        return "portal:"
    return view.replace(".", ":")
