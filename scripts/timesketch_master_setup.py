#!/usr/bin/env python3
"""Timesketch Master Setup — activation avancée + fusion + playbooks + import pipeline."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_py(name: str) -> int:
    script = ROOT / "scripts" / name
    print(f"[master-setup] → {name}")
    r = subprocess.run([sys.executable, str(script)], cwd=str(ROOT), env=os.environ.copy())
    return r.returncode


def main() -> int:
    skip_act = os.environ.get("TS_MASTER_SKIP_ACTIVATE", "0") != "1"
    if skip_act:
        act = ROOT / "scripts" / "activate_timesketch_advanced.sh"
        if act.is_file():
            print("[master-setup] activation Timesketch avancé...")
            if subprocess.run(["bash", str(act)], cwd=str(ROOT)).returncode != 0:
                print("[master-setup] WARN activation partielle", file=sys.stderr)

    steps = [
        "timesketch_ecs_adapter.py",
        "timesketch_fusion_engine.py",
        "timesketch_playbook_setup.py",
    ]
    for step in steps:
        if run_py(step) != 0:
            return 1

    exp = ROOT / "scripts" / "timesketch_export_grafana_metrics.py"
    if exp.is_file():
        subprocess.run([sys.executable, str(exp)], cwd=str(ROOT), env=os.environ.copy())

    print("[master-setup] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
