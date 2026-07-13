#!/usr/bin/env python3
"""Déploie cross-tool drill-down, pivots SOC, IR automation, correctifs TI."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    fails = 0
    steps = [
        [sys.executable, str(ROOT / "scripts" / "build_opensearch_dashboards.py")],
        [sys.executable, str(ROOT / "scripts" / "build_opensearch_siem_ti_dashboards.py")],
        [sys.executable, str(ROOT / "scripts" / "build_opensearch_observability.py")],
        ["bash", str(ROOT / "scripts" / "opensearch_dashboards_import_fp.sh")],
        ["bash", str(ROOT / "scripts" / "opensearch_dashboards_import_ti.sh")],
        ["bash", str(ROOT / "scripts" / "opensearch_dashboards_import_obs.sh")],
        [sys.executable, str(ROOT / "scripts" / "opensearch_drilldown_setup.py")],
        [sys.executable, str(ROOT / "scripts" / "opensearch_refresh_index_pattern.py"),
         "fp-events", "fp-logs", "fp-ti", "fp-ti-opencti", "fp-ti-misp", "fp-timesketch",
         "fp-obs-logs", "fp-mitre", "fp-fusion", "fp-ti-enriched"],
    ]
    for cmd in steps:
        r = subprocess.run(cmd, cwd=str(ROOT), timeout=600)
        if r.returncode != 0:
            print(f"[cross-pivot-ir] KO {' '.join(cmd)}", file=sys.stderr)
            fails += 1
        else:
            print(f"[cross-pivot-ir] OK {' '.join(Path(c).name for c in cmd[:2])}")

    # IR — traiter alertes récentes si demandé
    if os.environ.get("IR_AUTO_RUN", "1") != "0":
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "ir_auto_case.py")], cwd=str(ROOT), timeout=300)
        if r.returncode != 0:
            fails += 1

    print(f"[cross-pivot-ir] Bilan setup: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
