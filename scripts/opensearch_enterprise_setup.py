#!/usr/bin/env python3
"""Déploie les 5 modules Enterprise FP."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(cmd: list[str], label: str) -> bool:
    r = subprocess.run(cmd, cwd=str(ROOT), timeout=900)
    if r.returncode != 0:
        print(f"[enterprise] KO {label}", file=sys.stderr)
        return False
    print(f"[enterprise] OK {label}")
    return True


def main() -> int:
    py = sys.executable
    scripts = ROOT / "scripts"
    steps = [
        ([py, str(scripts / "cluster_repair.py")], "cluster repair"),
        ([py, str(scripts / "mitre_mapping.py")], "MITRE mapping"),
        ([py, str(scripts / "sigma_convert.py")], "Sigma convert"),
        ([py, str(scripts / "threat_hunting_setup.py")], "threat hunting catalog"),
        ([py, str(scripts / "cti_enrich.py")], "CTI enrich"),
        ([py, str(scripts / "forensic_fusion.py")], "forensic fusion"),
        ([py, str(scripts / "build_opensearch_enterprise.py")], "build enterprise"),
        ([py, str(scripts / "build_opensearch_dashboards.py")], "build SIEM"),
        ([py, str(scripts / "build_opensearch_siem_ti_dashboards.py")], "build TI"),
        ([py, str(scripts / "ux_optimize.py")], "UX optimize"),
        (["bash", str(scripts / "opensearch_dashboards_import_fp.sh")], "import FP"),
        (["bash", str(scripts / "opensearch_dashboards_import_ti.sh")], "import TI"),
        (["bash", str(scripts / "opensearch_dashboards_import_enterprise.sh")], "import enterprise"),
        ([py, str(scripts / "opensearch_restore_dashboard_refs.py")], "restore dashboard refs"),
        ([py, str(scripts / "opensearch_drilldown_setup.py")], "drilldown"),
        ([py, str(scripts / "opensearch_restore_dashboard_refs.py")], "restore refs post-drilldown"),
        ([py, str(scripts / "opensearch_refresh_index_pattern.py"),
          "fp-events", "fp-logs", "fp-ti", "fp-ti-opencti", "fp-ti-misp", "fp-mitre", "fp-fusion", "fp-ti-enriched"],
         "refresh patterns"),
        ([py, str(scripts / "threat_hunting_setup.py")], "threat hunting verify"),
    ]
    fails = sum(0 if run(c, l) else 1 for c, l in steps)
    print(f"[enterprise] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
