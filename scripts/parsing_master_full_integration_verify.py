#!/usr/bin/env python3
"""Verify global Parsing Master ↔ Hunts ↔ Playbooks."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

VERIFY_SCRIPTS = [
    ("parsing_master_full_verify.py", "Parsing Master Full"),
    ("hunting_parsing_verify.py", "Hunting"),
    ("purple_team_parsing_verify.py", "Purple Team"),
    ("dfir_parsing_verify.py", "DFIR"),
    ("cti_parsing_verify.py", "CTI"),
    ("soc_parsing_verify.py", "SOC"),
    ("incident_parsing_verify.py", "Incident"),
]


def main() -> int:
    fails = 0
    for script, label in VERIFY_SCRIPTS:
        path = ROOT / "scripts" / script
        r = subprocess.run([PY, str(path)], cwd=str(ROOT), timeout=300)
        if r.returncode != 0:
            print(f"[integration-verify] KO {label}", file=sys.stderr)
            fails += 1
        else:
            print(f"[integration-verify] OK {label}")
    print(f"[integration-verify] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
