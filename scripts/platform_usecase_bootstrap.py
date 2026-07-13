#!/usr/bin/env python3
"""Bootstrap IOCs + indices TI pour les 7 use cases forensic (livraison CERT)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cert_forensic_use_cases_e2e.py"


def main() -> int:
    if not SCRIPT.is_file():
        print(f"[bootstrap] KO script absent: {SCRIPT}", file=sys.stderr)
        return 1
    env = {**dict(__import__("os").environ), "UC_BOOTSTRAP_ONLY": "1"}
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--bootstrap-only"],
        cwd=str(ROOT),
        env=env,
    )
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
