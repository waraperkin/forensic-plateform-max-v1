#!/usr/bin/env python3
"""Cross-Pivot setup — OS→TS + TS→OS."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    steps = [
        ("crosspivot_os_to_ts.py", "OS -> Timesketch"),
        ("crosspivot_ts_to_os.py", "Timesketch -> OS"),
    ]
    for script, label in steps:
        print(f"[crosspivot-setup] === {label} ===")
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT))
        if r.returncode != 0:
            return 1
    print("[crosspivot-setup] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
