#!/usr/bin/env python3
"""Stories Purple Team — tactiques MITRE + chaîne complète."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import TS_URL  # noqa: E402
from timesketch_zones_lib import sketch_context  # noqa: E402

STORIES = [
    "Purple — Initial Access",
    "Purple — Execution",
    "Purple — Persistence",
    "Purple — Privilege Escalation",
    "Purple — Defense Evasion",
    "Purple — Impact",
    "Purple — Full Attack Chain",
]


def main() -> int:
    s, h, sid, _ = sketch_context()
    created = 0
    for title in STORIES:
        r = s.post(
            f"{TS_URL}/api/v1/sketches/{sid}/stories/",
            json={"title": f"Forensics — {title}", "components": [{"type": "text", "content": f"Purple Team: {title}"}]},
            headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/story/", "Content-Type": "application/json"},
            timeout=25,
        )
        if r.status_code in (200, 201):
            created += 1
    print(f"[ts-purple-stories] created={created}/{len(STORIES)}")
    return 0 if created >= len(STORIES) else 1


if __name__ == "__main__":
    sys.exit(main())
