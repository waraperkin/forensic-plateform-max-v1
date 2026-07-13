#!/usr/bin/env python3
"""CTI stories automatiques — IOC, malware, intrusion set, campaign, MITRE."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import login, TS_URL  # noqa: E402
from timesketch_zones_lib import sketch_context  # noqa: E402

STORY_TITLES = [
    "CTI — IOC Investigation",
    "CTI — Malware Analysis",
    "CTI — Intrusion Set Review",
    "CTI — Campaign Timeline",
    "CTI — MITRE TTP Mapping",
]


def main() -> int:
    s, h, sid, _ = sketch_context()
    created = 0
    for title in STORY_TITLES:
        r = s.post(
            f"{TS_URL}/api/v1/sketches/{sid}/stories/",
            json={"title": f"Forensics — {title}", "components": [{"type": "text", "content": f"Auto CTI story: {title}"}]},
            headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/story/", "Content-Type": "application/json"},
            timeout=25,
        )
        if r.status_code in (200, 201):
            created += 1
    print(f"[ts-cti-stories] created={created}/{len(STORY_TITLES)}")
    return 0 if created >= len(STORY_TITLES) else 1


if __name__ == "__main__":
    sys.exit(main())
