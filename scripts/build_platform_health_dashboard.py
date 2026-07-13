#!/usr/bin/env python3
"""Génère config/opensearch/dashboards/fp-platform-health.ndjson."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_CONFIG = ROOT / "config" / "opensearch" / "dashboards" / "fp-platform-health.ndjson"
OUT_DASH = ROOT / "dashboards" / "opensearch" / "fp-platform-health.ndjson"
sys.path.insert(0, str(ROOT / "scripts"))

from osd_platform_health_lib import build_all_objects  # noqa: E402


def main() -> None:
    objects = build_all_objects()
    OUT_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    OUT_DASH.parent.mkdir(parents=True, exist_ok=True)
    for path in (OUT_CONFIG, OUT_DASH):
        with path.open("w", encoding="utf-8") as f:
            for o in objects:
                f.write(json.dumps(o, ensure_ascii=False) + "\n")
        print(f"wrote {path} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
