#!/usr/bin/env python3
"""Verify templates IR."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import ZONES_DIR, list_view_names, sketch_context  # noqa: E402


def main() -> int:
    yaml = ZONES_DIR / "search_templates_incident_fp.yaml"
    if not yaml.is_file():
        print("[ts-incident-tpl-verify] KO yaml absent", file=sys.stderr)
        return 1
    s, h, sid, _ = sketch_context()
    names = list_view_names(s, h, sid)
    tpl = [n for n in names if "[FP-IR-Tpl]" in n]
    if len(tpl) < 4:
        print(f"[ts-incident-tpl-verify] KO views ({len(tpl)})", file=sys.stderr)
        return 1
    print(f"[ts-incident-tpl-verify] OK ({len(tpl)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
