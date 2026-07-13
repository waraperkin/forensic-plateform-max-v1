#!/usr/bin/env python3
"""Verify templates Purple Team."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import ZONES_DIR, list_view_names, sketch_context  # noqa: E402


def main() -> int:
    if not (ZONES_DIR / "search_templates_purple_fp.yaml").is_file():
        print("[ts-purple-tpl-verify] KO yaml", file=sys.stderr)
        return 1
    s, h, sid, _ = sketch_context()
    tpl = [n for n in list_view_names(s, h, sid) if "[FP-Purple-Tpl]" in n]
    if len(tpl) < 6:
        print(f"[ts-purple-tpl-verify] KO ({len(tpl)})", file=sys.stderr)
        return 1
    print(f"[ts-purple-tpl-verify] OK ({len(tpl)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
