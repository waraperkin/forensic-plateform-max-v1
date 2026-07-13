#!/usr/bin/env python3
"""Phase 3 — Playbooks OSD (titres panels format Action — Object — Context)."""
from __future__ import annotations

import sys

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_refactor_osd import apply_osd  # noqa: E402


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Alias vers refactor OSD (playbooks)")
    ap.add_argument("--dry-run", action="store_true")
    return apply_osd(dry_run=ap.parse_args().dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
