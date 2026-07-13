#!/usr/bin/env python3
"""Phase 3 — Labels Timesketch / vues / stories (noms affichés)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_common import OFFICIAL_PATH, collect_old_new_pairs, load_yaml, log, replace_in_file  # noqa: E402

TS_SCRIPTS = [
    "timesketch_master_lib.py",
    "ts_incident_commander_lib.py",
    "ts_incident_commander_setup.py",
    "ts_purple_team_lib.py",
    "ts_purple_team_setup.py",
    "ts_cti_fusion_lib.py",
    "ts_cti_fusion_setup.py",
    "ts_incident_stories.py",
    "ts_purple_team_stories.py",
    "ts_cti_stories.py",
    "dashboard_metrics_lib.py",
]


def apply_timesketch(dry_run: bool = False) -> int:
    official = load_yaml(OFFICIAL_PATH)
    pairs = collect_old_new_pairs(official)
    ts = official.get("timesketch") or {}
    extra = []
    if ts.get("master_sketch", {}).get("new_name"):
        # Label UI uniquement — ne pas remplacer le nom sketch stocké ([FP] Timesketch Master)
        pass
    pairs = extra + pairs
    prefix_pairs = [
        ("[FP-IR]", "Forensics — IR"),
        ("[FP-Purple]", "Forensics — Purple"),
        ("[FP-CTI]", "Forensics — CTI"),
    ]
    changed = 0
    for name in TS_SCRIPTS:
        path = ROOT / "scripts" / name
        if not path.is_file():
            continue
        n = replace_in_file(path, pairs, dry_run=dry_run)
        text = path.read_text(encoding="utf-8", errors="replace")
        orig = text
        for old, new in prefix_pairs:
            text = text.replace(old, new)
        if text != orig and not dry_run:
            path.write_text(text, encoding="utf-8")
            n = 1
        if n:
            changed += 1
            log(f"Timesketch: {name}")
    log(f"Timesketch terminé — {changed} fichier(s)")
    return 0


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    return apply_timesketch(dry_run=ap.parse_args().dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
