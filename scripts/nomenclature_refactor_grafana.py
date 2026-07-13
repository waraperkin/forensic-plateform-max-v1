#!/usr/bin/env python3
"""Phase 3 — Renommage titres Grafana (builders + JSON export)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_common import OFFICIAL_PATH, collect_old_new_pairs, load_yaml, log, replace_in_file  # noqa: E402


def apply_grafana(dry_run: bool = False) -> int:
    official = load_yaml(OFFICIAL_PATH)
    pairs = collect_old_new_pairs(official)
    changed = 0
    for path in [ROOT / "scripts" / "build_grafana_master_dashboards.py"]:
        if replace_in_file(path, pairs, dry_run=dry_run):
            changed += 1
            log(f"Grafana builder: {path.name}")

    for path in (ROOT / "dashboards" / "grafana").rglob("*.json"):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        uid = d.get("uid", "")
        for old, new in pairs:
            if d.get("title") == old:
                d["title"] = new
        gmap = official.get("grafana") or {}
        if uid in gmap:
            nt = gmap[uid].get("new_title") if isinstance(gmap[uid], dict) else gmap[uid]
            if nt:
                d["title"] = nt
        for p in d.get("panels") or []:
            # panels gardent titres techniques sauf préfixe FP —
            t = p.get("title") or ""
            if t.startswith("FP —"):
                for old, new in pairs:
                    if t == old:
                        p["title"] = new
        if not dry_run:
            path.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        changed += 1
    log(f"Grafana terminé — {changed} artefact(s)")
    return 0


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    return apply_grafana(dry_run=ap.parse_args().dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
