#!/usr/bin/env python3
"""Phase 3 — Renommage titres OSD (libs + builders), IDs préservés."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_common import (  # noqa: E402
    OFFICIAL_PATH,
    PLAN_PATH,
    collect_old_new_pairs,
    load_yaml,
    log,
    replace_in_file,
    transform_playbook_panel_title,
)


def apply_osd(dry_run: bool = False) -> int:
    official = load_yaml(OFFICIAL_PATH)
    plan = load_yaml(PLAN_PATH)
    pairs = collect_old_new_pairs(official)
    patterns = plan.get("playbook_patterns") or official.get("playbook_title_patterns") or []
    changed = 0

    globs = [
        "scripts/build_opensearch*.py",
        "scripts/osd_*.py",
        "scripts/build_opensearch_dashboards.py",
        "scripts/build_opensearch_siem_ti_dashboards.py",
        "scripts/build_opensearch_enterprise.py",
        "scripts/build_opensearch_observability.py",
        "scripts/osd_platform_health_lib.py",
        "scripts/detection_intel_master_lib.py",
        "scripts/fp_browser_qa_lib.py",
    ]
    paths: set[Path] = set()
    for g in globs:
        paths.update(ROOT.glob(g))

    for path in sorted(paths):
        if not path.is_file():
            continue
        n = replace_in_file(path, pairs, dry_run=dry_run)
        if n:
            changed += n
            log(f"OSD strings: {path.relative_to(ROOT)}")

        # Playbook panel titles S1 — ...
        text = path.read_text(encoding="utf-8", errors="replace")
        orig = text

        def repl(m: re.Match) -> str:
            old_title = m.group(2)
            new_title = transform_playbook_panel_title(old_title, patterns)
            if new_title == old_title:
                return m.group(0)
            return f'_e("{m.group(1)}", "{new_title}"'

        if "_e(" in text:
            text = re.sub(r'_e\(\s*"([^"]+)"\s*,\s*"([^"]+)"', repl, text)
        if text != orig and not dry_run:
            path.write_text(text, encoding="utf-8")
            changed += 1
            log(f"OSD playbooks: {path.relative_to(ROOT)}")

    # Index pattern titles in build_opensearch_dashboards
    idx_map = official.get("index_patterns") or {}
    bp = ROOT / "scripts" / "build_opensearch_dashboards.py"
    if bp.is_file() and idx_map:
        text = bp.read_text(encoding="utf-8")
        for iid, new_t in idx_map.items():
            text = re.sub(
                rf'(\("{re.escape(iid)}",\s*")[^"]+(")',
                rf"\g<1>{new_t}\2",
                text,
            )
        if not dry_run:
            bp.write_text(text, encoding="utf-8")
            changed += 1

    log(f"OSD terminé — {changed} fichier(s) touché(s)" + (" (dry-run)" if dry_run else ""))
    return 0 if changed >= 0 else 1


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    return apply_osd(dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
