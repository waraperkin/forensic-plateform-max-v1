#!/usr/bin/env python3
"""Inventaire Full Spectrum — indices, champs, pipelines."""
from __future__ import annotations

import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_master_full_lib import FULL_LOG_FAMILIES, KEY_FIELDS_FULL, OS, field_coverage_24h, list_indices, session  # noqa: E402

REPORT = ROOT / "docs" / "PARSING_FULL_INVENTORY.md"


def main() -> int:
    s = session()
    indices = list_indices(s)
    lines = [
        "# Inventaire Parsing Full Spectrum",
        "",
        f"Généré : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Indices FP",
        "",
        "| Index | Documents |",
        "|-------|-----------|",
    ]
    by_prefix: dict[str, int] = defaultdict(int)
    for row in sorted(indices, key=lambda x: x.get("index", "")):
        idx = row.get("index", "")
        docs = int(row.get("docs.count", 0) or 0)
        lines.append(f"| {idx} | {docs} |")
        prefix = idx.split("-")[0] + "-" + (idx.split("-")[1] if len(idx.split("-")) > 1 else "")
        if idx.startswith("forensic-linux"):
            by_prefix["forensic-linux"] += docs
        elif idx.startswith("forensic-windows"):
            by_prefix["forensic-windows"] += docs
        elif idx.startswith("forensic-web"):
            by_prefix["forensic-web"] += docs
        elif idx.startswith("forensic-ti"):
            by_prefix["forensic-ti"] += docs
        elif idx.startswith("fp-"):
            by_prefix["fp-"] += docs

    lines += ["", "## Agrégat par famille", ""]
    for k, v in sorted(by_prefix.items()):
        lines.append(f"- **{k}*** : {v:,} documents")

    lines += ["", "## Couverture champs (24h)", ""]
    problems = []
    checks = [
        ("forensic-linux-*", "Linux"),
        ("forensic-windows-*", "Windows"),
        ("forensic-web-*", "Web"),
        ("forensic-uploads-*", "Uploads"),
        ("forensic-ti-opencti-*", "TI OpenCTI"),
        ("fp-platform-logs*", "Platform"),
    ]
    for pattern, label in checks:
        lines.append(f"### {label}")
        lines.append("| Champ | 24h | Total | % |")
        for field in KEY_FIELDS_FULL[:14]:
            w, t = field_coverage_24h(s, pattern, field)
            pct = f"{100*w/t:.1f}" if t else "n/a"
            lines.append(f"| `{field}` | {w} | {t} | {pct} |")
            if t > 100 and field in ("event.dataset", "@timestamp") and w < t * 0.2:
                problems.append(f"{label}: `{field}` faible")
        lines.append("")

    lines += ["", "## Pipelines", ""]
    pr = s.get(f"{OS}/_ingest/pipeline", timeout=15)
    if pr.status_code == 200:
        for n in sorted(pr.json().keys()):
            if n.startswith("fp-") or n.endswith("-ecs"):
                lines.append(f"- `{n}`")

    lines += ["", "## Familles configurées", ""]
    for fam in FULL_LOG_FAMILIES:
        lines.append(f"- `{fam}` → {FULL_LOG_FAMILIES[fam]['indices']}")

    lines += ["", "## Problèmes", ""]
    if problems:
        for p in problems:
            lines.append(f"- {p}")
    else:
        lines.append("- Inventaire sans alerte critique (backfill peut être nécessaire sur historique).")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[parsing-full-inventory] {REPORT}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
