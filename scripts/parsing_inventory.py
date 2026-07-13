#!/usr/bin/env python3
"""Inventaire parsing — indices FP, mappings, couverture champs."""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_master_lib import FP_LOG_FAMILIES, KEY_FIELDS, OS, field_coverage, list_fp_indices, session  # noqa: E402

REPORT = ROOT / "docs" / "PARSING_INVENTORY_REPORT.md"


def get_mapping(s, index: str) -> dict:
    r = s.get(f"{OS}/{index}/_mapping", timeout=30)
    if r.status_code != 200:
        return {}
    data = r.json()
    idx = list(data.keys())[0] if data else index
    return data.get(idx, {}).get("mappings", {}).get("properties", {})


def flatten_props(props: dict, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in props.items():
        path = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if "properties" in v:
            out.update(flatten_props(v["properties"], path))
        elif "type" in v:
            out[path] = v["type"]
    return out


def main() -> int:
    s = session()
    indices = list_fp_indices(s)
    lines = [
        "# Rapport inventaire parsing FP",
        "",
        f"Généré : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Indices FP",
        "",
        "| Index | Documents | Taille |",
        "|-------|-----------|--------|",
    ]
    for row in sorted(indices, key=lambda x: x.get("index", "")):
        lines.append(f"| {row.get('index','')} | {row.get('docs.count','0')} | {row.get('store.size','')} |")

    lines += ["", "## Couverture champs clés (7 derniers jours)", ""]
    samples = [
        ("forensic-linux-*", "Linux/Syslog"),
        ("forensic-windows-*", "Windows"),
        ("forensic-web-*", "Web"),
        ("forensic-uploads-*", "Uploads"),
        ("fp-platform-logs*", "Platform"),
        ("forensic-ti-opencti-*", "TI OpenCTI"),
        ("forensic-ti-enriched", "TI Enriched"),
        ("forensic-alerts-*", "Alertes"),
    ]
    problems: list[str] = []
    for pattern, label in samples:
        lines.append(f"### {label} (`{pattern}`)")
        lines.append("")
        lines.append("| Champ | Présent | Total | % |")
        lines.append("|-------|---------|-------|---|")
        for field in KEY_FIELDS[:12]:
            with_f, total = field_coverage(s, pattern, field)
            pct = f"{100 * with_f / total:.1f}" if total else "n/a"
            lines.append(f"| `{field}` | {with_f} | {total} | {pct} |")
            if total > 100 and field in ("event.dataset", "event.category", "@timestamp", "host.name") and with_f < total * 0.5:
                problems.append(f"{label}: `{field}` couverture faible ({pct}%)")
        lines.append("")

    lines += ["", "## Familles de logs — statut", ""]
    for fam, spec in FP_LOG_FAMILIES.items():
        idx = spec["indices"]
        with_f, total = field_coverage(s, idx, "event.dataset", spec.get("query"))
        status = "OK" if total == 0 or with_f >= total * 0.3 else "KO"
        lines.append(f"- **{fam}** (`{idx}`) : event.dataset {with_f}/{total} — **{status}**")
        if status == "KO" and total > 0:
            problems.append(f"Famille {fam}: event.dataset insuffisant")

    lines += ["", "## Pipelines ingest", ""]
    pr = s.get(f"{OS}/_ingest/pipeline", timeout=15)
    if pr.status_code == 200:
        for name in sorted(pr.json().keys()):
            lines.append(f"- `{name}`")

    lines += ["", "## Problèmes détectés", ""]
    if problems:
        for p in problems:
            lines.append(f"- {p}")
    else:
        lines.append("- Aucun problème critique détecté à l'inventaire.")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[parsing-inventory] Rapport écrit: {REPORT}")
    print(f"[parsing-inventory] {len(indices)} indices, {len(problems)} problème(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
