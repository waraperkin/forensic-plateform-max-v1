#!/usr/bin/env python3
"""Corrige mappings FP pour champs Parsing Master (templates)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_master_lib import OS, put_index_template, session  # noqa: E402

REPORT = ROOT / "docs" / "PARSING_MAPPINGS_REPORT.md"

EXTRA_PROPERTIES = {
    "event": {
        "properties": {
            "dataset": {"type": "keyword"},
            "category": {"type": "keyword"},
            "type": {"type": "keyword"},
            "code": {"type": "keyword"},
            "module": {"type": "keyword"},
            "ingested": {"type": "date"},
        }
    },
    "log": {
        "properties": {
            "level": {"type": "keyword"},
            "source": {"type": "keyword"},
        }
    },
    "url": {
        "properties": {
            "full": {"type": "keyword", "ignore_above": 2048},
            "path": {"type": "keyword"},
            "domain": {"type": "keyword"},
        }
    },
    "http": {
        "properties": {
            "request": {"properties": {"method": {"type": "keyword"}}},
            "response": {"properties": {"status_code": {"type": "long"}, "bytes": {"type": "long"}}},
        }
    },
    "user": {"properties": {"name": {"type": "keyword"}}},
    "process": {
        "properties": {
            "name": {"type": "keyword"},
            "pid": {"type": "long"},
        }
    },
    "file": {"properties": {"name": {"type": "keyword"}}},
    "fp": {"properties": {"parsing_version": {"type": "keyword"}}},
    "ti": {
        "properties": {
            "ioc_value": {"type": "keyword"},
            "ioc_type": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "threat_score": {"type": "long"},
        }
    },
    "ti_match": {"type": "boolean"},
    "ti_ioc_value": {"type": "keyword"},
    "ti_sources": {"type": "keyword"},
}


def merge_properties(target: dict, extra: dict) -> None:
    for k, v in extra.items():
        if k not in target:
            target[k] = v
        elif "properties" in v and "properties" in target.get(k, {}):
            merge_properties(target[k]["properties"], v["properties"])
        else:
            target[k] = v


def patch_template(s, name: str) -> bool:
    r = s.get(f"{OS}/_index_template/{name}", timeout=30)
    if r.status_code != 200:
        print(f"[parsing-mappings] skip {name} HTTP {r.status_code}")
        return True
    tpl = r.json().get("index_templates", [{}])[0].get("index_template", {})
    props = tpl.setdefault("template", {}).setdefault("mappings", {}).setdefault("properties", {})
    merge_properties(props, EXTRA_PROPERTIES)
    return put_index_template(s, name, tpl)


def main() -> int:
    s = session()
    fails = 0
    patched = []
    for name in (
        "forensic-ecs",
        "fp-parsing-master-pipeline",
        "fp-parsing-ti-pipeline",
        "fp-events-ti-pipeline",
        "fp-platform-logs-template",
        "fp-ti-template",
    ):
        if patch_template(s, name):
            patched.append(name)
        else:
            fails += 1

    lines = [
        "# Rapport mappings Parsing Master",
        "",
        f"Généré : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Templates patchés",
        "",
    ]
    for n in patched:
        lines.append(f"- `{n}`")
    lines += [
        "",
        "## Champs normalisés ajoutés",
        "",
        "- `event.dataset`, `event.category`, `event.type`, `event.ingested`",
        "- `log.level`, `log.source`",
        "- `url.path`, `url.full`, `http.*`",
        "- `fp.parsing_version`, `ti.*`",
        "",
        "## Note reindex",
        "",
        "Les documents existants conservent leurs types jusqu'à reindex ou `_update_by_query`.",
        "Le backfill Parsing Master applique les champs via script painless.",
        "",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"[parsing-mappings] Rapport: {REPORT}")
    print(f"[parsing-mappings] Bilan: {fails} échec(s)")
    return fails


if __name__ == "__main__":
    sys.exit(main())
