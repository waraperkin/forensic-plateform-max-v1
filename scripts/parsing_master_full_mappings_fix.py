#!/usr/bin/env python3
"""Mappings Full Spectrum — typage FP-ECS-like."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_master_full_lib import merge_properties, put_index_template, session  # noqa: E402
from parsing_master_full_lib import OS  # noqa: E402

REPORT = ROOT / "docs" / "PARSING_FULL_MAPPINGS_REPORT.md"

EXTRA = {
    "event": {"properties": {
        "dataset": {"type": "keyword"}, "category": {"type": "keyword"}, "type": {"type": "keyword"},
        "code": {"type": "keyword"}, "provider": {"type": "keyword"}, "ingested": {"type": "date"},
    }},
    "log": {"properties": {"level": {"type": "keyword"}, "source": {"type": "keyword"}}},
    "host": {"properties": {"name": {"type": "keyword"}, "ip": {"type": "ip"}}},
    "user": {"properties": {"name": {"type": "keyword"}}},
    "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
    "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
    "process": {"properties": {"name": {"type": "keyword"}, "pid": {"type": "long"}, "command_line": {"type": "text"}}},
    "file": {"properties": {"name": {"type": "keyword"}, "path": {"type": "keyword"}}},
    "registry": {"properties": {"key": {"type": "keyword"}, "value": {"type": "keyword"}}},
    "dns": {"properties": {"question": {"properties": {"name": {"type": "keyword"}}}}},
    "http": {"properties": {
        "request": {"properties": {"method": {"type": "keyword"}}},
        "response": {"properties": {"status_code": {"type": "long"}, "bytes": {"type": "long"}}},
    }},
    "url": {"properties": {"full": {"type": "keyword", "ignore_above": 2048}, "path": {"type": "keyword"}, "domain": {"type": "keyword"}}},
    "fp": {"properties": {"parsing_version": {"type": "keyword"}, "ingest": {"type": "keyword"}}},
    "ti": {"properties": {"ioc_value": {"type": "keyword"}, "ioc_type": {"type": "keyword"}, "threat_score": {"type": "long"}}},
    "dfir": {"properties": {"artifact": {"type": "keyword"}, "tool": {"type": "keyword"}}},
    "ir": {"properties": {"case_id": {"type": "keyword"}}},
    "os_type": {"type": "keyword"},
    "csv_EventID": {"type": "keyword"},
    "csv_Computer": {"type": "keyword"},
    "ti_match": {"type": "boolean"},
}


def patch_template(s, name: str) -> bool:
    r = s.get(f"{OS}/_index_template/{name}", timeout=30)
    if r.status_code != 200:
        print(f"[parsing-full-mappings] skip {name}")
        return True
    tpl = r.json()["index_templates"][0]["index_template"]
    props = tpl.setdefault("template", {}).setdefault("mappings", {}).setdefault("properties", {})
    merge_properties(props, EXTRA)
    return put_index_template(s, name, tpl)


def main() -> int:
    s = session()
    fails = 0
    patched = []
    for name in (
        "forensic-ecs", "fp-parsing-master-full-pipeline", "fp-parsing-ti-pipeline",
        "fp-parsing-master-pipeline", "fp-events-ti-pipeline", "fp-platform-logs-template", "fp-ti-template",
    ):
        if patch_template(s, name):
            patched.append(name)
        else:
            fails += 1
    lines = [
        "# Rapport mappings Full Spectrum",
        "",
        f"Généré : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Templates patchés",
        "",
    ] + [f"- `{n}`" for n in patched]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[parsing-full-mappings] {REPORT}")
    return fails


if __name__ == "__main__":
    sys.exit(main())
