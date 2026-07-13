#!/usr/bin/env python3
"""Restaure les references dashboard après import OSD (l'API _import les ignore souvent)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import requests
from fp_runtime_env import OSD_URL

OSD = OSD_URL
ROOT = Path(__file__).resolve().parent.parent


def restore_from_ndjson(path: Path) -> int:
    s = requests.Session()
    s.verify = False
    hdrs = {"osd-xsrf": "true", "securitytenant": "global"}
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        o = json.loads(line)
        if o.get("type") != "dashboard":
            continue
        refs = o.get("references") or []
        if not refs:
            continue
        payload = {"attributes": o["attributes"], "references": refs}
        r = s.put(f"{OSD}/api/saved_objects/dashboard/{o['id']}", headers=hdrs, json=payload, timeout=40)
        if r.status_code == 404:
            r = s.post(f"{OSD}/api/saved_objects/dashboard/{o['id']}", headers=hdrs, json=payload, timeout=40)
        if r.status_code in (200, 201):
            print(f"[restore-refs] OK {o['id']} ({len(refs)} refs)")
            n += 1
        else:
            print(f"[restore-refs] KO {o['id']} HTTP {r.status_code}", file=sys.stderr)
    return n


def main() -> int:
    files = list((ROOT / "dashboards" / "opensearch").glob("*.ndjson"))
    total = 0
    for f in files:
        total += restore_from_ndjson(f)
    print(f"[restore-refs] Bilan: {total} dashboard(s)")
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
