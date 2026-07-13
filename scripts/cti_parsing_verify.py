#!/usr/bin/env python3
"""Verify Parsing Master ↔ CTI."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from parsing_domain_verify_lib import hdrs, session, verify_dashboard_loads, verify_saved_search_ecs  # noqa: E402
from parsing_ecs_adapters import os_count  # noqa: E402


def main() -> int:
    s = session()
    problems: list[str] = []
    for dash in ("fp-ti-overview", "fp-ioc-matches", "fp-opensearch-security"):
        err = verify_dashboard_loads(s, dash)
        if err:
            problems.append(err)
    for idx, field in (
        ("forensic-ti-opencti-*", "event.dataset"),
        ("forensic-ti-*", "ioc_value"),
        ("forensic-ti-enriched*", "threat_score"),
    ):
        r = s.post(
            f"{__import__('os').environ.get('OS_URL', 'http://localhost:9200')}/{idx}/_search",
            json={"size": 0, "query": {"exists": {"field": field}}}, timeout=30,
        )
        if r.status_code != 200:
            problems.append(f"index {idx} inaccessible")
        else:
            v = r.json()["hits"]["total"]["value"]
            if v < 1:
                problems.append(f"{idx}: pas de {field}")
            else:
                print(f"[cti-parsing-verify] OK {idx} {field}={v}")
    c = os_count(s, "forensic-linux-*,forensic-windows-*", "ti_match:true")
    if c < 1:
        problems.append("ti_match:0 sur events")
    else:
        print(f"[cti-parsing-verify] OK ti_match events={c}")
    for sid in ("fp-drill-ti-opencti", "fp-drill-ti-match-logs"):
        problems.extend(verify_saved_search_ecs(s, sid, min_hits=0, check_os=False))
    import os
    osd = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
    vr = s.get(f"{osd}/api/saved_objects/visualization/fp-ti-viz-opencti-count", headers=hdrs(), timeout=15)
    if vr.status_code != 200:
        problems.append("viz fp-ti-viz-opencti-count absente")
    if problems:
        print(f"[cti-parsing-verify] {len(problems)} problème(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[cti-parsing-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
