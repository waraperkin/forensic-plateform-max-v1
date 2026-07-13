#!/usr/bin/env python3
"""Verify API Sigma Master."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import (  # noqa: E402
    OS_URL,
    SIGMA_INDEX,
    count_saved_views,
    explore_query,
    load_sigma_yaml_files,
    load_state,
    os_session,
    sigma_rules_count_ts,
)

QUERIES = [
    ("sigma_tag", "tag:sigma OR message:*sigma*"),
    ("fp_sigma", "message:*FP-SIGMA*"),
    ("attack", "tag:attack OR message:*attack.t*"),
]


def main() -> int:
    fails = 0
    yaml_n = len(load_sigma_yaml_files())
    if yaml_n < 10:
        print(f"[sigma-master-verify] KO yaml={yaml_n}", file=sys.stderr)
        fails += 1
    else:
        print(f"[sigma-master-verify] OK yaml={yaml_n}")

    s = os_session()
    sr = s.post(f"{OS_URL}/{SIGMA_INDEX}/_search", json={"size": 0, "track_total_hits": True}, timeout=30)
    hits = sr.json().get("hits", {}).get("total", {})
    total = hits.get("value", 0) if isinstance(hits, dict) else hits
    if total < 400:
        print(f"[sigma-master-verify] WARN index {SIGMA_INDEX}={total} (cible 400)", file=sys.stderr)
    else:
        print(f"[sigma-master-verify] OK index {total}")

    rc = sigma_rules_count_ts()
    if rc < 400:
        print(f"[sigma-master-verify] WARN ts rules={rc} (cible 400)", file=sys.stderr)
    else:
        print(f"[sigma-master-verify] OK ts rules={rc}")

    for label, q in QUERIES:
        if not explore_query(q):
            print(f"[sigma-master-verify] KO explore {label}", file=sys.stderr)
            fails += 1
        else:
            print(f"[sigma-master-verify] OK explore {label}")

    if count_saved_views("[FP-Sigma-Master]") < 4:
        print("[sigma-master-verify] KO vues", file=sys.stderr)
        fails += 1

    print(f"[sigma-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
