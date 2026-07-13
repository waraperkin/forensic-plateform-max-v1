#!/usr/bin/env python3
"""Timesketch Master Verify — API (ECS, fusion, analyzers, import pipeline)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import (  # noqa: E402
    MASTER_SKETCH,
    STATE_JSON,
    TS_URL,
    check,
    explore,
    login,
)

EXPECTED_ANALYZERS = {"sigma", "feature_extraction", "domain", "misp_analyzer"}


def run_sub(script: str) -> bool:
    p = ROOT / "scripts" / script
    r = subprocess.run([sys.executable, str(p)], cwd=str(ROOT))
    return r.returncode == 0


def main() -> int:
    ok_n, ko_n = 0, 0

    def tally(o: int, k: int) -> None:
        nonlocal ok_n, ko_n
        ok_n += o
        ko_n += k

    for script in (
        "timesketch_ecs_verify.py",
        "timesketch_fusion_verify.py",
    ):
        if not run_sub(script):
            o, k = check(script, False)
            tally(o, k)
        else:
            o, k = check(script, True)
            tally(o, k)

    s, h = login()
    sid = None
    if STATE_JSON.is_file():
        sid = json.loads(STATE_JSON.read_text(encoding="utf-8")).get("sketch_id")
    if not sid:
        r = s.get(f"{TS_URL}/api/v1/sketches/", headers=h, timeout=20)
        for sk in r.json().get("objects", []):
            if sk.get("name") == MASTER_SKETCH:
                sid = sk["id"]
                break
    if not sid:
        o, k = check("sketch Master", False)
        tally(o, k)
        return 1

    sid = int(sid)
    hsk = {**h, "Referer": f"{TS_URL}/sketch/{sid}/explore/"}
    det = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=hsk, timeout=25).json()["objects"][0]
    tls = det.get("timelines", [])
    o, k = check("timelines importées", len(tls) >= 1, str(len(tls)))
    tally(o, k)

    ar = s.get(f"{TS_URL}/api/v1/sketches/{sid}/analyzer/", headers=hsk, timeout=30)
    if ar.status_code == 200:
        names = {x.get("name", "") for x in ar.json()}
        o, k = check("analyzers whitelist", names == EXPECTED_ANALYZERS, str(sorted(names)))
        tally(o, k)
    else:
        o, k = check("GET analyzer", False, str(ar.status_code))
        tally(o, k)

    indices = [(tl.get("searchindex") or {}).get("index_name", "") for tl in tls if (tl.get("searchindex") or {}).get("index_name")]
    ex = explore(s, h, sid, {"query_string": "*", "size": 20, "indices": indices[:8]})
    o, k = check("explore events", ex.get("ok") and len(ex.get("events", [])) >= 1)
    tally(o, k)

    intel = s.get(f"{TS_URL}/api/v1/intelligence/tagmetadata/", headers=h, timeout=20)
    o, k = check("intelligence API", intel.status_code == 200)
    tally(o, k)

    print(f"[master-verify] bilan OK={ok_n} KO={ko_n}")
    return 0 if ko_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
