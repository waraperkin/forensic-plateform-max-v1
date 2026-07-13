#!/usr/bin/env python3
"""Verify API Timesketch Purple Team."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import TS_URL  # noqa: E402
from timesketch_zones_lib import explore, sketch_context  # noqa: E402
from ts_purple_team_lib import (  # noqa: E402
    MITRE_TACTICS,
    PURPLE_TIMELINE_NAME,
    collect_purple_events,
    ecs_validate,
    is_purple_timeline,
    load_state,
)

QUERIES = [
    ("purple", "message:*purple* OR tag:purple"),
    ("mitre", "message:*mitre.id* OR tag:mitre"),
    ("ti", "tag:ti OR message:*ti.indicator*"),
    ("sigma", "message:*sigma*"),
    ("simulation", "message:*purple.scenario*"),
]


def main() -> int:
    fails = 0
    events = collect_purple_events()
    if len(events) < 6:
        print(f"[ts-purple-verify] KO events={len(events)}", file=sys.stderr)
        fails += 1

    purple_ok = mitre_ok = ti_ok = 0
    for ev in events[:40]:
        errs = ecs_validate(ev)
        if errs:
            print(f"[ts-purple-verify] KO ECS {errs}", file=sys.stderr)
            fails += 1
        if ev.get("purple.scenario"):
            purple_ok += 1
        if ev.get("mitre.id"):
            mitre_ok += 1
        if ev.get("ti.indicator.value") or ev.get("ti.ioc_value"):
            ti_ok += 1
    if purple_ok < 5 or mitre_ok < 5:
        print(f"[ts-purple-verify] KO purple={purple_ok} mitre={mitre_ok}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-purple-verify] OK ECS purple={purple_ok} mitre={mitre_ok} ti={ti_ok}")

    s, h, sid, indices = sketch_context()
    det = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()
    tls = det.get("objects", [{}])[0].get("timelines", [])
    if not any(is_purple_timeline(t.get("name") or "") for t in tls):
        print(f"[ts-purple-verify] KO timeline {PURPLE_TIMELINE_NAME}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-purple-verify] OK timeline {PURPLE_TIMELINE_NAME}")

    for label, q in QUERIES:
        ex = explore(s, h, sid, {"query_string": q, "size": 2, "indices": indices[:10]})
        if not ex.get("ok"):
            print(f"[ts-purple-verify] KO explore {label}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-purple-verify] OK explore {label}")

    st = load_state()
    for key in ("ttp_ts", "sim_os", "pt_dashboard"):
        if not st.get("pivots", {}).get(key, "").startswith("http"):
            print(f"[ts-purple-verify] KO pivot {key}", file=sys.stderr)
            fails += 1

    for script in (
        "ts_purple_team_stories_verify.py",
        "ts_purple_team_visualizations_verify.py",
        "ts_purple_team_templates_verify.py",
    ):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT))
        if r.returncode != 0:
            fails += 1

    print(f"[ts-purple-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
