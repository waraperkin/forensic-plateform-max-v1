#!/usr/bin/env python3
"""Verify API Timesketch Incident Commander."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import TS_URL  # noqa: E402
from timesketch_zones_lib import explore, sketch_context  # noqa: E402
from ts_incident_commander_lib import (  # noqa: E402
    INCIDENT_TIMELINE_NAME,
    IR_PHASES,
    collect_incident_events,
    ecs_validate,
    is_incident_timeline,
    load_state,
)

PHASE_QUERIES = [
    ("detection", "message:*ir.phase=detection* OR tag:ir.detection"),
    ("containment", "message:*ir.phase=containment*"),
    ("eradication", "message:*ir.phase=eradication*"),
    ("recovery", "message:*ir.phase=recovery*"),
    ("alerts", "message:*event.dataset=alert* OR tag:ir"),
]


def main() -> int:
    fails = 0
    events = collect_incident_events()
    if len(events) < 5:
        print(f"[ts-incident-verify] KO events={len(events)}", file=sys.stderr)
        fails += 1

    phase_counts = {p: 0 for p in IR_PHASES}
    for ev in events[:50]:
        errs = ecs_validate(ev)
        if errs:
            print(f"[ts-incident-verify] KO ECS {errs}", file=sys.stderr)
            fails += 1
        p = ev.get("ir.phase")
        if p in phase_counts:
            phase_counts[p] += 1
    if sum(phase_counts.values()) < 3:
        print(f"[ts-incident-verify] KO phases {phase_counts}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-incident-verify] OK ECS phases {phase_counts}")

    s, h, sid, indices = sketch_context()
    det = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()
    tls = det.get("objects", [{}])[0].get("timelines", [])
    if not any(is_incident_timeline(t.get("name") or "") for t in tls):
        print(f"[ts-incident-verify] KO timeline {INCIDENT_TIMELINE_NAME}", file=sys.stderr)
        fails += 1
    else:
        print(f"[ts-incident-verify] OK timeline {INCIDENT_TIMELINE_NAME}")

    for label, q in PHASE_QUERIES:
        ex = explore(s, h, sid, {"query_string": q, "size": 2, "indices": indices[:10]})
        if not ex.get("ok"):
            print(f"[ts-incident-verify] KO explore {label}", file=sys.stderr)
            fails += 1
        else:
            print(f"[ts-incident-verify] OK explore {label}")

    st = load_state()
    for key in ("alert_ts", "host_ts", "ic_dashboard"):
        if not st.get("pivots", {}).get(key, "").startswith("http"):
            print(f"[ts-incident-verify] KO pivot {key}", file=sys.stderr)
            fails += 1

    for script in (
        "ts_incident_stories_verify.py",
        "ts_incident_visualizations_verify.py",
        "ts_incident_templates_verify.py",
    ):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT))
        if r.returncode != 0:
            fails += 1

    print(f"[ts-incident-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
