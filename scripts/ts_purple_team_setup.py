#!/usr/bin/env python3
"""Timesketch Purple Team — setup timeline, vues, stories, viz, templates."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import get_master_sketch_id, login, ts_client, upload_events_timeline, wait_timeline_ready  # noqa: E402
from timesketch_zones_lib import create_saved_view, explore, run_analyzers_on_sketch, sketch_context  # noqa: E402
from ts_purple_team_lib import (  # noqa: E402
    PURPLE_TIMELINE_NAME,
    collect_purple_events,
    pivot_pt_dashboard,
    pivot_simulation_to_os,
    pivot_simulation_to_ts,
    pivot_ttp_to_os,
    pivot_ttp_to_ts,
    save_state,
)

PURPLE_VIEWS = [
    ("Forensics — Purple Overview", "message:*purple* OR tag:purple OR purple_match:true"),
    ("Forensics — Purple MITRE TTP", "message:*mitre.id* OR tag:mitre*"),
    ("Forensics — Purple Simulations", "message:*purple.scenario* OR message:*simulat*"),
    ("Forensics — Purple Sigma validation", "message:*sigma* OR message:*FP-SIGMA*"),
    ("Forensics — Purple CTI IOC", "tag:ti OR message:*ti.indicator*"),
    ("Forensics — Purple DFIR artifacts", "message:*dfir* OR tag:dfir"),
    ("Forensics — Purple Suspicious", "tag:suspicious OR message:*suspicious*"),
]


def tag_purple_labels(sketch_id: int) -> bool:
    s, h = login()
    lr = s.post(
        f"{__import__('os').environ.get('TIMESKETCH_URL', 'http://localhost:5000')}/api/v1/sketches/{sketch_id}/attribute/",
        json={
            "name": "labels",
            "values": ["purple.simulation", "purple.execution", "mitre.t1059", "fp-purple-team", "sigma"],
            "ontology": "label",
            "action": "post",
        },
        headers={**h, "Referer": f"http://localhost:5000/sketch/{sketch_id}/", "Content-Type": "application/json"},
        timeout=25,
    )
    return lr.status_code in (200, 201)


def main() -> int:
    print("[ts-purple-setup] démarrage")
    events = collect_purple_events()
    if len(events) < 6:
        print(f"[ts-purple-setup] ERREUR events={len(events)}", file=sys.stderr)
        return 1
    print(f"[ts-purple-setup] events={len(events)}")

    client = ts_client()
    if not client:
        return 1
    sid = get_master_sketch_id(client)
    ok, tid = upload_events_timeline(client, sid, PURPLE_TIMELINE_NAME, events)
    if not ok:
        return 1

    session = client["session"]
    headers = __import__("timesketch_io").api_headers(
        client, __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/"), sid
    )
    wait_timeline_ready(session, headers, sid, timeout=240)
    tag_purple_labels(sid)

    if tid:
        run_analyzers_on_sketch(sid, int(tid), ["sigma", "domain", "feature_extraction"])

    s, h, _, indices = sketch_context()
    views_ok = 0
    for name, q in PURPLE_VIEWS:
        if create_saved_view(s, h, sid, name, q, indices, f"Purple Team — {name}"):
            views_ok += 1
        explore(s, h, sid, {"query_string": __import__("timesketch_zones_lib").ecs_query_to_ts(q), "size": 3, "indices": indices[:10]})

    create_saved_view(
        s, h, sid, "Forensics — Purple Open Purple Team OSD", "purple.scenario:*",
        indices, f"PURPLE_TEAM_URL={pivot_pt_dashboard()}",
    )
    views_ok += 1

    for script in ("ts_purple_team_stories.py", "ts_purple_team_visualizations.py", "ts_purple_team_templates.py"):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT))
        if r.returncode != 0:
            print(f"[ts-purple-setup] WARN {script} rc={r.returncode}", file=sys.stderr)

    pivots = {
        "ttp_ts": pivot_ttp_to_ts("T1059", sid),
        "ttp_os": pivot_ttp_to_os("T1059"),
        "sim_ts": pivot_simulation_to_ts("FP-SIM", sid),
        "sim_os": pivot_simulation_to_os("FP-SIM"),
        "pt_dashboard": pivot_pt_dashboard(),
    }
    save_state({"sketch_id": sid, "timeline_id": tid, "events": len(events), "views_ok": views_ok, "pivots": pivots})
    print(f"[ts-purple-setup] OK sketch={sid} views={views_ok}")
    return 0 if views_ok >= 6 and ok else 1


if __name__ == "__main__":
    sys.exit(main())
