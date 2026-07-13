#!/usr/bin/env python3
"""Timesketch Incident Commander — setup timeline IR, vues, stories, viz, templates."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import get_master_sketch_id, login, ts_client, upload_events_timeline, wait_timeline_ready  # noqa: E402
from timesketch_zones_lib import create_saved_view, explore, sketch_context  # noqa: E402
from ts_incident_commander_lib import (  # noqa: E402
    INCIDENT_TIMELINE_NAME,
    collect_incident_events,
    pivot_alert_to_os,
    pivot_alert_to_ts,
    pivot_host_to_ts,
    pivot_ic_dashboard,
    pivot_ip_to_ts,
    pivot_process_to_ts,
    pivot_ts_to_ic,
    pivot_user_to_ts,
    save_state,
)

IR_VIEWS = [
    ("Forensics — IR Full Incident", "message:*ir.phase* OR tag:ir"),
    ("Forensics — IR Phase — Detection", "message:*ir.phase=detection* OR tag:ir.detection"),
    ("Forensics — IR Phase — Containment", "message:*ir.phase=containment* OR tag:ir.containment"),
    ("Forensics — IR Phase — Eradication", "message:*ir.phase=eradication* OR tag:ir.eradication"),
    ("Forensics — IR Phase — Recovery", "message:*ir.phase=recovery* OR tag:ir.recovery"),
    ("Forensics — IR Alerts", "event.dataset:alert OR message:*event.dataset=alert*"),
    ("Forensics — IR DFIR + CTI", "message:*dfir* OR tag:ti OR message:*ti.*"),
    ("Forensics — IR Suspicious", "tag:suspicious OR tag:mitre*"),
]


def tag_ir_labels(sketch_id: int) -> bool:
    s, h = login()
    lr = s.post(
        f"{__import__('os').environ.get('TIMESKETCH_URL', 'http://localhost:5000')}/api/v1/sketches/{sketch_id}/attribute/",
        json={
            "name": "labels",
            "values": ["ir.detection", "ir.containment", "ir.eradication", "ir.recovery", "ir.case", "fp-incident-commander"],
            "ontology": "label",
            "action": "post",
        },
        headers={**h, "Referer": f"http://localhost:5000/sketch/{sketch_id}/", "Content-Type": "application/json"},
        timeout=25,
    )
    return lr.status_code in (200, 201)


import os
import time

# Idempotence (cf. ts_cti_fusion_setup) : relancé par TheHive Master via
# sync_integrations alors que la phase dédiée l'a déjà fait. Évite le ré-upload
# + attente d'indexation (240s) répétés.
_SENTINEL = ROOT / "logs" / ".ts_incident_commander.done"
_SENTINEL_TTL = int(os.environ.get("FP_CTI_FUSION_TTL", "2700"))


def _recently_done() -> bool:
    if os.environ.get("FP_FORCE_CTI_FUSION") == "1":
        return False
    try:
        return (time.time() - _SENTINEL.stat().st_mtime) < _SENTINEL_TTL
    except OSError:
        return False


def _mark_done() -> None:
    try:
        _SENTINEL.parent.mkdir(parents=True, exist_ok=True)
        _SENTINEL.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), encoding="utf-8")
    except OSError:
        pass


def main() -> int:
    print("[ts-incident-setup] démarrage")
    if _recently_done():
        print("[ts-incident-setup] OK (déjà configuré récemment — idempotent, skip)")
        return 0
    events = collect_incident_events()
    if len(events) < 5:
        print(f"[ts-incident-setup] ERREUR events={len(events)}", file=sys.stderr)
        return 1
    print(f"[ts-incident-setup] events={len(events)}")

    client = ts_client()
    if not client:
        return 1
    sid = get_master_sketch_id(client)
    ok, tid = upload_events_timeline(client, sid, INCIDENT_TIMELINE_NAME, events)
    if not ok:
        print("[ts-incident-setup] ERREUR upload timeline", file=sys.stderr)
        return 1

    session = client["session"]
    headers = __import__("timesketch_io").api_headers(
        client, __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/"), sid
    )
    wait_timeline_ready(session, headers, sid, timeout=240)
    tag_ir_labels(sid)

    s, h, _, indices = sketch_context()
    views_ok = 0
    for name, q in IR_VIEWS:
        if create_saved_view(s, h, sid, name, q, indices, f"Incident Commander — {name}"):
            views_ok += 1
        ex = explore(s, h, sid, {"query_string": __import__("timesketch_zones_lib").ecs_query_to_ts(q), "size": 3, "indices": indices[:10]})
        if not ex.get("ok"):
            print(f"[ts-incident-setup] WARN explore {name}", file=sys.stderr)

    ic_view = f"Forensics — IR Open Incident Commander"
    if create_saved_view(
        s,
        h,
        sid,
        ic_view,
        "ir.phase:detection",
        indices,
        f"INCIDENT_COMMANDER_URL={pivot_ic_dashboard()}",
    ):
        views_ok += 1

    for script in ("ts_incident_stories.py", "ts_incident_visualizations.py", "ts_incident_templates.py"):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT))
        if r.returncode != 0:
            print(f"[ts-incident-setup] WARN {script} rc={r.returncode}", file=sys.stderr)

    pivots = {
        "alert_ts": pivot_alert_to_ts("critical", sid),
        "alert_os": pivot_alert_to_os("critical"),
        "host_ts": pivot_host_to_ts("WIN-MASTER01", sid),
        "user_ts": pivot_user_to_ts("analyst", sid),
        "ip_ts": pivot_ip_to_ts("203.0.113.44", sid),
        "process_ts": pivot_process_to_ts("explorer.exe", sid),
        "ts_to_ic": pivot_ts_to_ic(sid, "detection"),
        "ic_dashboard": pivot_ic_dashboard(),
    }
    save_state({"sketch_id": sid, "timeline_id": tid, "events": len(events), "views_ok": views_ok, "pivots": pivots})
    print(f"[ts-incident-setup] OK sketch={sid} views={views_ok}")
    success = views_ok >= 6 and ok
    if success:
        _mark_done()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
