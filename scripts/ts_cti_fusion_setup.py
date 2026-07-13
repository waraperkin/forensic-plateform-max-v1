#!/usr/bin/env python3
"""Timesketch CTI Fusion — setup (timeline, vues, stories, analyzers, fusion)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import resolve_sketch_id  # noqa: E402
from timesketch_master_lib import get_master_sketch_id, ts_client, upload_events_timeline, wait_timeline_ready  # noqa: E402
from timesketch_zones_lib import create_saved_view, explore, run_analyzers_on_sketch, sketch_context  # noqa: E402
from ts_cti_fusion_lib import (  # noqa: E402
    CTI_ANALYZERS,
    CTI_TIMELINE_NAME,
    collect_cti_events,
    pivot_ioc_to_os,
    pivot_ioc_to_ts,
    save_state,
    tag_ioc,
)

CTI_VIEWS = [
    ("Forensics — CTI TI Overview", "event.dataset:ti.* OR tag:ti OR message:*ti.indicator*"),
    ("Forensics — CTI IOC Domain/IP", "message:*ti.indicator* OR tag:ti.ioc"),
    ("Forensics — CTI MITRE TTP", "message:*ti.mitre* OR message:*T1110*"),
    ("Forensics — CTI Intrusion Sets", "message:*ti.group*"),
    ("Forensics — CTI Malware", "message:*ti.malware*"),
    ("Forensics — CTI Campaigns", "message:*ti.campaign*"),
    ("Forensics — CTI OpenCTI", "message:*ti.opencti*"),
    ("Forensics — CTI MISP", "message:*ti.misp*"),
]


import os
import time

# Sentinelle d'idempotence : ce setup (ré-upload timeline + attente indexation
# 240s + analyzers) est relancé par CHAQUE couche Master via sync_integrations,
# alors que la phase dédiée « Timesketch CTI Fusion » l'a déjà fait. On évite
# ainsi un full-start de plusieurs heures. Une exécution réussie < 45 min court-
# circuite les ré-invocations (sauf FP_FORCE_CTI_FUSION=1).
_SENTINEL = ROOT / "logs" / ".ts_cti_fusion.done"
_SENTINEL_TTL = int(os.environ.get("FP_CTI_FUSION_TTL", "2700"))


def _recently_done() -> bool:
    if os.environ.get("FP_FORCE_CTI_FUSION") == "1":
        return False
    try:
        age = time.time() - _SENTINEL.stat().st_mtime
        return age < _SENTINEL_TTL
    except OSError:
        return False


def _mark_done() -> None:
    try:
        _SENTINEL.parent.mkdir(parents=True, exist_ok=True)
        _SENTINEL.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), encoding="utf-8")
    except OSError:
        pass


def main() -> int:
    print("[ts-cti-fusion-setup] démarrage")
    if _recently_done():
        print("[ts-cti-fusion-setup] OK (déjà configuré récemment — idempotent, skip)")
        return 0
    events = collect_cti_events()
    if not events:
        print("[ts-cti-fusion-setup] ERREUR aucun événement CTI", file=sys.stderr)
        return 1
    print(f"[ts-cti-fusion-setup] events={len(events)}")

    client = ts_client()
    if not client:
        return 1
    sid = get_master_sketch_id(client)
    ok, tid = upload_events_timeline(client, sid, CTI_TIMELINE_NAME, events)
    if not ok:
        print("[ts-cti-fusion-setup] ERREUR upload timeline", file=sys.stderr)
        return 1
    print(f"[ts-cti-fusion-setup] timeline={CTI_TIMELINE_NAME} id={tid}")

    session = client["session"]
    headers = __import__("timesketch_io").api_headers(
        client, __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/"), sid
    )
    wait_timeline_ready(session, headers, sid, timeout=240)

    tag_ioc(sid, "malicious.example.com")
    tag_ioc(sid, "10.10.10.10")

    s, h, _, indices = sketch_context()
    views_ok = 0
    for name, q in CTI_VIEWS:
        if create_saved_view(s, h, sid, name, q, indices, f"CTI Fusion — {name}"):
            views_ok += 1
        ex = explore(s, h, sid, {"query_string": __import__("timesketch_zones_lib").ecs_query_to_ts(q), "size": 3, "indices": indices[:8]})
        if not ex.get("ok"):
            print(f"[ts-cti-fusion-setup] WARN explore {name}", file=sys.stderr)

    if tid:
        run_analyzers_on_sketch(sid, int(tid), CTI_ANALYZERS)

    for script in ("ts_cti_visualizations.py", "ts_cti_stories.py"):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT))
        if r.returncode != 0:
            print(f"[ts-cti-fusion-setup] WARN {script} rc={r.returncode}", file=sys.stderr)

    fr = subprocess.run([sys.executable, str(ROOT / "scripts" / "timesketch_fusion_engine.py")], cwd=str(ROOT))
    fusion_rc = fr.returncode

    pivots = [
        {"ioc": "malicious.example.com", "ts_url": pivot_ioc_to_ts("malicious.example.com", sid), "os_url": pivot_ioc_to_os("malicious.example.com")},
        {"ioc": "10.10.10.10", "ts_url": pivot_ioc_to_ts("10.10.10.10", sid), "os_url": pivot_ioc_to_os("10.10.10.10")},
    ]
    save_state(
        {
            "sketch_id": sid,
            "timeline_name": CTI_TIMELINE_NAME,
            "timeline_id": tid,
            "events": len(events),
            "views_ok": views_ok,
            "pivots": pivots,
            "fusion_rc": fusion_rc,
            "analyzers": CTI_ANALYZERS,
        }
    )
    print(f"[ts-cti-fusion-setup] OK sketch={sid} views={views_ok} fusion_rc={fusion_rc}")
    success = views_ok >= 5 and ok
    if success:
        _mark_done()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
