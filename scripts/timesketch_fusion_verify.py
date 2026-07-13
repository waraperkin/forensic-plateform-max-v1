#!/usr/bin/env python3
"""Vérifie la timeline fusionnée Timesketch Master (API + comptages)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import (  # noqa: E402
    LOG_DIR,
    MASTER_SKETCH,
    STATE_JSON,
    explore,
    login,
)


def main() -> int:
    failed = 0
    s, h = login()
    state = {}
    if STATE_JSON.is_file():
        state = json.loads(STATE_JSON.read_text(encoding="utf-8"))
    sid = state.get("sketch_id")
    if not sid:
        r = s.get(f"{__import__('os').environ.get('TIMESKETCH_URL', 'http://localhost:5000')}/api/v1/sketches/", headers=h, timeout=20)
        for sk in r.json().get("objects", []):
            if sk.get("name") == MASTER_SKETCH:
                sid = sk["id"]
                break
    if not sid:
        print("[fusion-verify] KO sketch Master introuvable", file=sys.stderr)
        return 1
    sid = int(sid)
    det = s.get(
        f"{__import__('os').environ.get('TIMESKETCH_URL', 'http://localhost:5000').rstrip('/')}/api/v1/sketches/{sid}/",
        headers={**h, "Referer": f"{__import__('os').environ.get('TIMESKETCH_URL', 'http://localhost:5000')}/sketch/{sid}/"},
        timeout=25,
    ).json()["objects"][0]
    tls = det.get("timelines", [])
    if len(tls) < 2:
        print(f"[fusion-verify] KO timelines={len(tls)} (attendu >=2)", file=sys.stderr)
        failed += 1
    indices = [(tl.get("searchindex") or {}).get("index_name", "") for tl in tls if (tl.get("searchindex") or {}).get("index_name")]
    ex = explore(s, h, sid, {"query_string": "*", "size": 30, "indices": indices[:8]})
    if not ex.get("ok"):
        print(f"[fusion-verify] KO explore {ex.get('status')}", file=sys.stderr)
        failed += 1
    events = ex.get("events", [])
    if len(events) < 1:
        print("[fusion-verify] KO aucun événement", file=sys.stderr)
        failed += 1
    fusion_hit = False
    tag_hit = False
    for ev in events:
        src = ev.get("_source") if isinstance(ev, dict) else ev
        if not isinstance(src, dict):
            continue
        blob = json.dumps(src, default=str).lower()
        if "fusion" in blob or "dfir.fusion" in blob:
            fusion_hit = True
        if src.get("tag") or src.get("tags"):
            tag_hit = True
    for q in ("hostname:WIN-MASTER01", "user:analyst", "message:*203.0.113*"):
        pr = explore(s, h, sid, {"query_string": q, "size": 5, "indices": indices[:4]})
        if not pr.get("ok"):
            print(f"[fusion-verify] KO pivot {q}", file=sys.stderr)
            failed += 1
    if not fusion_hit:
        print("[fusion-verify] WARN fusion marker absent (timeline partielle OK)", file=sys.stderr)
    if not tag_hit:
        print("[fusion-verify] KO tags invisibles", file=sys.stderr)
        failed += 1
    print(f"[fusion-verify] sketch={sid} timelines={len(tls)} events={len(events)} errors={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
