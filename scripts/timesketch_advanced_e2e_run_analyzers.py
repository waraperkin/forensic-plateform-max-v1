#!/usr/bin/env python3
"""Lance les analyzers whitelistés et attend la fin (POINT 3 E2E)."""
from __future__ import annotations

import os
import re
import sys
import time

import requests

TS = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
USER = os.environ.get("TIMESKETCH_USER", "admin")
PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
CASE = os.environ.get("TS_ADV_E2E_CASE_ID", "")
SKETCH_ID = os.environ.get("TS_ADV_E2E_SKETCH_ID", "").strip()
WAIT_SEC = int(os.environ.get("TS_ADV_E2E_ANALYZER_WAIT", "240"))
POST_SETTLE_SEC = int(os.environ.get("TS_ADV_E2E_ANALYZER_SETTLE", "25"))
ANALYZERS = ["sigma", "domain", "feature_extraction", "misp_analyzer"]


def flatten_analyses(objects: list) -> list[dict]:
    """L'API renvoie parfois objects=[[{analysis}, ...]]."""
    out: list[dict] = []
    for item in objects:
        if isinstance(item, list):
            out.extend(x for x in item if isinstance(x, dict))
        elif isinstance(item, dict):
            out.append(item)
    return out


def login() -> tuple[requests.Session, dict[str, str]]:
    s = requests.Session()
    r = s.get(f"{TS}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        print("[run-analyzers] ERREUR: CSRF login", file=sys.stderr)
        sys.exit(1)
    s.post(
        f"{TS}/login/",
        data={"username": USER, "password": PASS},
        headers={"Referer": f"{TS}/login/"},
        timeout=25,
    )
    return s, {"X-CSRFToken": m.group(1), "Content-Type": "application/json", "Referer": TS}


def resolve_sketch(s: requests.Session, h: dict[str, str]) -> tuple[int, int, str]:
    if SKETCH_ID.isdigit():
        sid = int(SKETCH_ID)
        det = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()
        obj = det.get("objects", [{}])[0]
        tls = obj.get("timelines", [])
        if not tls:
            print(f"[run-analyzers] ERREUR: sketch {sid} sans timeline", file=sys.stderr)
            sys.exit(1)
        tid = tls[0]["id"]
        idx = (tls[0].get("searchindex") or {}).get("index_name", "")
        return sid, tid, idx

    name = f"[FP] {CASE}"
    for sk in s.get(f"{TS}/api/v1/sketches/", headers=h, timeout=20).json().get("objects", []):
        if sk.get("name") == name:
            sid = sk["id"]
            det = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()
            obj = det.get("objects", [{}])[0]
            tls = obj.get("timelines", [])
            if not tls:
                continue
            tid = tls[0]["id"]
            idx = (tls[0].get("searchindex") or {}).get("index_name", "")
            return sid, tid, idx
    print(f"[run-analyzers] ERREUR: sketch {name} introuvable", file=sys.stderr)
    sys.exit(1)


def wait_analyses(s: requests.Session, h: dict[str, str], sid: int, tid: int) -> bool:
    deadline = time.time() + WAIT_SEC
    while time.time() < deadline:
        ta = s.get(
            f"{TS}/api/v1/sketches/{sid}/timelines/{tid}/analysis/",
            headers=h,
            timeout=30,
        )
        if ta.status_code != 200:
            time.sleep(5)
            continue
        objects = flatten_analyses(ta.json().get("objects", []))
        if not objects:
            time.sleep(5)
            continue
        statuses: list[tuple[str, str]] = []
        for item in objects:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("analyzer_name", "?")
            st_list = item.get("status") or []
            st = st_list[-1].get("status", "?") if st_list else "?"
            statuses.append((name, st))
        print(f"[run-analyzers] analyses: {statuses}")
        terminal = {"DONE", "ERROR", "WARNING"}
        if statuses and all(st in terminal for _, st in statuses):
            failed = [n for n, st in statuses if st not in ("DONE", "WARNING")]
            if failed:
                print(f"[run-analyzers] WARN analyzers en erreur: {failed}", file=sys.stderr)
            return True
        time.sleep(5)
    print("[run-analyzers] WARN timeout attente analyses", file=sys.stderr)
    return False


def main() -> int:
    s, h = login()
    sid, tid, idx = resolve_sketch(s, h)
    os.environ["TS_VERIFY_SKETCH_ID"] = str(sid)
    print(f"[run-analyzers] sketch={sid} timeline={tid} index={idx}")

    h_sk = {**h, "Referer": f"{TS}/sketch/{sid}/explore/"}
    for name in ANALYZERS:
        pr = s.post(
            f"{TS}/api/v1/sketches/{sid}/analyzer/",
            json={
                "timeline_ids": [tid],
                "analyzer_names": [name],
                "analyzer_force_run": True,
            },
            headers=h_sk,
            timeout=90,
        )
        if pr.status_code != 200:
            print(
                f"[run-analyzers] ERREUR POST {name}: HTTP {pr.status_code} {pr.text[:200]}",
                file=sys.stderr,
            )
            return 1
        print(f"[run-analyzers] lancé: {name}")

    if POST_SETTLE_SEC > 0:
        print(f"[run-analyzers] attente {POST_SETTLE_SEC}s (pipeline Celery)...")
        time.sleep(POST_SETTLE_SEC)
    wait_analyses(s, h, sid, tid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
