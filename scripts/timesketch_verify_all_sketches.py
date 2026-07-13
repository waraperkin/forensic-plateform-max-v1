#!/usr/bin/env python3
"""Vérifie TOUS les sketches Timesketch (explore + chronology + UI sans Server side error)."""
from __future__ import annotations

import os
import re
import sys

import requests

TS = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
USER = os.environ.get("TIMESKETCH_USER", "admin")
PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
OS = os.environ.get("OPENSEARCH_URL", "http://localhost:9200").rstrip("/")
PATTERN = os.environ.get("TS_VERIFY_PATTERN", "")


def login() -> tuple[requests.Session, dict[str, str]]:
    s = requests.Session()
    r = s.get(f"{TS}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        raise RuntimeError("CSRF login introuvable")
    s.post(
        f"{TS}/login/",
        data={"username": USER, "password": PASS},
        headers={"Referer": f"{TS}/login/"},
        timeout=25,
    )
    return s, {
        "X-CSRFToken": m.group(1),
        "Content-Type": "application/json",
        "Referer": TS,
    }


def verify_sketch(s: requests.Session, h: dict, sid: int, name: str) -> tuple[bool, str]:
    h = {**h, "Referer": f"{TS}/sketch/{sid}/explore/"}
    ar = s.get(f"{TS}/api/v1/sketches/{sid}/analyzer/", headers=h, timeout=30)
    if ar.status_code != 200:
        return False, f"analyzer_http_{ar.status_code}:{ar.text[:80]}"
    detail = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()["objects"][0]
    tls = detail.get("timelines", [])
    if not tls:
        # Sketch sans timeline : l'API explore doit répondre 200 (patch FP_PATCH_EMPTY_INDICES),
        # sinon l'UI affiche un toast « Server side error » (HTTP 400 upstream).
        er = s.post(
            f"{TS}/api/v1/sketches/{sid}/explore/",
            json={"query_string": "*", "filter": {}},
            headers=h,
            timeout=60,
        )
        if er.status_code != 200:
            return False, f"empty_sketch_explore_http_{er.status_code}:{er.text[:120]}"
        ui = s.get(f"{TS}/sketch/{sid}/explore/", timeout=30)
        if "Server side error" in ui.text:
            return False, "no_timelines_ui_server_side_error"
        if ui.status_code != 200:
            return False, f"no_timelines_ui_http_{ui.status_code}"
        return True, "empty_sketch_explore_ok"
    for tl in tls:
        st = (tl.get("status") or [{}])[-1].get("status", "")
        idx = (tl.get("searchindex") or {}).get("index_name", "")
        if st == "fail":
            return False, f"fail:{tl.get('name')}"
        if idx:
            cnt = requests.get(f"{OS}/{idx}/_count", timeout=15).json().get("count", 0)
            if cnt == 0:
                return False, f"empty_index:{idx}"
    payloads = [
        {"query_string": "*", "filter": {}},
        {
            "query_string": "*",
            "filter": {},
            "fields": [{"field": "datetime", "type": "datetime"}],
            "chronology": True,
            "order": "asc",
        },
        {
            "query_string": "*",
            "filter": {
                "indices": ["_all"],
                "fields": [
                    {"field": "datetime", "type": "datetime"},
                    {"field": "message", "type": "text"},
                ],
            },
            "chronology": True,
        },
    ]
    total = 0
    for i, p in enumerate(payloads):
        er = s.post(f"{TS}/api/v1/sketches/{sid}/explore/", json=p, headers=h, timeout=90)
        if er.status_code != 200:
            return False, f"explore_{i}_http_{er.status_code}"
        total = er.json().get("meta", {}).get("es_total_count", 0)
        if total < 1:
            return False, f"explore_{i}_zero"
    ui = s.get(f"{TS}/sketch/{sid}/explore/", timeout=30)
    if "Server side error" in ui.text:
        return False, "ui_server_side_error"
    return True, f"ok events={total}"


def fetch_all_sketches(s: requests.Session, h: dict) -> list[dict]:
    """Parcourt toutes les pages `/api/v1/sketches/` (défaut ~10 sketchs par page)."""
    sketches: list[dict] = []
    page = 1
    while True:
        r = s.get(f"{TS}/api/v1/sketches/", params={"page": page}, headers=h, timeout=20)
        r.raise_for_status()
        data = r.json()
        sketches.extend(data.get("objects", []))
        meta = data.get("meta") or {}
        if not meta.get("has_next"):
            break
        page = int(meta.get("next_page") or page + 1)
    return sketches


def main() -> int:
    s, h = login()
    sketches = fetch_all_sketches(s, h)
    if PATTERN:
        sketches = [x for x in sketches if PATTERN in (x.get("name") or "")]
    failed = []
    for sk in sketches:
        sid, name = sk["id"], sk.get("name", "")
        ok, msg = verify_sketch(s, h, sid, name)
        status = "OK" if ok else "FAIL"
        print(f"[{status}] id={sid} {name[:60]} — {msg}")
        if not ok:
            failed.append((sid, name, msg))
    if failed:
        print(f"\n{len(failed)} sketch(s) en échec sur {len(sketches)}", file=sys.stderr)
        return 1
    print(f"\nTous les {len(sketches)} sketch(s) OK (pagination API prise en compte)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
