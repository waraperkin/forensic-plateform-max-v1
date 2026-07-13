#!/usr/bin/env python3
"""Bibliothèque partagée Timesketch Master (session, sketch, CSV, attente timelines)."""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
INGEST = ROOT / "ingest-worker"
if str(INGEST) not in sys.path:
    sys.path.insert(0, str(INGEST))

from timesketch_io import (  # noqa: E402
    api_headers,
    get_or_create_sketch,
    login_session,
    upload_csv_timeline,
)
from csv_validator import events_to_csv_bytes  # noqa: E402
from timesketch_normalizer import normalize_event_to_ts_row  # noqa: E402

TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
TS_USER = os.environ.get("TIMESKETCH_USER", "admin")
TS_PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
MASTER_SKETCH_DISPLAY = os.environ.get("TS_MASTER_SKETCH_DISPLAY", "Forensics — Master Investigation")
# Nom stocké en base — ne pas changer sans migration API (anti-régression)
MASTER_SKETCH = os.environ.get("TS_MASTER_SKETCH_NAME", "[FP] Timesketch Master")
MASTER_SKETCH_ALIASES = [
    "[FP] Timesketch Master",
    MASTER_SKETCH,
    MASTER_SKETCH_DISPLAY,
    "Forensics — Master Investigation",
]
MASTER_CASE = os.environ.get("TS_MASTER_CASE_ID", "FP-TS-MASTER")
LOG_DIR = ROOT / "logs"
CONFIG_DIR = ROOT / "config" / "timesketch"
PLAYBOOKS_JSON = CONFIG_DIR / "playbooks.json"
DASHBOARD_PACK_JSON = CONFIG_DIR / "dashboard_pack.json"
STATE_JSON = LOG_DIR / "timesketch_master_state.json"


def login() -> tuple[requests.Session, dict[str, str]]:
    """Session web + en-têtes CSRF (compatible scripts verify existants)."""
    s = requests.Session()
    s.verify = False
    r = s.get(f"{TS_URL}/login/", timeout=25)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        raise RuntimeError("CSRF login Timesketch introuvable")
    s.post(
        f"{TS_URL}/login/",
        data={"username": TS_USER, "password": TS_PASS},
        headers={"Referer": f"{TS_URL}/login/"},
        timeout=30,
    )
    return s, {
        "X-CSRFToken": m.group(1),
        "Content-Type": "application/json",
        "Referer": TS_URL,
    }


def ts_client() -> dict[str, Any]:
    return login_session(TS_URL, TS_USER, TS_PASS)


def sketch_headers(client: dict[str, Any], sketch_id: int) -> dict[str, str]:
    return api_headers(client, TS_URL, sketch_id)


def get_master_sketch_id(client: dict[str, Any] | None = None) -> int:
    c = client or ts_client()
    from timesketch_io import _fetch_all_sketch_objects  # noqa: E402

    session = c["session"]
    h = api_headers(c, TS_URL)
    all_sketches = _fetch_all_sketch_objects(session, TS_URL, h)
    seen: set[str] = set()
    for name in MASTER_SKETCH_ALIASES:
        if not name or name in seen:
            continue
        seen.add(name)
        sid = next((s["id"] for s in all_sketches if s.get("name") == name), None)
        if sid:
            return int(sid)
    sid = get_or_create_sketch(
        c,
        TS_URL,
        MASTER_SKETCH,
        f"{MASTER_SKETCH_DISPLAY} — fusion DFIR/CTI/SOC ({MASTER_CASE})",
    )
    if not sid:
        raise RuntimeError("création sketch Master impossible")
    return int(sid)


def wait_timeline_ready(
    session: requests.Session,
    headers: dict[str, str],
    sketch_id: int,
    timeout: int = 300,
    interval: int = 5,
) -> list[dict]:
    """Attend que toutes les timelines du sketch soient ready (pas fail)."""
    deadline = time.time() + timeout
    last: list[dict] = []
    while time.time() < deadline:
        det = session.get(
            f"{TS_URL}/api/v1/sketches/{sketch_id}/",
            headers=headers,
            timeout=25,
        ).json()
        last = det.get("objects", [{}])[0].get("timelines", [])
        if not last:
            time.sleep(interval)
            continue
        ok = True
        for tl in last:
            st = (tl.get("status") or [{}])[-1].get("status", "")
            if st == "fail":
                raise RuntimeError(f"timeline fail: {tl.get('name')}")
            if st not in ("ready", "archived"):
                ok = False
        if ok:
            return last
        time.sleep(interval)
    return last


def upload_events_timeline(
    client: dict[str, Any],
    sketch_id: int,
    timeline_name: str,
    events: list[dict[str, Any]],
    job: dict[str, Any] | None = None,
) -> tuple[bool, int | None]:
    job = job or {"portal": "timesketch-master", "case_id": MASTER_CASE, "filename": timeline_name}
    if not events:
        return False, None
    csv_bytes = events_to_csv_bytes(events, timeline_name)
    safe = timeline_name.replace(" ", "-").lower()[:64]
    ok, meta = upload_csv_timeline(client, TS_URL, sketch_id, f"{safe}.csv", csv_bytes)
    return ok, meta.get("timeline_id")


def explore(
    session: requests.Session,
    headers: dict[str, str],
    sketch_id: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    h = {**headers, "Referer": f"{TS_URL}/sketch/{sketch_id}/explore/"}
    r = session.post(
        f"{TS_URL}/api/v1/sketches/{sketch_id}/explore/",
        json=body,
        headers=h,
        timeout=90,
    )
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "text": r.text[:300]}
    data = r.json()
    return {"ok": True, "events": data.get("objects", []), "meta": data.get("meta", {})}


def os_search(index: str, query: dict, size: int = 400) -> list[dict[str, Any]]:
    s = requests.Session()
    s.verify = False
    r = s.post(
        f"{OS_URL}/{index}/_search",
        json={"size": size, "query": query, "sort": [{"@timestamp": "desc"}]},
        timeout=60,
    )
    if r.status_code != 200:
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def write_sketch_url(sketch_id: int) -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    url = f"{TS_URL}/sketch/{sketch_id}/explore/"
    p = LOG_DIR / "timesketch_master_sketch.url"
    p.write_text(url + "\n", encoding="utf-8")
    return p


def check(label: str, ok: bool, detail: str = "") -> tuple[int, int]:
    if ok:
        print(f"[ts-master] OK  {label}" + (f" — {detail}" if detail else ""))
        return 1, 0
    print(f"[ts-master] KO  {label}" + (f" — {detail}" if detail else ""), file=sys.stderr)
    return 0, 1
