#!/usr/bin/env python3
"""Bibliothèque zones Timesketch — contexte sketch, vues, explore, analyzers."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from crosspivot_engine import resolve_sketch_id
from timesketch_master_lib import TS_URL, explore, login

ROOT = Path(__file__).resolve().parents[1]
ZONES_DIR = ROOT / "config" / "timesketch" / "zones"
STATE_PATH = ROOT / "logs" / "timesketch_zones_state.json"

ZONE_SETUP: dict[str, Callable[[], int]] = {}


def load_state() -> dict[str, Any]:
    if STATE_PATH.is_file():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {}


def sketch_context() -> tuple[Any, dict[str, str], int, list[str]]:
    session, headers = login()
    sketch_id = int(resolve_sketch_id())
    det = session.get(f"{TS_URL}/api/v1/sketches/{sketch_id}/", headers=headers, timeout=25).json()
    timelines = det.get("objects", [{}])[0].get("timelines", [])
    indices: list[str] = []
    for tl in timelines:
        idx = (tl.get("searchindex") or {}).get("index_name")
        if idx:
            indices.append(idx)
    if not indices:
        indices = ["timesketch"]
    return session, headers, sketch_id, indices


def ecs_query_to_ts(query: str) -> str:
    return (
        query.replace("event.code", "event_type")
        .replace("@timestamp", "datetime")
        .replace("case_id.keyword", "case_id")
    )


def create_saved_view(
    session: Any,
    headers: dict[str, str],
    sketch_id: int,
    name: str,
    query: str,
    indices: list[str],
    description: str = "",
) -> bool:
    body = {
        "name": name[:255],
        "query_string": ecs_query_to_ts(query),
        "description": (description or name)[:500],
    }
    r = session.post(
        f"{TS_URL}/api/v1/sketches/{sketch_id}/views/",
        json=body,
        headers={**headers, "Referer": f"{TS_URL}/sketch/{sketch_id}/"},
        timeout=30,
    )
    return r.status_code in (200, 201, 409)


def list_view_names(session: Any, headers: dict[str, str], sketch_id: int) -> list[str]:
    r = session.get(f"{TS_URL}/api/v1/sketches/{sketch_id}/views/", headers=headers, timeout=30)
    if r.status_code != 200:
        return []
    return [str(v.get("name") or "") for v in r.json().get("objects", [])]


def run_analyzers_on_sketch(sketch_id: int, timeline_id: int, analyzers: list[str]) -> bool:
    session, headers = login()
    headers = {**headers, "Referer": f"{TS_URL}/sketch/{sketch_id}/"}
    r = session.post(
        f"{TS_URL}/api/v1/sketches/{sketch_id}/timelines/{timeline_id}/analyzer/",
        json={"analyzer_names": analyzers},
        headers=headers,
        timeout=90,
    )
    if r.status_code in (200, 201):
        return True
    if r.status_code == 403 and "already" in (r.text or "").lower():
        return True
    return False


def wait_analyzer_done(sketch_id: int, timeline_id: int, timeout: int = 90) -> list[str]:
    session, headers = login()
    deadline = time.time() + timeout
    done: list[str] = []
    while time.time() < deadline:
        r = session.get(
            f"{TS_URL}/api/v1/sketches/{sketch_id}/timelines/{timeline_id}/",
            headers=headers,
            timeout=25,
        )
        if r.status_code == 200:
            obj = r.json().get("objects", [{}])[0]
            for item in obj.get("analysis", []) or []:
                if item.get("status") == "DONE":
                    name = item.get("analyzer_name") or item.get("name")
                    if name and name not in done:
                        done.append(str(name))
        if done:
            break
        time.sleep(2)
    return done


def run_zone_verify(zone: str) -> int:
    st = load_state().get("zones", {}).get(zone, {})
    return 0 if st.get("ok", True) else 1
