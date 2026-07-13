#!/usr/bin/env python3
"""Helpers verify parsing ↔ domaines (hunting, playbooks, dashboards)."""
from __future__ import annotations

import json
import os
from typing import Any

import requests

OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")


def session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "securitytenant": "global"}


def verify_dashboard_loads(s: requests.Session, dash_id: str) -> str | None:
    r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=25)
    if r.status_code != 200:
        return f"dashboard {dash_id} HTTP {r.status_code}"
    try:
        panels = json.loads(r.json()["attributes"]["panelsJSON"])
        if not panels:
            return f"dashboard {dash_id} sans panels"
    except (KeyError, json.JSONDecodeError):
        return f"dashboard {dash_id} panelsJSON invalide"
    return None


def verify_saved_search_ecs(
    s: requests.Session,
    sid: str,
    *,
    min_hits: int = 0,
    check_os: bool = True,
) -> list[str]:
    from parsing_ecs_adapters import _index_to_os, os_count, query_uses_ecs_fields  # noqa: E402

    problems: list[str] = []
    r = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=15)
    if r.status_code != 200:
        return [f"search {sid} absent"]
    attrs = r.json()["attributes"]
    ss = json.loads(attrs.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", "{}"))
    raw_q = ss.get("query", "")
    q = raw_q if isinstance(raw_q, str) else (raw_q.get("query", "") if isinstance(raw_q, dict) else str(raw_q))
    idx = ss.get("index", "fp-events")
    if not query_uses_ecs_fields(q):
        problems.append(f"{sid}: requête non ECS ({q[:70]})")
    if check_os and min_hits >= 0:
        cnt = os_count(s, _index_to_os(idx), q)
        if cnt < 0:
            problems.append(f"{sid}: OS erreur")
        elif min_hits > 0 and cnt < min_hits:
            problems.append(f"{sid}: {cnt} hits (min {min_hits})")
        elif cnt >= min_hits:
            print(f"[domain-verify] OK {sid} hits={cnt}")
    return problems


def verify_specs_list(
    s: requests.Session,
    specs: list[tuple[str, str, str, str, list[str]]],
    *,
    min_hits: int = 1,
    sample_max: int = 30,
) -> list[str]:
    problems: list[str] = []
    for i, (sid, *_rest) in enumerate(specs):
        if i >= sample_max:
            break
        problems.extend(verify_saved_search_ecs(s, sid, min_hits=min_hits))
    return problems
