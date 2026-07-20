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
    # Champs SaveViewForm : name / query / filter / dsl — `filter` obligatoire,
    # l'API view.py fait `"from" in form.filter.data` et lève TypeError
    # (HTTP 500) si le filtre est absent (None).
    body = {
        "name": name[:255],
        "query": ecs_query_to_ts(query),
        "filter": {
            "size": 40,
            "terminate_after": 40,
            "indices": indices or "_all",
            "order": "asc",
            "chips": [],
        },
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
    objs = r.json().get("objects", [])
    # L'API renvoie parfois objects=[[{...}, …]] (liste imbriquée)
    if objs and isinstance(objs[0], list):
        objs = objs[0]
    return [str(v.get("name") or "") for v in objs if isinstance(v, dict)]


def run_analyzers_on_sketch(sketch_id: int, timeline_id: int, analyzers: list[str]) -> bool:
    session, headers = login()
    headers = {**headers, "Referer": f"{TS_URL}/sketch/{sketch_id}/"}
    # Endpoint niveau sketch : le endpoint timeline (/timelines/{id}/analyzer/)
    # répond 405 sur cette version de Timesketch. Le POST peut être lent
    # (gunicorn sync + dispatch celery) → timeout large.
    r = session.post(
        f"{TS_URL}/api/v1/sketches/{sketch_id}/analyzer/",
        json={"analyzer_names": analyzers, "timeline_ids": [timeline_id]},
        headers=headers,
        timeout=280,
    )
    if r.status_code in (200, 201):
        return True
    if r.status_code == 403 and "already" in (r.text or "").lower():
        return True
    return False


def wait_analyzer_done(sketch_id: int, timeline_id: int, timeout: int = 90) -> list[str]:
    import requests as _rq

    session, headers = login()
    deadline = time.time() + timeout
    done: list[str] = []
    while time.time() < deadline:
        try:
            # Le détail timeline renvoie analysis=[] sur cette version de
            # Timesketch — la vraie liste vit sur /timelines/{id}/analysis/
            r = session.get(
                f"{TS_URL}/api/v1/sketches/{sketch_id}/timelines/{timeline_id}/analysis/",
                headers=headers,
                timeout=25,
            )
        except _rq.RequestException:
            # Worker gunicorn recyclé pendant le polling — retenter
            time.sleep(2)
            continue
        pending = False
        if r.status_code == 200:
            items = r.json().get("objects", []) or []
            if items and isinstance(items[0], list):
                items = items[0]
            for item in items:
                if not isinstance(item, dict):
                    continue
                # status est une liste d'objets [{"status": "DONE", ...}] — on
                # prend le plus récent (dernier élément)
                st = item.get("status")
                if isinstance(st, list):
                    st = (st[-1] or {}).get("status") if st else None
                if st in ("PENDING", "STARTED"):
                    pending = True
                if st == "DONE":
                    name = item.get("analyzer_name") or item.get("name")
                    if name and name not in done:
                        done.append(str(name))
        # Ne sortir que quand plus rien n'est en cours (sinon on raterait les
        # analyzers encore PENDING alors qu'un premier vient de finir)
        if done and not pending:
            break
        time.sleep(2)
    return done


def run_zone_verify(zone: str) -> int:
    st = load_state().get("zones", {}).get(zone, {})
    return 0 if st.get("ok", True) else 1


# ── Implémentation des 11 zones ──────────────────────────────────────────────

def _save_zone_state(zone: str, ok: bool, **details: Any) -> int:
    st = load_state()
    st.setdefault("zones", {})[zone] = {"ok": ok, **details}
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(st, indent=2, default=str), encoding="utf-8")
    return 0 if ok else 1


def _zone_get(path: str) -> tuple[int, Any]:
    session, headers = login()
    r = session.get(f"{TS_URL}{path}", headers=headers, timeout=30)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, None


def zone_timelines() -> int:
    _s, _h, sid, indices = sketch_context()
    ok = len(indices) > 0 and indices != ["timesketch"]
    if not ok:
        ok = len(indices) > 0
    return _save_zone_state("timelines", ok, sketch=sid, indices=len(indices))


def zone_savedsearches() -> int:
    s, h, sid, indices = sketch_context()
    core = [
        ("[FP Zone] Événements Windows", 'data_type:"windows:evtx:record" OR source_short:WIN'),
        ("[FP Zone] Authentifications", "tag:logon OR event_type:4624 OR event_type:4625"),
        ("[FP Zone] Exécutions process", 'data_type:"windows:evtx:record" AND event_type:1'),
        ("[FP Zone] Matches TI", "tag:ti_match OR ti_match:true"),
    ]
    fails = 0
    for name, q in core:
        if not create_saved_view(s, h, sid, name, q, indices, name):
            fails += 1
    total = len(list_view_names(s, h, sid))
    return _save_zone_state("savedsearches", fails == 0, created=len(core) - fails, total_views=total)


def zone_datatypes() -> int:
    s, h, sid, indices = sketch_context()
    r = s.post(
        f"{TS_URL}/api/v1/sketches/{sid}/aggregation/explore/",
        json={"aggregator_name": "field_bucket", "aggregator_parameters": {"field": "data_type", "limit": 25}},
        headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/"},
        timeout=45,
    )
    buckets = 0
    if r.status_code == 200:
        try:
            objs = r.json().get("objects") or []
            values = (objs[0] or [{}])[0].get("field_bucket", {}).get("buckets", []) if objs else []
            buckets = len(values)
        except Exception:
            buckets = 0
    return _save_zone_state("datatypes", r.status_code == 200, buckets=buckets)


def zone_tags() -> int:
    s, h, sid, indices = sketch_context()
    ex = explore(s, h, sid, {"query_string": "*", "size": 4, "indices": indices[:10]})
    events = [
        {"_id": e.get("_id"), "_index": e.get("_index")}
        for e in (ex.get("events") or [])
        if e.get("_id") and e.get("_index")
    ]
    if not events:
        return _save_zone_state("tags", False, error="aucun événement")
    r = s.post(
        f"{TS_URL}/api/v1/sketches/{sid}/event/tagging/",
        json={"tag_string": '["fp-zone-check"]', "events": events},
        headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/"},
        timeout=45,
    )
    ok = r.status_code in (200, 201)
    if not ok:
        # Repli : des tags existent déjà (analyzers sigma/TI)
        ex2 = explore(s, h, sid, {"query_string": "_exists_:tag", "size": 1, "indices": indices[:10]})
        ok = bool(ex2.get("ok") and ex2.get("events"))
    return _save_zone_state("tags", ok, tagged=len(events) if ok else 0)


def zone_graphs() -> int:
    code, data = _zone_get(f"/api/v1/sketches/{int(resolve_sketch_id())}/graphs/")
    return _save_zone_state("graphs", code == 200, saved_graphs=len((data or {}).get("objects") or []))


def zone_stories() -> int:
    s, h, sid, _ = sketch_context()
    r = s.get(f"{TS_URL}/api/v1/sketches/{sid}/stories/", headers=h, timeout=30)
    stories = []
    if r.status_code == 200:
        objs = r.json().get("objects") or []
        stories = objs[0] if objs and isinstance(objs[0], list) else objs
    if not stories:
        cr = s.post(
            f"{TS_URL}/api/v1/sketches/{sid}/stories/",
            json={"title": "FP Zones — Résumé investigation", "content": "[]"},
            headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/"},
            timeout=30,
        )
        ok = cr.status_code in (200, 201)
        return _save_zone_state("stories", ok, stories=1 if ok else 0)
    return _save_zone_state("stories", True, stories=len(stories))


def zone_templates() -> int:
    code, data = _zone_get("/api/v1/searchtemplates/")
    n = len((data or {}).get("objects") or [])
    return _save_zone_state("templates", code == 200, templates=n)


def zone_sigma() -> int:
    code, data = _zone_get("/api/v1/sigmarules/")
    n = int(((data or {}).get("meta") or {}).get("rules_count") or 0)
    return _save_zone_state("sigma", code == 200 and n > 0, rules=n)


def zone_ti() -> int:
    code, data = _zone_get(f"/api/v1/sketches/{int(resolve_sketch_id())}/attribute/")
    has_intel = bool((data or {}).get("intelligence"))
    return _save_zone_state("ti", code == 200 and has_intel, intelligence=has_intel)


def zone_analyzers() -> int:
    code, data = _zone_get(f"/api/v1/sketches/{int(resolve_sketch_id())}/analyzer/")
    names = [a.get("name") for a in (data or []) if isinstance(a, dict)] if isinstance(data, list) else []
    return _save_zone_state("analyzers", code == 200 and len(names) > 0, analyzers=names[:20])


def zone_visualizations() -> int:
    s, h, sid, _ = sketch_context()
    r = s.post(
        f"{TS_URL}/api/v1/sketches/{sid}/aggregation/explore/",
        json={"aggregator_name": "field_bucket", "aggregator_parameters": {"field": "timestamp_desc", "limit": 10}},
        headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/"},
        timeout=45,
    )
    return _save_zone_state("visualizations", r.status_code == 200)


ZONE_SETUP.update({
    "timelines": zone_timelines,
    "savedsearches": zone_savedsearches,
    "datatypes": zone_datatypes,
    "tags": zone_tags,
    "graphs": zone_graphs,
    "stories": zone_stories,
    "templates": zone_templates,
    "sigma": zone_sigma,
    "ti": zone_ti,
    "analyzers": zone_analyzers,
    "visualizations": zone_visualizations,
})
