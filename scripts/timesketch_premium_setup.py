#!/usr/bin/env python3
"""Timesketch Premium Setup — saved searches multi-tag + aggregations premium.

Ce script enrichit le sketch master Timesketch sans toucher aux timelines,
playbooks existants ni aux analyzers :

- saved searches "multi-tag" qui démontrent que l'API filtre déjà sur plusieurs
  tags (la sélection multiple côté frontend reste un patch SPA hors périmètre) ;
- aggregations persistantes via /api/v1/sketches/{sid}/aggregation/ :
    * Top hosts (field_bucket sur host.name / hostname)
    * Top users (field_bucket sur user.name / username)
    * Top IPs sources (field_bucket sur source.ip)
    * Histogramme d'événements (date_histogram quotidien)
    * Top event types / tags (query_bucket multi-tag)

Idempotent : un saved search ou une aggregation existante (même nom) est mise
à jour, pas dupliquée.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import (  # noqa: E402
    LOG_DIR,
    TS_URL,
    explore,
    get_master_sketch_id,
    login,
    write_sketch_url,
)


def get_sketch_indices(session, headers: dict[str, str], sid: int) -> list[str]:
    h = {**headers, "Referer": f"{TS_URL}/sketch/{sid}/"}
    r = session.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=30)
    if r.status_code != 200:
        return []
    obj = (r.json().get("objects") or [{}])[0]
    indices: list[str] = []
    for tl in obj.get("timelines", []) or []:
        idx = (tl.get("searchindex") or {}).get("index_name", "")
        if idx and idx not in indices:
            indices.append(idx)
    return indices


def get_timeline_ids(session, headers: dict[str, str], sid: int) -> list[int]:
    h = {**headers, "Referer": f"{TS_URL}/sketch/{sid}/"}
    r = session.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=30)
    if r.status_code != 200:
        return []
    obj = (r.json().get("objects") or [{}])[0]
    ids: list[int] = []
    for tl in obj.get("timelines", []) or []:
        tid = tl.get("id")
        if tid:
            ids.append(int(tid))
    return ids


def find_existing(items: list[dict], name: str) -> dict | None:
    for it in items or []:
        if isinstance(it, dict) and it.get("name") == name:
            return it
    return None


def upsert_saved_search(
    session,
    headers: dict[str, str],
    sid: int,
    name: str,
    query: str,
    description: str,
) -> dict:
    h = {**headers, "Referer": f"{TS_URL}/sketch/{sid}/views/"}
    r = session.get(f"{TS_URL}/api/v1/sketches/{sid}/views/", headers=h, timeout=30)
    existing = None
    if r.status_code == 200:
        existing = find_existing(r.json().get("objects") or [], name)

    # Timesketch v2024+ : POST /views/ accepte name/description/query/filter/dsl
    # (schéma identique à timesketch_zones_lib.create_saved_view).
    qf: dict[str, Any] = {
        "fields": [
            {"field": "datetime"},
            {"field": "timestamp_desc"},
            {"field": "message"},
            {"field": "tag"},
            {"field": "hostname"},
            {"field": "user"},
            {"field": "data_type"},
        ],
        "chips": [],
        "indices": "_all",
    }
    body = {
        "name": name[:255],
        "description": description[:500],
        "query": query,
        "filter": qf,
        "dsl": {},
    }

    if existing:
        vid = existing.get("id")
        upd = session.post(
            f"{TS_URL}/api/v1/sketches/{sid}/views/{vid}/",
            headers={**h, "Content-Type": "application/json"},
            json=body,
            timeout=30,
        )
        ok = upd.status_code in (200, 201)
        return {
            "name": name,
            "id": vid,
            "ok": ok,
            "updated": True,
            "status": upd.status_code,
            "error": upd.text[:200] if not ok else None,
        }

    cr = session.post(
        f"{TS_URL}/api/v1/sketches/{sid}/views/",
        headers={**h, "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    if cr.status_code not in (200, 201):
        return {"name": name, "ok": False, "status": cr.status_code, "error": cr.text[:200]}
    new_id = None
    try:
        objs = cr.json().get("objects") or []
        if objs:
            new_id = objs[0].get("id") if isinstance(objs[0], dict) else None
    except Exception:
        pass
    return {"name": name, "id": new_id, "ok": True, "created": True}


def run_aggregation(
    session,
    headers: dict[str, str],
    sid: int,
    name: str,
    description: str,
    aggregator_name: str,
    parameters: dict[str, Any],
    chart_type: str = "table",
) -> dict:
    """Exécute (et persiste si supporté) une aggregation premium."""
    h = {**headers, "Referer": f"{TS_URL}/sketch/{sid}/aggregation/"}
    body = {
        "aggregator_name": aggregator_name,
        "aggregator_parameters": parameters,
        "chart_type": chart_type,
        "name": name,
        "description": description,
    }
    r = session.post(
        f"{TS_URL}/api/v1/sketches/{sid}/aggregation/explore/",
        headers={**h, "Content-Type": "application/json"},
        json=body,
        timeout=60,
    )
    ok = r.status_code == 200
    rows = 0
    if ok:
        try:
            data = r.json()
            objs = data.get("objects") or []
            if objs and isinstance(objs[0], dict):
                wrap = objs[0]
                # field_bucket: { field_bucket: { buckets: [...] } }
                # date_histogram: { date_histogram: { buckets: [...] } }
                # Wrappers possibles
                for v in wrap.values():
                    if isinstance(v, dict) and isinstance(v.get("buckets"), list):
                        rows = max(rows, len(v["buckets"]))
                if not rows:
                    direct = wrap.get("buckets")
                    if isinstance(direct, list):
                        rows = len(direct)
        except Exception:
            pass
    return {
        "name": name,
        "aggregator": aggregator_name,
        "ok": ok,
        "rows": rows,
        "status": r.status_code,
    }


def save_aggregation(
    session,
    headers: dict[str, str],
    sid: int,
    name: str,
    description: str,
    aggregator_name: str,
    parameters: dict[str, Any],
    chart_type: str = "table",
) -> dict:
    """Persiste une aggregation via /aggregation/ (saved aggregation)."""
    h = {**headers, "Referer": f"{TS_URL}/sketch/{sid}/aggregation/"}
    r0 = session.get(f"{TS_URL}/api/v1/sketches/{sid}/aggregation/", headers=h, timeout=30)
    existing = None
    if r0.status_code == 200:
        try:
            existing = find_existing(r0.json().get("objects") or [], name)
        except Exception:
            existing = None
    body = {
        "name": name,
        "description": description,
        "agg_type": aggregator_name,
        "parameters": json.dumps(parameters),
        "chart_type": chart_type,
        "view_id": None,
    }
    if existing and existing.get("id"):
        aid = existing["id"]
        upd = session.post(
            f"{TS_URL}/api/v1/sketches/{sid}/aggregation/{aid}/",
            headers={**h, "Content-Type": "application/json"},
            json=body,
            timeout=30,
        )
        return {"name": name, "id": aid, "ok": upd.status_code in (200, 201), "status": upd.status_code}
    cr = session.post(
        f"{TS_URL}/api/v1/sketches/{sid}/aggregation/",
        headers={**h, "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    return {"name": name, "ok": cr.status_code in (200, 201), "status": cr.status_code}


def main() -> int:
    s, h = login()
    sid = get_master_sketch_id()
    if not sid:
        print("[ts-premium] KO sketch master introuvable", file=sys.stderr)
        return 1

    indices = get_sketch_indices(s, h, sid)
    timeline_ids = get_timeline_ids(s, h, sid)
    if not indices and not timeline_ids:
        print(f"[ts-premium] WARN aucune timeline ready sur sketch {sid} — création differée")

    print(f"[ts-premium] sketch={sid} indices={len(indices)} timelines={len(timeline_ids)}")

    applied: dict[str, list] = {"saved_searches": [], "aggregations_run": [], "aggregations_saved": []}

    # ── Saved searches multi-tag ────────────────────────────────────────────
    multi_tag_searches = [
        {
            "name": "[FP][Premium] Multi-tag — SOC critique (tag:soc AND tag:critical)",
            "query": "tag:soc AND tag:critical",
            "description": "Multi-sélection AND : événements taggés SOC + critical (démo combinaison ET).",
        },
        {
            "name": "[FP][Premium] Multi-tag — DFIR ou IR (tag:dfir OR tag:ir)",
            "query": "tag:dfir OR tag:ir",
            "description": "Multi-sélection OR : événements taggés DFIR ou Incident Response.",
        },
        {
            "name": "[FP][Premium] Multi-tag — Phishing + suspicious",
            "query": "(tag:phishing OR tag:phish) AND tag:suspicious",
            "description": "Combine phishing/suspect : démontre la sélection multiple de tags via expressions booléennes.",
        },
        {
            "name": "[FP][Premium] Multi-tag — Privesc OR Lateral movement",
            "query": "tag:privesc OR tag:lateral_movement OR tag:lateralmovement",
            "description": "Top-bar tags : privilege escalation ou lateral movement.",
        },
        {
            "name": "[FP][Premium] Raw logs — parsing par type (data_type:*)",
            "query": "_exists_:data_type",
            "description": "Liste tous les events parsés (data_type renseigné) — vérifie le parsing.",
        },
        {
            "name": "[FP][Premium] Raw logs — Windows EVTX",
            "query": "data_type:\"windows:evtx:record\" OR source_short:WIN",
            "description": "Filtre rapide sur les events Windows EVTX (vérifie parsing EVTX).",
        },
        {
            "name": "[FP][Premium] Raw logs — Linux syslog",
            "query": "data_type:\"syslog:line\" OR source_short:LIN",
            "description": "Filtre rapide sur les events Linux/Syslog.",
        },
    ]

    for ss in multi_tag_searches:
        res = upsert_saved_search(s, h, sid, ss["name"], ss["query"], ss["description"])
        applied["saved_searches"].append(res)
        mark = "OK" if res.get("ok") else "KO"
        print(f"[ts-premium] saved_search {mark} {ss['name'][:60]}")

    # ── Aggregations premium ────────────────────────────────────────────────
    if not indices:
        print("[ts-premium] WARN pas d'index — aggregations sautées")
        out = LOG_DIR / "timesketch_premium_state.json"
        out.write_text(json.dumps({"sketch_id": sid, "applied": applied}, indent=2), encoding="utf-8")
        return 0

    # field_bucket signature : (field, limit, supported_charts, start_time, end_time, order_field)
    # OpenSearch utilise field.keyword pour les agrégations exactes
    # (text root retourne 0 buckets).
    # On essaie systématiquement le .keyword et on conserve un fallback sur le
    # champ brut quand pertinent.
    common_fb = {"limit": 20, "supported_charts": "barchart"}

    aggregations = [
        {
            "name": "[FP][Premium] Top hosts (hostname)",
            "description": "Top 20 hôtes par volume d'events — barchart (Plaso hostname).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "hostname.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top hosts ECS (host.name)",
            "description": "Top 20 hôtes ECS host.name (vide si pas d'event ECS).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "host.name.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top users (user)",
            "description": "Top 20 utilisateurs — champ Plaso user.",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "user.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top users ECS (user.name)",
            "description": "Top 20 utilisateurs — ECS user.name (vide si pas d'event ECS).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "user.name.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top source IPs (source.ip)",
            "description": "Top 20 IP sources (ECS).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "source.ip.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top destination IPs (destination.ip)",
            "description": "Top 20 IP destinations (ECS).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "destination.ip.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top data_types (parsing répartition)",
            "description": "Répartition par type de log parsé — vérifie le parsing.",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "data_type.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top tags",
            "description": "Top tags (premium — multi-tag visible).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "tag"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top source_short (parser hint)",
            "description": "Origine du parseur Plaso (source_short).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "source_short.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Top timestamp_desc (event types Plaso)",
            "description": "Top types d'événements (timestamp_desc Plaso).",
            "aggregator": "field_bucket",
            "params": {**common_fb, "field": "timestamp_desc.keyword"},
            "chart": "barchart",
        },
        {
            "name": "[FP][Premium] Event timeline (date_histogram day)",
            "description": "Histogramme journalier des events (table).",
            "aggregator": "date_histogram",
            "params": {
                "supported_charts": "table",
                "field": "datetime",
                "supported_intervals": "day",
                "field_query_string": "*",
                "start_time": "2000-01-01T00:00:00",
                "end_time": "2030-01-01T00:00:00",
            },
            "chart": "table",
        },
        {
            "name": "[FP][Premium] Event timeline (date_histogram month)",
            "description": "Histogramme mensuel des events (table).",
            "aggregator": "date_histogram",
            "params": {
                "supported_charts": "table",
                "field": "datetime",
                "supported_intervals": "month",
                "field_query_string": "*",
                "start_time": "2000-01-01T00:00:00",
                "end_time": "2030-01-01T00:00:00",
            },
            "chart": "table",
        },
    ]

    for agg in aggregations:
        run = run_aggregation(
            s,
            h,
            sid,
            agg["name"],
            agg["description"],
            agg["aggregator"],
            agg["params"],
            agg["chart"],
        )
        applied["aggregations_run"].append(run)
        mark = "OK" if run.get("ok") else "KO"
        print(
            f"[ts-premium] agg_run {mark} {agg['aggregator']:<16} rows={run.get('rows', 0):>4} {agg['name'][:55]}"
        )

        saved = save_aggregation(
            s,
            h,
            sid,
            agg["name"],
            agg["description"],
            agg["aggregator"],
            agg["params"],
            agg["chart"],
        )
        applied["aggregations_saved"].append(saved)

    out = LOG_DIR / "timesketch_premium_state.json"
    out.write_text(
        json.dumps({"sketch_id": sid, "applied": applied}, indent=2),
        encoding="utf-8",
    )
    write_sketch_url(sid)

    ko_run = sum(1 for a in applied["aggregations_run"] if not a.get("ok"))
    ko_ss = sum(1 for a in applied["saved_searches"] if not a.get("ok"))
    saved_ok = sum(1 for a in applied["aggregations_saved"] if a.get("ok"))
    print(
        f"[ts-premium] Bilan: saved_searches OK={len(applied['saved_searches']) - ko_ss}/"
        f"{len(applied['saved_searches'])} aggregations_run OK={len(applied['aggregations_run']) - ko_run}/"
        f"{len(applied['aggregations_run'])} aggregations_saved OK={saved_ok}/"
        f"{len(applied['aggregations_saved'])}"
    )
    print(f"[ts-premium] URL: {TS_URL}/sketch/{sid}/aggregation/")
    # Tolérance : les "saved aggregations" persistées dépendent de l'API
    # (certaines versions exposent /aggregation/{id}/ avec parameters différents) ;
    # on ne fait pas échouer le script si seules les exécutions live passent.
    return 0 if ko_run == 0 and ko_ss == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
