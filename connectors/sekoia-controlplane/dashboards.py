"""SEKOIA EXTENDED PLATFORM — Dashboard & Visualization Layer (module 3.7).

Le SIEM Sekoia ne propose aucun tableau de bord d'ingestion : pas de courbe de
volumétrie, pas de carte de chaleur d'activité, pas de comparaison entre sources,
pas d'exploration temporelle. Un analyste ne peut ni voir une tendance, ni
repérer une source qui décroche, ni situer un incident dans le temps.

Ce module sert en UN SEUL appel tout ce qu'un tableau de bord exige — série
temporelle, classement des sources, carte de chaleur, répartition des alertes,
indicateurs — calculé sur la télémétrie produite par le moteur de volumétrie.

Choix de conception : l'agrégation est faite ICI, pas dans le navigateur. Le
front reçoit des séries prêtes à tracer, ce qui garde l'écran fluide même avec
des centaines de sources et évite de transférer des milliers de documents.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, Query

import app as cp

VOLUMETRY_INDEX = "sekoia-volumetry-*"
INTAKES_INDEX = "sekoia-intakes-*"
ALERTS_INDEX = "sekoia-alerts-*"


def _interval_for(hours: int) -> str:
    """Granularité adaptée à la fenêtre : ni 2000 points, ni 3."""
    if hours <= 6:
        return "15m"
    if hours <= 48:
        return "1h"
    if hours <= 24 * 14:
        return "6h"
    return "1d"


def _buckets(agg: Optional[dict], key: str) -> list:
    return ((agg or {}).get(key) or {}).get("buckets", []) or []


async def build(hours: int, top: int) -> dict:
    interval = _interval_for(hours)
    window = {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}

    # ── Série temporelle globale + par source (une seule requête) ────────────
    # `count_1h` est un compteur GLISSANT sur une heure, ré-échantillonné à
    # chaque cycle de collecte. Le sommer sur un créneau multiplierait le volume
    # par le nombre de collectes (mesuré : 61 M au lieu de ~1,7 M/h). On prend
    # donc le MAX par source et par créneau, puis on somme entre sources —
    # d'où le pipeline sum_bucket.
    ts_body = {
        "size": 0, "query": window,
        "aggs": {
            "total": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": interval,
                                   "min_doc_count": 0},
                "aggs": {
                    "per_intake": {"terms": {"field": "intake_uuid.keyword", "size": 1000},
                                   "aggs": {"v": {"max": {"field": "count_1h"}}}},
                    "vol": {"sum_bucket": {"buckets_path": "per_intake>v"}},
                },
            },
            "per_intake": {
                "terms": {"field": "intake_name.keyword", "size": top,
                          "order": {"vol": "desc"}},
                "aggs": {
                    "vol": {"max": {"field": "count_1h"}},
                    "ts": {"date_histogram": {"field": "@timestamp",
                                              "fixed_interval": interval,
                                              "min_doc_count": 0},
                           "aggs": {"v": {"max": {"field": "count_1h"}}}},
                },
            },
        },
    }
    ts_res, ts_err = await cp.os_search(VOLUMETRY_INDEX, ts_body)
    ts_aggs = (ts_res or {}).get("aggregations") or {}

    timeline = [{"ts": b.get("key_as_string"),
                 "count": round((b.get("vol") or {}).get("value") or 0)}
                for b in _buckets(ts_aggs, "total")]

    series = []
    for b in _buckets(ts_aggs, "per_intake"):
        series.append({
            "intake_name": b.get("key"),
            "total": round((b.get("vol") or {}).get("value") or 0),
            "points": [{"ts": p.get("key_as_string"),
                        "count": round((p.get("v") or {}).get("value") or 0)}
                       for p in _buckets(b, "ts")],
        })

    # ── Carte de chaleur : source × créneau ──────────────────────────────────
    # Réutilise `series` : une seule passe sur les mêmes buckets, aucun appel
    # OpenSearch supplémentaire.
    slots = [p["ts"] for p in (series[0]["points"] if series else timeline)]
    heatmap = {
        "slots": slots,
        "rows": [{"label": s["intake_name"],
                  "values": [p["count"] for p in s["points"]]}
                 for s in series],
        "max": max([p["count"] for s in series for p in s["points"]] or [0]),
    }

    # ── État courant des sources ─────────────────────────────────────────────
    state_body = {
        "size": 0, "query": {"range": {"@timestamp": {"gte": "now-2h"}}},
        "aggs": {"per_intake": {
            "terms": {"field": "intake_uuid.keyword", "size": 1000},
            "aggs": {"last": {"top_hits": {
                "size": 1, "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": ["intake_name", "current_count", "silent",
                            "volume_available", "entity_name", "baseline_avg"]}}}}},
    }
    st_res, st_err = await cp.os_search(INTAKES_INDEX, state_body)
    sources = []
    for b in _buckets((st_res or {}).get("aggregations") or {}, "per_intake"):
        hits = (((b.get("last") or {}).get("hits") or {}).get("hits") or [])
        if hits:
            sources.append(hits[0].get("_source") or {})
    measured = [s for s in sources if s.get("volume_available")]
    silent = [s for s in measured if s.get("silent")]
    active = [s for s in measured if (s.get("current_count") or 0) > 0]

    top_sources = sorted(
        ({"name": s.get("intake_name"), "entity": s.get("entity_name"),
          "count": s.get("current_count") or 0,
          "baseline": round(s.get("baseline_avg") or 0)}
         for s in measured), key=lambda x: -x["count"])[:top]

    # ── Alertes : répartition et chronologie ─────────────────────────────────
    al_body = {
        "size": 0, "query": window,
        "aggs": {
            "by_severity": {"terms": {"field": "severity.keyword", "size": 10}},
            "by_type": {"terms": {"field": "rule_type.keyword", "size": 15}},
            "timeline": {"date_histogram": {"field": "@timestamp",
                                            "fixed_interval": interval,
                                            "min_doc_count": 0}},
        },
    }
    al_res, al_err = await cp.os_search(ALERTS_INDEX, al_body)
    al_aggs = (al_res or {}).get("aggregations") or {}

    errors = [e for e in (ts_err, st_err, al_err) if e]
    return {
        "available": bool(timeline or sources),
        "errors": errors or None,
        "hours": hours, "interval": interval,
        "kpi": {
            # Débit courant (dernier créneau mesuré) plutôt qu'un cumul : additionner
            # des compteurs glissants d'une heure n'a pas de sens métier.
            "events_per_hour": timeline[-1]["count"] if timeline else 0,
            "events_peak": max([p["count"] for p in timeline] or [0]),
            "sources_total": len(sources),
            "sources_active": len(active),
            "sources_silent": len(silent),
            "sources_unmeasured": len(sources) - len(measured),
        },
        "timeline": timeline,
        "series": series,
        "heatmap": heatmap,
        "top_sources": top_sources,
        "alerts": {
            "by_severity": {b["key"]: b["doc_count"]
                            for b in _buckets(al_aggs, "by_severity")},
            "by_type": {b["key"]: b["doc_count"]
                        for b in _buckets(al_aggs, "by_type")},
            "timeline": [{"ts": b.get("key_as_string"), "count": b.get("doc_count", 0)}
                         for b in _buckets(al_aggs, "timeline")],
        },
    }


def register(dash_app) -> None:
    dep = [Depends(cp.require_internal_token)]

    @dash_app.get("/control/sekoia/dashboard", dependencies=dep)
    async def dashboard(hours: int = Query(default=24, ge=1, le=24 * 90),
                        top: int = Query(default=10, ge=1, le=50)):
        return await build(hours, top)
