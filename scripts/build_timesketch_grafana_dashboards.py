#!/usr/bin/env python3
"""Génère les dashboards Grafana Timesketch (format compatible grafana-opensearch-datasource)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "timesketch"

DS_TS = {"type": "grafana-opensearch-datasource", "uid": "forensic-timesketch"}
DS_MET = {"type": "grafana-opensearch-datasource", "uid": "forensic-timesketch-metrics"}
DS_ALL = {"type": "grafana-opensearch-datasource", "uid": "forensic-all"}


def ds(uid: str) -> dict:
    return {"type": "grafana-opensearch-datasource", "uid": uid}


def time_field(uid: str) -> str:
    return "datetime" if uid == "forensic-timesketch" else "@timestamp"


def hist_bucket(uid: str, interval: str = "1d") -> dict:
    return {
        "id": "2",
        "type": "date_histogram",
        "field": time_field(uid),
        "settings": {"interval": interval, "min_doc_count": "0"},
    }


def target_stat(uid: str, query: str, *, field: str | None = None, interval: str = "30d") -> dict:
    if field:
        metrics = [{"id": "1", "type": "max", "field": field}]
    else:
        metrics = [{"id": "1", "type": "count"}]
    return {
        "datasource": ds(uid),
        "query": query,
        "metrics": metrics,
        "bucketAggs": [hist_bucket(uid, interval)],
        "timeField": time_field(uid),
    }


def target_series(uid: str, query: str, interval: str = "1d", alias: str | None = None) -> dict:
    t = {
        "datasource": ds(uid),
        "query": query,
        "metrics": [{"id": "1", "type": "count"}],
        "bucketAggs": [hist_bucket(uid, interval)],
        "timeField": time_field(uid),
    }
    if alias:
        t["alias"] = alias
    return t


def target_terms(uid: str, query: str, field: str, size: str = "12") -> dict:
    # orderBy "1" → résultats vides avec grafana-opensearch-datasource 2.17 (plugin renvoie {})
    return {
        "datasource": ds(uid),
        "query": query,
        "metrics": [{"id": "1", "type": "count"}],
        "bucketAggs": [
            {
                "id": "2",
                "type": "terms",
                "field": field,
                "settings": {"size": size, "order": "desc", "orderBy": "_count"},
            }
        ],
        "timeField": time_field(uid),
    }


def stat_panel(pid: int, title: str, x: int, y: int, w: int, h: int, uid: str, query: str, **kw) -> dict:
    return {
        "id": pid,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "type": "stat",
        "title": title,
        "fieldConfig": {
            "defaults": {
                "color": {"mode": "thresholds"},
                "thresholds": {"steps": [{"color": "blue", "value": None}]},
            }
        },
        "options": {
            # date_histogram 30d → [0, N] ou [None, N] : max évite d'afficher 0 (first/lastNotNull)
            "reduceOptions": {
                "calcs": ["max"],
            },
            "colorMode": "value",
        },
        "targets": [target_stat(uid, query, **kw)],
    }


def overview() -> dict:
    return {
        "id": None,
        "uid": "timesketch-overview",
        "title": "Timesketch — Overview",
        "tags": ["timesketch", "forensic", "point4"],
        "timezone": "browser",
        "schemaVersion": 38,
        "version": 2,
        "refresh": "1m",
        "time": {"from": "now-30d", "to": "now"},
        "panels": [
            # Stats via champs overview (export ts-metrics) — même pattern que Uploads [FP]
            stat_panel(1, "Sketches (sync API)", 0, 0, 4, 4, "forensic-all", "metric_type:overview", field="sketch_count", interval="30d"),
            stat_panel(2, "Timelines", 4, 0, 4, 4, "forensic-all", "metric_type:overview", field="timeline_count", interval="30d"),
            stat_panel(3, "Événements Timesketch", 8, 0, 4, 4, "forensic-all", "metric_type:overview", field="events_count", interval="30d"),
            stat_panel(4, "Règles Sigma (API)", 12, 0, 4, 4, "forensic-all", "metric_type:overview", field="sigma_rules_count", interval="30d"),
            stat_panel(5, "Uploads [FP]", 16, 0, 4, 4, "forensic-all", "case_id:FP* OR case_id:TS* OR case_id:CASE* OR tags:timesketch*", interval="30d"),
            stat_panel(6, "Docs métriques erreurs", 20, 0, 4, 4, "forensic-all", "metric_type:error_log", interval="30d"),
            {
                "id": 7,
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
                "type": "timeseries",
                "title": "Événements par jour",
                "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"lineWidth": 2}}},
                "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
                "targets": [target_series("forensic-timesketch", "__ts_timeline_id:*")],
            },
            {
                "id": 8,
                "gridPos": {"h": 8, "w": 6, "x": 12, "y": 4},
                "type": "barchart",
                "title": "Top tags (sources / cases)",
                "targets": [target_terms("forensic-timesketch", "__ts_timeline_id:*", "tag.keyword", "15")],
            },
            {
                "id": 9,
                "gridPos": {"h": 8, "w": 6, "x": 18, "y": 4},
                "type": "piechart",
                "title": "Répartition tags plateforme",
                "targets": [target_terms("forensic-timesketch", "__ts_timeline_id:*", "tag.keyword", "8")],
            },
            {
                "id": 10,
                "gridPos": {"h": 7, "w": 8, "x": 0, "y": 12},
                "type": "barchart",
                "title": "Tags Sigma (attack.*)",
                "targets": [
                    target_terms(
                        "forensic-timesketch",
                        "__ts_timeline_id:* AND (tag:attack* OR tag:*credential* OR tag:*defense*)",
                        "tag.keyword",
                    )
                ],
            },
            {
                "id": 11,
                "gridPos": {"h": 7, "w": 8, "x": 8, "y": 12},
                "type": "barchart",
                "title": "Tags TI / intelligence",
                "targets": [
                    target_terms(
                        "forensic-timesketch",
                        "__ts_timeline_id:* AND (tag:intelligence OR tag:ti OR tag:*ioc*)",
                        "tag.keyword",
                    )
                ],
            },
            {
                "id": 12,
                "gridPos": {"h": 7, "w": 8, "x": 16, "y": 12},
                "type": "table",
                "title": "Erreurs récentes (logs web/worker)",
                "targets": [
                    {
                        "datasource": ds("forensic-all"),
                        "query": "metric_type:error_log",
                        "metrics": [{"id": "1", "type": "raw_data", "settings": {"size": 30}}],
                        "bucketAggs": [hist_bucket("forensic-all", "30d")],
                        "timeField": "@timestamp",
                    }
                ],
            },
            {
                "id": 13,
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 19},
                "type": "table",
                "title": "Sketches (dernier export métriques)",
                "targets": [
                    {
                        "datasource": ds("forensic-all"),
                        "query": "metric_type:sketch",
                        "metrics": [{"id": "1", "type": "raw_data", "settings": {"size": 50}}],
                        "bucketAggs": [hist_bucket("forensic-all", "30d")],
                        "timeField": "@timestamp",
                    }
                ],
            },
        ],
    }


def workflow() -> dict:
    var_query = json.dumps(
        {"find": "terms", "field": "tag.keyword", "size": 40, "query": "__ts_timeline_id:*"}
    )
    return {
        "id": None,
        "uid": "timesketch-analyst-workflow",
        "title": "Timesketch — Analyst Workflow",
        "tags": ["timesketch", "forensic", "analyst", "point4"],
        "timezone": "browser",
        "schemaVersion": 38,
        "version": 2,
        "refresh": "1m",
        "time": {"from": "now-30d", "to": "now"},
        "templating": {
            "list": [
                {
                    "name": "case_tag",
                    "type": "query",
                    "datasource": DS_TS,
                    "query": var_query,
                    "definition": var_query,
                    "refresh": 2,
                    "includeAll": True,
                    "allValue": "*",
                    "multi": False,
                    "label": "Case / tag",
                    "regex": "/^(CASE|TS-|IR-|TS-ADV|TS-FULL)/",
                    "sort": 1,
                    "current": {"text": "All", "value": "$__all"},
                }
            ]
        },
        "panels": [
            stat_panel(1, "Sketches actifs", 0, 0, 6, 4, "forensic-all", "metric_type:overview", field="sketch_count", interval="30d"),
            stat_panel(2, "Timelines", 6, 0, 6, 4, "forensic-all", "metric_type:overview", field="timeline_count", interval="30d"),
            stat_panel(
                3,
                "Events (filtre tag)",
                12,
                0,
                6,
                4,
                "forensic-timesketch",
                "__ts_timeline_id:* AND tag:($case_tag)",
                interval="30d",
            ),
            stat_panel(
                4,
                "Analyzers (export)",
                18,
                0,
                6,
                4,
                "forensic-all",
                "metric_type:sketch",
                field="analyzer_runs",
                interval="30d",
            ),
            {
                "id": 5,
                "gridPos": {"h": 8, "w": 14, "x": 0, "y": 4},
                "type": "timeseries",
                "title": "Activité par tag (30j)",
                "targets": [
                    target_series(
                        "forensic-timesketch",
                        "__ts_timeline_id:* AND tag:($case_tag)",
                        interval="1d",
                    )
                ],
            },
            {
                "id": 6,
                "gridPos": {"h": 8, "w": 10, "x": 14, "y": 4},
                "type": "piechart",
                "title": "Répartition sources (tag)",
                "targets": [
                    target_terms(
                        "forensic-timesketch",
                        "__ts_timeline_id:* AND tag:($case_tag)",
                        "tag.keyword",
                    )
                ],
            },
            {
                "id": 7,
                "gridPos": {"h": 7, "w": 12, "x": 0, "y": 12},
                "type": "barchart",
                "title": "Résultats Sigma par tag",
                "targets": [
                    target_terms(
                        "forensic-timesketch",
                        "__ts_timeline_id:* AND tag:($case_tag) AND (tag:attack* OR tag:*sigma*)",
                        "tag.keyword",
                    )
                ],
            },
            {
                "id": 8,
                "gridPos": {"h": 7, "w": 12, "x": 12, "y": 12},
                "type": "barchart",
                "title": "Résultats TI par tag",
                "targets": [
                    target_terms(
                        "forensic-timesketch",
                        "__ts_timeline_id:* AND tag:($case_tag) AND (tag:intelligence OR tag:ti)",
                        "tag.keyword",
                    )
                ],
            },
            {
                "id": 9,
                "gridPos": {"h": 7, "w": 12, "x": 0, "y": 19},
                "type": "barchart",
                "title": "Timelines par statut",
                "targets": [
                    target_terms(
                        "forensic-all",
                        "metric_type:timeline",
                        "timeline_status.keyword",
                    )
                ],
            },
            {
                "id": 10,
                "gridPos": {"h": 7, "w": 12, "x": 12, "y": 19},
                "type": "barchart",
                "title": "Sketches (export)",
                "targets": [
                    target_terms(
                        "forensic-all",
                        "metric_type:sketch",
                        "sketch_name.keyword",
                        "15",
                    )
                ],
            },
            {
                "id": 11,
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 26},
                "type": "table",
                "title": "Uploads plateforme (case)",
                "targets": [
                    {
                        "datasource": ds("forensic-all"),
                        "query": "case_id:$case_tag OR tags:timesketch*",
                        "metrics": [{"id": "1", "type": "raw_data", "settings": {"size": 25}}],
                        "bucketAggs": [hist_bucket("forensic-all", "30d")],
                        "timeField": "@timestamp",
                    }
                ],
            },
        ],
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, dash in [
        ("timesketch_overview.json", overview()),
        ("timesketch_analyst_workflow.json", workflow()),
    ]:
        path = OUT / name
        path.write_text(json.dumps(dash, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
