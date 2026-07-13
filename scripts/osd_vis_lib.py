#!/usr/bin/env python3
"""Helpers visualisations OpenSearch Dashboards 2.12 — visState compatibles (évite erreurs metric.show)."""
from __future__ import annotations

import json
from typing import Any


MIGRATION = {
    "index-pattern": "7.6.0",
    "search": "7.9.3",
    "visualization": "7.10.0",
    "dashboard": "7.9.3",
}


def saved_object(otype: str, oid: str, attributes: dict, references: list | None = None) -> dict:
    return {
        "id": oid,
        "type": otype,
        "attributes": attributes,
        "references": references or [],
        "migrationVersion": {otype: MIGRATION.get(otype, "7.10.0")},
    }


def _metric_params() -> dict[str, Any]:
    return {
        "type": "metric",
        "addTooltip": True,
        "addLegend": False,
        "metric": {
            "percentageMode": False,
            "useRanges": False,
            "colorSchema": "Green to Red",
            "metricColorMode": "None",
            "colorsRange": [{"from": 0, "to": 100}],
            "labels": {"show": True},
            "invertColors": False,
            "style": {
                "bgFill": "#000",
                "bgColor": False,
                "labelColor": False,
                "subText": "",
                "fontSize": 48,
            },
        },
    }


def _pie_params() -> dict[str, Any]:
    return {
        "type": "pie",
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "isDonut": False,
        "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
    }


def _histogram_params(field: str = "@timestamp") -> dict[str, Any]:
    return {
        "type": "histogram",
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "truncate": 100},
                "title": {},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": "histogram",
                "mode": "stacked",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": False,
                "showCircles": True,
            }
        ],
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
    }


def vis_search_source(index_id: str, query: str) -> tuple[dict, list]:
    ss = {
        "index": index_id,
        "query": {"language": "kuery", "query": query},
        "filter": [],
    }
    refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_id}]
    return ss, refs


def vis_metric(oid: str, title: str, index_id: str, query: str) -> dict:
    vis_state = {
        "title": title,
        "type": "metric",
        "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}],
        "params": _metric_params(),
    }
    ss, refs = vis_search_source(index_id, query)
    return saved_object(
        "visualization",
        oid,
        {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        refs,
    )


def vis_metric_max(
    oid: str,
    title: str,
    index_id: str,
    query: str,
    field: str = "health.value",
) -> dict:
    """Métrique = max(field) — pour snapshots health.value (pas count de documents)."""
    vis_state = {
        "title": title,
        "type": "metric",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "max",
                "schema": "metric",
                "params": {"field": field},
            }
        ],
        "params": _metric_params(),
    }
    ss, refs = vis_search_source(index_id, query)
    return saved_object(
        "visualization",
        oid,
        {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        refs,
    )


def vis_metric_cardinality(
    oid: str,
    title: str,
    index_id: str,
    query: str,
    field: str = "ioc_value",
) -> dict:
    """Métrique = IOC uniques (cardinality) — évite double-comptage unified."""
    vis_state = {
        "title": title,
        "type": "metric",
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "cardinality",
                "schema": "metric",
                "params": {"field": terms_agg_field(field)},
            }
        ],
        "params": _metric_params(),
    }
    ss, refs = vis_search_source(index_id, query)
    return saved_object(
        "visualization",
        oid,
        {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "IOC uniques (cardinality) — index canonique sans forensic-ti-unified",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        refs,
    )


def terms_agg_field(field: str) -> str:
    """Champ compatible agrégation terms (évite Saved field invalid dans l'UI)."""
    if field.endswith(".keyword") or field.startswith("_"):
        return field
    if field in (
        "@timestamp", "datetime", "ioc_type", "ioc_value", "source", "metric_type", "event.code",
        "technique_id", "tactic", "geoip.country", "asn", "cluster_id", "threat_score",
    ):
        return field
    if field in ("event.module", "tags", "message", "service", "ti_sources"):
        return f"{field}.keyword"
    return field


def vis_pie(
    oid: str,
    title: str,
    index_id: str,
    query: str,
    field: str,
    size: int = 12,
    terms_field: str | None = None,
) -> dict:
    agg_field = terms_field if terms_field is not None else terms_agg_field(field)
    vis_state = {
        "title": title,
        "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {"field": agg_field, "size": size, "order": "desc", "orderBy": "1"},
            },
        ],
        "params": _pie_params(),
    }
    ss, refs = vis_search_source(index_id, query)
    return saved_object(
        "visualization",
        oid,
        {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        refs,
    )


def vis_histogram(oid: str, title: str, index_id: str, query: str, field: str = "@timestamp") -> dict:
    vis_state = {
        "title": title,
        "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "schema": "segment",
                "params": {"field": field, "interval": "auto", "min_doc_count": 1},
            },
        ],
        "params": _histogram_params(field),
    }
    ss, refs = vis_search_source(index_id, query)
    return saved_object(
        "visualization",
        oid,
        {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        refs,
    )


def vis_data_table(oid: str, title: str, index_id: str, query: str, fields: list[str]) -> dict:
    vis_state = {
        "title": title,
        "type": "table",
        "aggs": [],
        "params": {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False,
            "totalFunc": "sum",
        },
        "columns": [{"aggId": None, "field": f, "id": str(i)} for i, f in enumerate(fields)],
    }
    ss, refs = vis_search_source(index_id, query)
    return saved_object(
        "visualization",
        oid,
        {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        refs,
    )
