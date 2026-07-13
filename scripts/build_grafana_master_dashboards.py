#!/usr/bin/env python3
"""Génère le pack dashboards Grafana FP Master (métriques health.value = source portail)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboards" / "grafana" / "fp-master"

DS_ALL = {"type": "grafana-opensearch-datasource", "uid": "forensic-all"}
DS_PH = {"type": "grafana-opensearch-datasource", "uid": "fp-platform-health"}
DS_INT = {"type": "grafana-opensearch-datasource", "uid": "fp-internal-metrics"}
DS_TS = {"type": "grafana-opensearch-datasource", "uid": "forensic-timesketch-metrics"}
DS_TI = {"type": "grafana-opensearch-datasource", "uid": "forensic-all"}
DS_PROM = {"type": "prometheus", "uid": "fp-prometheus"}
DS_LOKI = {"type": "loki", "uid": "fp-loki"}

# Aligné index-pattern fp-events (OSD Security / platform_health_lib)
FP_EVENTS_INDEX_QUERY = (
    "_index:forensic-windows-* OR _index:forensic-linux-* OR _index:forensic-web-* "
    "OR _index:forensic-network-* OR _index:forensic-cloud-* OR _index:forensic-endpoint-* "
    "OR _index:forensic-macos-* OR _index:forensic-firewall-*"
)


def hist(tf: str = "@timestamp", interval: str = "1d") -> dict:
    return {
        "id": "2",
        "type": "date_histogram",
        "field": tf,
        "settings": {"interval": interval, "min_doc_count": "0"},
    }


def health_value_target(metric: str, *, category: str = "", ref: str = "A") -> dict:
    """Lit health.value (dernier snapshot) — pas un count de documents health."""
    q = f'health.metric: "{metric}"'
    if category:
        q += f' AND health.category: "{category}"'
    return {
        "datasource": DS_PH,
        "query": q,
        "metrics": [{"id": "1", "type": "max", "field": "health.value"}],
        "bucketAggs": [hist()],
        "timeField": "@timestamp",
        "refId": ref,
    }


def health_value_latest_target(metric: str, *, category: str = "", ref: str = "A") -> dict:
    """Dernier snapshot health (fenêtre 2h) — évite max sur 7j obsolète."""
    q = f'health.metric: "{metric}" AND @timestamp:[now-2h TO now]'
    if category:
        q += f' AND health.category: "{category}"'
    return {
        "datasource": DS_PH,
        "query": q,
        "metrics": [{"id": "1", "type": "max", "field": "health.value"}],
        "bucketAggs": [],
        "timeField": "@timestamp",
        "refId": ref,
    }


def siem_24h_live_target(*, ref: str = "A") -> dict:
    """Comptage live fp-events rolling 24h — aligné OSD Security « Total events (24h) »."""
    return {
        "datasource": DS_ALL,
        "query": FP_EVENTS_INDEX_QUERY,
        "metrics": [{"id": "1", "type": "count"}],
        "bucketAggs": [hist(interval="1h")],
        "timeField": "@timestamp",
        "refId": ref,
    }


def platform_24h_live_target(*, ref: str = "A") -> dict:
    """Comptage live forensic-* rolling 24h (plateforme)."""
    return {
        "datasource": DS_ALL,
        "query": "*",
        "metrics": [{"id": "1", "type": "count"}],
        "bucketAggs": [hist(interval="1h")],
        "timeField": "@timestamp",
        "refId": ref,
    }


def event_count_target(ds: dict, query: str, *, interval: str = "1d", ref: str = "A") -> dict:
    """Volume événements sur la période du dashboard (histogram + sum)."""
    return {
        "datasource": ds,
        "query": query,
        "metrics": [{"id": "1", "type": "count"}],
        "bucketAggs": [hist(interval=interval)],
        "timeField": "@timestamp",
        "refId": ref,
    }


def prom_target(expr: str) -> dict:
    return {"datasource": DS_PROM, "expr": expr, "refId": "A", "legendFormat": "value"}


def stat_panel(
    pid: int,
    title: str,
    x: int,
    y: int,
    w: int,
    h: int,
    targets: list,
    *,
    description: str = "",
    time_from: str | None = None,
    time_to: str | None = None,
    datasource: dict | None = None,
    reduce_calc: str = "lastNotNull",
) -> dict:
    p = {
        "id": pid,
        "type": "stat",
        "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": datasource or DS_PH,
        "targets": targets,
        "options": {
            "reduceOptions": {"calcs": [reduce_calc], "fields": "", "values": False},
            "colorMode": "value",
        },
        "fieldConfig": {
            "defaults": {
                "thresholds": {
                    "mode": "absolute",
                    "steps": [{"color": "green", "value": None}],
                }
            }
        },
    }
    if description:
        p["description"] = description
    if time_from:
        p["timeFrom"] = time_from
        p["timeTo"] = time_to or "now"
    return p


def timeseries_panel(pid: int, title: str, x: int, y: int, w: int, h: int, targets: list) -> dict:
    return {
        "id": pid,
        "type": "timeseries",
        "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": targets,
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
    }


def build_dashboard(uid: str, title: str, panels: list, tags: list | None = None) -> dict:
    return {
        "id": None,
        "uid": uid,
        "title": title,
        "tags": tags or ["fp", "forensic", "master"],
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "refresh": "1m",
        "time": {"from": "now-7d", "to": "now"},
        "panels": panels,
        "templating": {"list": []},
    }


def dash_platform_health() -> dict:
    p = [
        stat_panel(1, "Statut global SOC", 0, 0, 6, 4, [health_value_target("global_status")]),
        stat_panel(2, "Composants OK", 6, 0, 6, 4, [health_value_target("component_status", category="soc_autonomous")]),
        stat_panel(3, "Composants WARN", 12, 0, 6, 4, [health_value_target("component_status", ref="B")]),
        stat_panel(4, "Composants FAIL", 18, 0, 6, 4, [health_value_target("component_status", ref="C")]),
        stat_panel(
            5,
            "Events 24h (OpenSearch)",
            0,
            4,
            12,
            4,
            [platform_24h_live_target()],
            description="Comptage live forensic-* rolling 24h.",
            time_from="now-24h",
            time_to="now",
            datasource=DS_ALL,
            reduce_calc="sum",
        ),
        stat_panel(
            8,
            "Events 24h (SIEM)",
            12,
            4,
            12,
            4,
            [siem_24h_live_target()],
            description="Comptage live fp-events rolling 24h — aligné OSD Security.",
            time_from="now-24h",
            time_to="now",
            datasource=DS_ALL,
            reduce_calc="sum",
        ),
        stat_panel(
            6,
            "Events Explore (API)",
            0,
            8,
            12,
            4,
            [health_value_target("explore_events", category="timesketch")],
            description="Compteur API Explore Timesketch (query *).",
        ),
        timeseries_panel(7, "Snapshots health (période)", 12, 8, 12, 8, [event_count_target(DS_PH, "health.category:*")]),
    ]
    return build_dashboard("fp-platform-health-gf", "Metrics — Platform Overview", p, ["fp", "health", "soc"])


def dash_opensearch() -> dict:
    desc = "Snapshot health (aligné portail). Graphique = période sélectionnée."
    p = [
        stat_panel(1, "Index forensic", 0, 0, 6, 4, [health_value_target("index_count", category="opensearch")], description=desc),
        stat_panel(2, "Latence cluster (ms)", 6, 0, 6, 4, [health_value_target("latency_ms", category="opensearch")]),
        stat_panel(3, "Erreurs ingest", 12, 0, 6, 4, [health_value_target("ingest_errors", category="opensearch")]),
        stat_panel(4, "Events 24h (plateforme)", 18, 0, 6, 4, [platform_24h_live_target()], description=desc, time_from="now-24h", time_to="now", datasource=DS_ALL, reduce_calc="sum"),
        stat_panel(
            5,
            "Events 24h (SIEM)",
            0,
            4,
            6,
            4,
            [siem_24h_live_target()],
            description="Comptage live fp-events rolling 24h — aligné OSD Security.",
            time_from="now-24h",
            time_to="now",
            datasource=DS_ALL,
            reduce_calc="sum",
        ),
        timeseries_panel(
            5,
            "Volume événements (période)",
            0,
            4,
            24,
            8,
            [event_count_target(DS_ALL, "*", interval="auto")],
        ),
    ]
    return build_dashboard("fp-opensearch-metrics", "Metrics — OpenSearch Cluster", p, ["fp", "opensearch"])


def dash_timesketch() -> dict:
    desc = "Snapshots health.value (collecte platform_health) — alignés Timesketch API / explore."
    p = [
        stat_panel(
            1,
            "Sketches",
            0,
            0,
            6,
            4,
            [health_value_target("sketch_count", category="timesketch")],
            description=desc,
        ),
        stat_panel(
            2,
            "Timelines",
            6,
            0,
            6,
            4,
            [health_value_target("timeline_count", category="timesketch")],
            description=desc,
        ),
        stat_panel(
            3,
            "Events Explore (API)",
            12,
            0,
            6,
            4,
            [health_value_target("explore_events", category="timesketch")],
            description="API Explore query * — aligné UI Timesketch.",
        ),
        stat_panel(
            4,
            "Events timeline (all-time)",
            18,
            0,
            6,
            4,
            [health_value_target("timeline_events", category="timesketch")],
            description="Docs index timeline sketch actif (OpenSearch).",
        ),
        stat_panel(
            5,
            "Events timeline (24h)",
            0,
            4,
            6,
            4,
            [health_value_target("timeline_events_24h", category="timesketch")],
            description="Index timeline — fenêtre rolling 24h.",
        ),
        stat_panel(
            6,
            "Analyzer runs",
            6,
            4,
            6,
            4,
            [health_value_target("analyzer_runs", category="timesketch")],
            description="Exécutions analyseurs sur le sketch actif (API Timesketch).",
        ),
        stat_panel(
            7,
            "Analyzer failures",
            12,
            4,
            6,
            4,
            [health_value_target("analyzer_failures", category="timesketch")],
            description=desc,
        ),
        timeseries_panel(
            8,
            "Métriques TS (export)",
            0,
            8,
            24,
            8,
            [event_count_target(DS_TS, "metric_type:overview OR metric_type:sketch")],
        ),
    ]
    return build_dashboard("fp-timesketch-metrics", "Metrics — Timesketch Activity", p, ["fp", "timesketch"])


def dash_cti() -> dict:
    desc = "IOC uniques (cardinality index) + indicators GraphQL OpenCTI."
    p = [
        stat_panel(1, "IOC uniques OpenCTI", 0, 0, 6, 4, [health_value_target("ioc_unique_opencti", category="ti")], description=desc),
        stat_panel(2, "Indicators (GraphQL)", 6, 0, 6, 4, [health_value_target("indicators", category="ti")], description=desc),
        stat_panel(3, "Docs index TI", 12, 0, 6, 4, [health_value_target("ioc_index_docs", category="ti")], description="All-time doc count TI indices"),
        stat_panel(4, "Campagnes (OpenCTI)", 18, 0, 6, 4, [health_value_target("campaigns", category="ti")]),
        stat_panel(5, "Malware (OpenCTI)", 0, 4, 6, 4, [health_value_target("malware", category="ti")]),
        timeseries_panel(6, "TI timeline (période)", 0, 8, 24, 8, [event_count_target(DS_TI, "_index:forensic-ti-*")]),
    ]
    return build_dashboard("fp-cti-metrics", "Metrics — Connectors Health", p, ["fp", "cti"])


def dash_misp() -> dict:
    p = [
        stat_panel(1, "IOC MISP (période)", 0, 0, 12, 4, [event_count_target(DS_ALL, "_index:forensic-ti-misp-*")]),
        stat_panel(2, "Sync TI (health)", 12, 0, 12, 4, [health_value_target("last_import", category="ti")]),
        timeseries_panel(3, "MISP imports", 0, 4, 24, 8, [event_count_target(DS_ALL, "_index:forensic-ti-misp-*")]),
    ]
    return build_dashboard("fp-misp-metrics", "Metrics — MISP Connector", p, ["fp", "misp"])


def dash_thehive() -> dict:
    p = [
        stat_panel(1, "TheHive (health)", 0, 0, 12, 4, [health_value_target("component_status", category="soc_autonomous")]),
        stat_panel(2, "Cases IR (période)", 12, 0, 12, 4, [event_count_target(DS_ALL, "message:*thehive* OR message:*case*")]),
        timeseries_panel(3, "IR activity", 0, 4, 24, 8, [event_count_target(DS_ALL, "message:*ir.phase*")]),
    ]
    return build_dashboard("fp-thehive-metrics", "Metrics — TheHive IR", p, ["fp", "thehive"])


def dash_cortex() -> dict:
    p = [
        stat_panel(1, "Cortex (health)", 0, 0, 12, 4, [health_value_target("component_status", category="soc_autonomous")]),
        stat_panel(2, "Analyzers (période)", 12, 0, 12, 4, [event_count_target(DS_INT, "*")]),
        timeseries_panel(3, "Cortex / analyzers", 0, 4, 24, 8, [event_count_target(DS_ALL, "message:*cortex* OR message:*analyzer*")]),
    ]
    return build_dashboard("fp-cortex-metrics", "Metrics — Cortex Analyzers", p, ["fp", "cortex"])


def dash_grafana_self() -> dict:
    p = [
        stat_panel(1, "Prometheus UP", 0, 0, 8, 4, [prom_target('up{job="grafana"}')]),
        stat_panel(2, "Scrape targets", 8, 0, 8, 4, [prom_target("count(up)")]),
        stat_panel(3, "Grafana health", 16, 0, 8, 4, [health_value_target("component_status", category="soc_autonomous")]),
        timeseries_panel(4, "Prometheus samples", 0, 4, 24, 8, [prom_target("prometheus_tsdb_head_series")]),
    ]
    return build_dashboard("fp-grafana-metrics", "FP — Grafana Metrics", p, ["fp", "grafana"])


def dash_soc_autonomous() -> dict:
    p = [
        stat_panel(1, "GLOBAL OK", 0, 0, 6, 4, [health_value_target("global_status", category="soc_autonomous")]),
        stat_panel(2, "GLOBAL WARN", 6, 0, 6, 4, [health_value_target("component_status", ref="B")]),
        stat_panel(3, "GLOBAL FAIL", 12, 0, 6, 4, [health_value_target("component_status", ref="C")]),
        stat_panel(4, "Composants SOC", 18, 0, 6, 4, [event_count_target(DS_PH, 'health.category: "soc_autonomous"')]),
        timeseries_panel(5, "SOC Autonomous timeline", 0, 4, 24, 8, [event_count_target(DS_PH, 'health.category: "soc_autonomous"')]),
    ]
    return build_dashboard("fp-soc-autonomous-metrics", "Metrics — SOC Autonomous", p, ["fp", "soc", "autonomous"])


def dash_pipelines() -> dict:
    p = [
        stat_panel(1, "Parse errors", 0, 0, 8, 4, [health_value_target("parse_errors", category="parsing")]),
        stat_panel(2, "Missing host.name", 8, 0, 8, 4, [health_value_target("missing_host_name", category="parsing")]),
        stat_panel(3, "Datasets (health)", 16, 0, 8, 4, [health_value_target("docs_by_dataset", category="parsing")]),
        timeseries_panel(4, "Parsing volume (période)", 0, 4, 24, 8, [event_count_target(DS_ALL, "event.dataset:*")]),
    ]
    return build_dashboard("fp-pipelines-parsing-metrics", "Metrics — Ingestion Pipelines", p, ["fp", "parsing"])


def dash_alerts() -> dict:
    p = [
        stat_panel(1, "Alertes (période)", 0, 0, 8, 4, [event_count_target(DS_ALL, "_index:forensic-alerts* OR level:critical", interval="1h")]),
        stat_panel(2, "Sigma hits 24h", 8, 0, 8, 4, [health_value_target("hits_24h", category="sigma")]),
        stat_panel(3, "Sigma errors", 16, 0, 8, 4, [health_value_target("execution_errors", category="sigma")]),
        timeseries_panel(4, "Alerts timeline", 0, 4, 24, 8, [event_count_target(DS_ALL, "_index:forensic-alerts*")]),
    ]
    return build_dashboard("fp-alerts-metrics", "Metrics — Alerts Pipeline", p, ["fp", "alerts"])


BUILDERS = [
    dash_platform_health,
    dash_opensearch,
    dash_timesketch,
    dash_cti,
    dash_misp,
    dash_thehive,
    dash_cortex,
    dash_grafana_self,
    dash_soc_autonomous,
    dash_pipelines,
    dash_alerts,
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for fn in BUILDERS:
        dash = fn()
        path = OUT / f"{dash['uid']}.json"
        path.write_text(json.dumps(dash, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"  wrote {path.name}")
    print(f"OK {len(BUILDERS)} dashboards → {OUT}")


if __name__ == "__main__":
    main()
