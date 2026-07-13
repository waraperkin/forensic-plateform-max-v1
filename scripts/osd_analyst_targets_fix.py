#!/usr/bin/env python3
"""
Corrige les cibles UI analyste : dashboard Security, visualisations, Maps TI,
Observability, Reporting, Alerting drill-down.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OSD_NGINX = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")

sys.path.insert(0, str(ROOT / "scripts"))
from fp_http_lib import wait_osd  # noqa: E402

# Visualisations sample (URLs analyste) → contenu FP
SAMPLE_VIZ_FP = {
    "19717e00-228f-11ee-b88b-47a93b5c527c": {
        "title": "FP — Windows event.code",
        "index": "fp-events",
        "query": "_index:forensic-windows*",
        "field": "event.code",
        "type": "pie",
    },
    "fa54ce40-eb7b-11ed-8e00-17d7d50cd7b2": {
        "title": "FP — Events per day",
        "index": "fp-events",
        "query": "*",
        "field": "@timestamp",
        "type": "histogram",
    },
    "009fd930-22a8-11ee-b88b-47a93b5c527c": {
        "title": "FP — Linux top tags",
        "index": "fp-events",
        "query": "_index:forensic-linux*",
        "field": "tags.keyword",
        "type": "pie",
    },
    "9482ed20-eb9b-11ed-8e00-17d7d50cd7b2": {
        "title": "FP — TI matches per day",
        "index": "fp-events",
        "query": "ti_match: true",
        "field": "@timestamp",
        "type": "histogram",
    },
}

FP_VIZ_FIXES = {
    "fp-viz-win-module": {"field": "event.code", "title": "Windows — event.code"},
    "fp-viz-linux-tags": {"field": "tags.keyword"},
    "fp-viz-ts-timeline": {"field": "@timestamp", "query": "*", "index": "fp-timesketch"},
    "fp-viz-ts-tags": {"field": "metric_type", "query": "*", "index": "fp-timesketch", "title": "Timesketch — metric type"},
}

SAVED_SEARCHES_DRILL = [
    ("fp-search-win-module", "FP — Windows events (Discover)", "fp-events", "_index:forensic-windows*",
     ["@timestamp", "message", "host.name", "event.code", "event.module"]),
    ("fp-search-linux-tags", "FP — Linux events (Discover)", "fp-events", "_index:forensic-linux*",
     ["@timestamp", "message", "host.name", "tags"]),
    ("fp-search-ts-metrics", "FP — Timesketch metrics (Discover)", "fp-timesketch", "*",
     ["@timestamp", "metric_type", "sketch_name", "events_count", "message"]),
    ("fp-search-ti-matches-discover", "FP — TI matches events (Discover)", "fp-events", "ti_match: true",
     ["@timestamp", "message", "ti_ioc_value", "ti_sources", "host.name"]),
]


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def ok(msg: str) -> None:
    print(f"[analyst-fix] OK {msg}")


def ko(msg: str) -> None:
    print(f"[analyst-fix] KO {msg}", file=sys.stderr)


def terms_field(field: str) -> str:
    if field.startswith("_") or field.endswith(".keyword"):
        return field
    if field in ("@timestamp", "datetime", "ioc_type", "ioc_value", "source", "metric_type", "event.code"):
        return field
    if field in ("event.module", "tags", "message", "service"):
        return f"{field}.keyword"
    return field


def patch_vis_state(vis_state: dict, field: str | None, query: str | None, index_id: str | None) -> dict:
    vs = json.loads(json.dumps(vis_state))
    if field and len(vs.get("aggs", [])) > 1:
        vs["aggs"][1]["params"]["field"] = terms_field(field)
    if vs.get("type") == "histogram" and field:
        vs["aggs"][1]["params"]["field"] = field
    return vs


def put_visualization(s: requests.Session, vid: str, attrs: dict, refs: list) -> bool:
    r = s.put(
        f"{OSD}/api/saved_objects/visualization/{vid}",
        headers=hdrs(),
        json={"attributes": attrs, "references": refs},
        timeout=30,
        verify=False,
    )
    return r.status_code in (200, 201)


def fix_fp_visualization(s: requests.Session, vid: str, fixes: dict) -> int:
    r = s.get(f"{OSD}/api/saved_objects/visualization/{vid}", headers=hdrs(), timeout=20, verify=False)
    if r.status_code != 200:
        ko(f"viz {vid} introuvable")
        return 1
    body = r.json()
    attrs = body["attributes"]
    refs = body.get("references", [])
    vs = json.loads(attrs["visState"])
    ss = json.loads(attrs["kibanaSavedObjectMeta"]["searchSourceJSON"])
    if fixes.get("title"):
        attrs["title"] = fixes["title"]
        vs["title"] = fixes["title"]
    if fixes.get("index"):
        ss["index"] = fixes["index"]
        refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": fixes["index"]}]
    if fixes.get("query") is not None:
        ss["query"] = {"language": "kuery", "query": fixes["query"]}
    field = fixes.get("field")
    if field:
        vs = patch_vis_state(vs, field, fixes.get("query"), fixes.get("index"))
    attrs["visState"] = json.dumps(vs)
    attrs["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(ss)
    if put_visualization(s, vid, attrs, refs):
        ok(f"viz {vid} ({attrs['title']})")
        return 0
    ko(f"viz {vid} PUT failed")
    return 1


def rebuild_sample_viz_as_fp(s: requests.Session, vid: str, spec: dict) -> int:
    sys.path.insert(0, str(ROOT / "scripts"))
    from osd_vis_lib import vis_histogram, vis_pie  # noqa: E402

    if spec["type"] == "pie":
        obj = vis_pie(vid, spec["title"], spec["index"], spec["query"], spec["field"])
    else:
        obj = vis_histogram(vid, spec["title"], spec["index"], spec["query"], spec["field"])
    if put_visualization(s, vid, obj["attributes"], obj["references"]):
        ok(f"sample viz {vid} → {spec['title']}")
        return 0
    return 1


def upsert_saved_search(
    s: requests.Session,
    sid: str,
    title: str,
    index_id: str,
    query: str,
    columns: list[str] | None = None,
) -> int:
    attrs = {
        "title": title,
        "description": "Drill-down Forensic Platform — clic panel associé ou Discover",
        "hits": 0,
        "columns": columns or ["@timestamp", "message", "host.name", "event.code", "tags"],
        "sort": [["@timestamp", "desc"]],
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(
                {"index": index_id, "query": {"language": "kuery", "query": query}, "filter": []}
            )
        },
    }
    refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_id}]
    for method, path in (
        ("put", f"{OSD}/api/saved_objects/search/{sid}"),
        ("post", f"{OSD}/api/saved_objects/search/{sid}"),
    ):
        r = s.request(method, path, headers=hdrs(), json={"attributes": attrs, "references": refs}, timeout=20, verify=False)
        if r.status_code in (200, 201):
            ok(f"saved search {sid}")
            return 0
    ko(f"saved search {sid}")
    return 1


def fix_security_dashboard_drilldown(s: requests.Session) -> int:
    """Ajoute panels Discover + liens drill-down sur fp-opensearch-security."""
    r = s.get(f"{OSD}/api/saved_objects/dashboard/fp-opensearch-security", headers=hdrs(), timeout=20, verify=False)
    if r.status_code != 200:
        return 1
    dash = r.json()
    panels = json.loads(dash["attributes"]["panelsJSON"])
    refs = list(dash.get("references", []))
    ref_names = {x["name"] for x in refs}

    for sid, title, idx, q, cols in SAVED_SEARCHES_DRILL:
        upsert_saved_search(s, sid, title, idx, q, cols)

    drill_panels = [
        ("fp-search-win-module", 0, 36, 12, 6),
        ("fp-search-linux-tags", 12, 36, 12, 6),
        ("fp-search-ts-metrics", 0, 42, 24, 8),
        ("fp-search-ti-matches-discover", 0, 50, 24, 8),
    ]

    new_panels = []
    title_by_id = {sid: title for sid, title, _, _, _ in SAVED_SEARCHES_DRILL}
    for sid, x, y, w, h in drill_panels:
        title = title_by_id[sid]
        p = {
            "version": "2.12.0",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": sid},
            "panelIndex": sid,
            "embeddableConfig": {"title": f"Discover: {title}"},
            "panelRefName": f"panel_{sid}",
        }
        new_panels.append(p)
        rn = f"panel_{sid}"
        if rn not in ref_names:
            refs.append({"name": rn, "type": "search", "id": sid})
            ref_names.add(rn)

    # Keep viz panels, append search panels
    viz_only = [p for p in panels if not p["panelIndex"].startswith("fp-search-")]
    combined = viz_only + new_panels
    dash["attributes"]["panelsJSON"] = json.dumps(combined)
    # enrich viz embeddableConfig for filter drill
    for p in viz_only:
        p["embeddableConfig"] = {
            **(p.get("embeddableConfig") or {}),
            "enhancements": {"dynamicActions": True},
        }

    ur = s.put(
        f"{OSD}/api/saved_objects/dashboard/fp-opensearch-security",
        headers=hdrs(),
        json={"attributes": dash["attributes"], "references": refs},
        timeout=30,
        verify=False,
    )
    if ur.status_code in (200, 201):
        ok("dashboard fp-opensearch-security + panels Discover drill-down")
        return 0
    ko(f"dashboard PUT {ur.status_code}")
    return 1


def fix_fp_timesketch_pattern(s: requests.Session) -> int:
    title = "forensic-timesketch*,forensic-tokens-*"
    r = s.get(f"{OSD}/api/saved_objects/index-pattern/fp-timesketch", headers=hdrs(), timeout=15, verify=False)
    if r.status_code != 200:
        return 1
    attrs = r.json()["attributes"]
    attrs["title"] = title
    attrs["timeFieldName"] = "@timestamp"
    ur = s.put(
        f"{OSD}/api/saved_objects/index-pattern/fp-timesketch",
        headers=hdrs(),
        json={"attributes": attrs},
        timeout=20,
        verify=False,
    )
    if ur.status_code in (200, 201):
        ok("index-pattern fp-timesketch")
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "opensearch_refresh_index_pattern.py"), "fp-timesketch"],
            check=False,
            timeout=120,
        )
        return 0
    return 1


def fix_fp_ti_map(s: requests.Session) -> int:
    """Remplace la map sample Flights par FP TI / events geo."""
    map_id = "88a24e6c-0216-4f76-8bc7-c8db6c8705da"
    layers = [
        {
            "name": "Base map",
            "type": "opensearch_vector_tile_map",
            "id": "fp-base-map",
            "zoomRange": [0, 22],
            "opacity": 100,
            "visibility": "visible",
            "source": {"dataURL": "https://tiles.maps.opensearch.org/data/v1.json"},
            "style": {"styleURL": "https://tiles.maps.opensearch.org/v3/manifest.json"},
        },
        {
            "name": "FP — Web geo (ti_match)",
            "description": "Events web avec geo + TI match",
            "type": "documents",
            "id": "fp-web-geo-layer",
            "zoomRange": [0, 22],
            "opacity": 70,
            "visibility": "visible",
            "source": {
                "indexPatternRefName": "fp-events",
                "indexPatternId": "fp-events",
                "geoFieldType": "geo_point",
                "geoFieldName": "source.geo.geo.location",
                "documentRequestNumber": 300,
                "tooltipFields": ["@timestamp", "message", "ti_ioc_value", "source.ip"],
                "showTooltips": True,
                "filters": [
                    {
                        "meta": {"index": "fp-events", "negate": False, "disabled": False},
                        "query": {"match_phrase": {"ti_match": True}},
                        "$state": {"store": "appState"},
                    }
                ],
                "useGeoBoundingBoxFilter": True,
            },
            "style": {"fillColor": "#54B399", "borderColor": "#54B399", "borderThickness": 1, "markerSize": 5},
        },
    ]
    attrs = {
        "title": "Incident Response — Evidence Map (geo)",
        "description": "Threat intelligence IOC + events web géolocalisés (ti_match). Clic tooltip → filtre carte.",
        "layerList": json.dumps(layers),
        "mapState": json.dumps(
            {
                "timeRange": {"from": "now-30d", "to": "now"},
                "query": {"query": "", "language": "kuery"},
                "refreshInterval": {"pause": True, "value": 60000},
            }
        ),
    }
    refs = [
        {"name": "fp-ti", "type": "index-pattern", "id": "fp-ti"},
        {"name": "fp-events", "type": "index-pattern", "id": "fp-events"},
    ]
    # PUT met à jour un objet existant (404 si absent sur instance vierge) ;
    # on bascule alors sur POST pour CRÉER la map avec cet identifiant.
    payload = {"attributes": attrs, "references": refs}
    ur = s.put(
        f"{OSD}/api/saved_objects/map/{map_id}",
        headers=hdrs(), json=payload, timeout=30, verify=False,
    )
    if ur.status_code in (200, 201):
        ok(f"map {map_id} → FP IOC Threat Map")
        return 0
    if ur.status_code == 404:
        cr = s.post(
            f"{OSD}/api/saved_objects/map/{map_id}?overwrite=true",
            headers=hdrs(), json=payload, timeout=30, verify=False,
        )
        if cr.status_code in (200, 201):
            ok(f"map {map_id} créé → FP IOC Threat Map")
            return 0
        ko(f"map POST {cr.status_code}: {cr.text[:200]}")
        return 1
    ko(f"map PUT {ur.status_code}: {ur.text[:200]}")
    return 1


def ensure_report_ae83(s: requests.Session) -> int:
    """Met à jour l'instance de rapport ae83 → dashboard fp-opensearch-security."""
    report_id = "ae83Sp4B3QNRsIdMwHE9"
    now = int(__import__("time").time() * 1000)
    day_ago = now - 86_400_000

    # L'instance peut ne pas exister sur une plateforme vierge : on la CRÉE
    # directement dans l'index .opendistro-reports-instances (le GET reporting
    # renvoie 404 tant que le doc n'existe pas). On récupère l'éventuel doc
    # existant pour préserver sa date de création, sinon valeurs par défaut.
    cur = {}
    gr = s.get(f"{OSD}/api/reporting/reports/{report_id}", headers=hdrs(), timeout=15, verify=False)
    if gr.status_code == 200:
        cur = gr.json()
    rd = cur.get("report_definition", {})
    def_id = (
        cur.get("report_definition_id")
        or rd.get("id")
        or "3545f290-5505-11f1-bd1e-1ff08948d43d"
    )

    instance_doc = {
        "lastUpdatedTimeMs": now,
        "createdTimeMs": cur.get("time_created", now),
        "beginTimeMs": day_ago,
        "endTimeMs": now,
        "tenant": "",
        "reportDefinitionDetails": {
            "id": def_id,
            "lastUpdatedTimeMs": now,
            "createdTimeMs": cur.get("time_created", now),
            "tenant": "",
            "reportDefinition": {
                "name": "FP_Security_Events_TI",
                "isEnabled": True,
                "source": {
                    "description": "Forensic Platform SIEM",
                    "type": "Dashboard",
                    "origin": OSD,
                    "id": "fp-opensearch-security",
                },
                "format": {"duration": "PT24H", "fileFormat": "Png"},
                "trigger": {"triggerType": "Download"},
                "delivery": {
                    "title": "FP Security",
                    "textDescription": "Forensic Platform",
                    "htmlDescription": "<p>FP Security Events TI</p>",
                    "configIds": [],
                },
            },
        },
        "status": "Success",
        "inContextDownloadUrlPath": "/app/dashboards#/view/fp-opensearch-security",
    }

    es_url = f"{OS}/.opendistro-reports-instances/_doc/{report_id}"
    ur = s.put(es_url, json=instance_doc, timeout=30)
    if ur.status_code not in (200, 201):
        ko(f"report instance ES PUT {ur.status_code}: {ur.text[:160]}")
        return 1
    s.post(f"{OS}/.opendistro-reports-instances/_refresh", timeout=15)

    # Vérification directe du doc ES (l'API reporting OSD ne reflète pas ce schéma).
    vr = s.get(es_url, timeout=15)
    if vr.status_code == 200:
        src = vr.json().get("_source", {})
        sid = (
            src.get("reportDefinitionDetails", {})
            .get("reportDefinition", {})
            .get("source", {})
            .get("id", "")
        )
        if sid == "fp-opensearch-security" or "fp-opensearch-security" in src.get("inContextDownloadUrlPath", ""):
            ok(f"report {report_id} → fp-opensearch-security")
            return 0

    ko(f"report {report_id} non relié au dashboard security après update")
    return 1


def fix_vis_builder_571745a0(s: requests.Session) -> int:
    """Crée visualisation FP si l'ID 571745a0 (vis-builder) manque."""
    vid = "571745a0-eb99-11ed-8e00-17d7d50cd7b2"
    sys.path.insert(0, str(ROOT / "scripts"))
    from osd_vis_lib import vis_pie  # noqa: E402

    obj = vis_pie(vid, "FP — TI by source (vis-builder slot)", "fp-ti", "*", "source")
    for method in ("POST", "PUT"):
        r = s.request(
            method,
            f"{OSD}/api/saved_objects/visualization/{vid}",
            headers=hdrs(),
            json={"attributes": obj["attributes"], "references": obj["references"]},
            timeout=30,
            verify=False,
        )
        if r.status_code in (200, 201):
            ok(f"vis-builder slot {vid}")
            return 0
    ko(f"vis-builder slot {vid} create failed")
    return 1


def main() -> int:
    global OSD
    s = requests.Session()
    s.verify = False
    base = wait_osd(s, [OSD, OSD_NGINX], timeout_total=300)
    if not base:
        ko("OpenSearch Dashboards inaccessible")
        return 1
    OSD = base
    ok(f"OSD prêt — {base}")

    fails = 0

    # Rebuild NDJSON + import base
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_opensearch_dashboards.py")], check=False)

    subprocess.run(["bash", str(ROOT / "scripts" / "opensearch_dashboards_import_fp.sh")], check=False, timeout=180)

    fails += fix_fp_timesketch_pattern(s)

    for vid, fixes in FP_VIZ_FIXES.items():
        fails += fix_fp_visualization(s, vid, fixes)

    for vid, spec in SAMPLE_VIZ_FP.items():
        fails += rebuild_sample_viz_as_fp(s, vid, spec)

    fails += fix_vis_builder_571745a0(s)
    fails += fix_security_dashboard_drilldown(s)
    fails += fix_fp_ti_map(s)

    subprocess.run([sys.executable, str(ROOT / "scripts" / "opensearch_observability_setup.py")], check=False, timeout=120)

    fails += ensure_report_ae83(s)

    subprocess.run([sys.executable, str(ROOT / "scripts" / "opensearch_refresh_index_pattern.py")], check=False, timeout=180)

    print(f"[analyst-fix] Bilan: {fails} étape(s) en échec")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
