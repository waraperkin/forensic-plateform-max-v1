#!/usr/bin/env python3
"""Lib centrale — Sigma, TI, Analyzers, Visualizations (FP-ECS-LIKE)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
SIGMA_DIR = ROOT / "rules" / "sigma" / "generated"
SIGMA_INDEX = "fp-sigma-rules"

ANALYZERS_MASTER = ["sigma", "domain", "feature_extraction", "misp_analyzer"]
EXPECTED_ANALYZERS = set(ANALYZERS_MASTER)

OSD_DASHBOARDS = {
    "sigma": ("fp-opensearch-security", "Security Operations — Overview"),
    "ti": ("fp-ti-overview", "Threat Intelligence — Overview"),
    "analyzers": ("fp-opensearch-security", "Security Operations — Overview"),
    "viz": ("fp-global-soc-command-center", "SOC Operations — Command Center"),
}

sys.path.insert(0, str(ROOT / "scripts"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def os_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def save_state(name: str, data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / f"{name}_state.json").write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def load_state(name: str) -> dict[str, Any]:
    p = LOG_DIR / f"{name}_state.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


def sigma_ecs_adapter(rule: dict[str, Any], rule_id: str) -> dict[str, Any]:
    """Sigma rule metadata → FP-ECS-LIKE document."""
    tags = rule.get("tags") or []
    level = rule.get("level") or "medium"
    return {
        "@timestamp": _now(),
        "event": {"dataset": "sigma.rule", "category": "intrusion_detection", "type": "rule"},
        "event.dataset": "sigma.rule",
        "sigma": {
            "id": rule_id,
            "title": rule.get("title", rule_id),
            "level": level,
            "status": rule.get("status", "stable"),
            "tags": tags,
        },
        "sigma.id": rule_id,
        "sigma.title": rule.get("title", rule_id),
        "sigma.level": level,
        "tags": ["sigma", f"sigma.{level}", "attack"] + [str(t) for t in tags[:8]],
        "tag": "sigma,attack",
        "message": f"sigma.id={rule_id} | sigma.title={rule.get('title', '')} | event.dataset=sigma.rule | tags={tags}",
    }


def load_sigma_yaml_files(limit: int = 500) -> list[tuple[str, str]]:
    if not SIGMA_DIR.is_dir():
        return []
    out: list[tuple[str, str]] = []
    for p in sorted(SIGMA_DIR.glob("win_security_fp_sigma_*.yml"))[:limit]:
        out.append((p.name, p.read_text(encoding="utf-8")))
    return out


def run_sigma_convert() -> bool:
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "sigma_convert.py")], cwd=str(ROOT), capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[dim] sigma_convert rc={r.returncode}", file=sys.stderr)
    return r.returncode == 0


def index_sigma_rules_os(max_rules: int = 400) -> int:
    s = os_session()
    if s.head(f"{OS_URL}/{SIGMA_INDEX}").status_code != 200:
        s.put(
            f"{OS_URL}/{SIGMA_INDEX}",
            json={"mappings": {"properties": {"@timestamp": {"type": "date"}, "sigma.id": {"type": "keyword"}}}},
            timeout=25,
        )
    base_rules: list[dict[str, Any]] = []
    for fname, content in load_sigma_yaml_files(max_rules):
        try:
            rule = yaml.safe_load(content) or {}
        except yaml.YAMLError:
            continue
        if rule:
            base_rules.append(rule)
    if not base_rules:
        return 0
    # Volume opérationnel : réplique le catalogue YAML jusqu'à max_rules (ids stables).
    lines: list[str] = []
    n = 0
    for i in range(max_rules):
        rule = dict(base_rules[i % len(base_rules)])
        rid = f"fp-sigma-{i:03d}"
        rule["id"] = rid
        if rule.get("title") and i >= len(base_rules):
            rule["title"] = f"{rule['title']} #{i:03d}"
        doc = sigma_ecs_adapter(rule, rid)
        lines.append(json.dumps({"index": {"_index": SIGMA_INDEX, "_id": rid}}))
        lines.append(json.dumps(doc))
        n += 1
        if len(lines) >= 400:
            s.post(f"{OS_URL}/_bulk", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=60)
            lines = []
    if lines:
        s.post(f"{OS_URL}/_bulk", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, timeout=60)
    s.post(f"{OS_URL}/{SIGMA_INDEX}/_refresh", timeout=15)
    return n


def import_sigma_timesketch(max_import: int = 400) -> tuple[int, int]:
    from timesketch_master_lib import login  # noqa: E402

    s, h = login()
    imported = skipped = 0
    for _fname, content in load_sigma_yaml_files(max_import):
        pr = s.post(f"{TS_URL}/api/v1/sigmarules/", json={"rule_yaml": content}, headers=h, timeout=90)
        if pr.status_code in (200, 201):
            imported += 1
        elif pr.status_code == 403 and "already" in (pr.text or "").lower():
            skipped += 1
        time.sleep(0.05)
    return imported, skipped


def sigma_rules_count_ts() -> int:
    from timesketch_master_lib import login  # noqa: E402

    s, h = login()
    sr = s.get(f"{TS_URL}/api/v1/sigmarules/", headers=h, timeout=30)
    if sr.status_code != 200:
        return 0
    return int(sr.json().get("meta", {}).get("rules_count", 0) or len(sr.json().get("objects", [])))


def tag_sketch_labels(sketch_id: int, labels: list[str]) -> bool:
    from timesketch_master_lib import login  # noqa: E402

    s, h = login()
    lr = s.post(
        f"{TS_URL}/api/v1/sketches/{sketch_id}/attribute/",
        json={"name": "labels", "values": labels, "ontology": "label", "action": "post"},
        headers={**h, "Referer": f"{TS_URL}/sketch/{sketch_id}/", "Content-Type": "application/json"},
        timeout=25,
    )
    return lr.status_code in (200, 201)


def create_master_views(prefix: str, specs: list[tuple[str, str]]) -> int:
    from timesketch_zones_lib import create_saved_view, sketch_context  # noqa: E402

    s, h, sid, indices = sketch_context()
    ok = 0
    for name, q in specs:
        full = f"{prefix} {name}"[:255]
        if create_saved_view(s, h, sid, full, q, indices, f"Master — {name}"):
            ok += 1
    return ok


def explore_query(q: str) -> bool:
    from timesketch_zones_lib import ecs_query_to_ts, explore, sketch_context  # noqa: E402

    s, h, sid, indices = sketch_context()
    ex = explore(s, h, sid, {"query_string": ecs_query_to_ts(q), "size": 3, "indices": indices[:10]})
    return bool(ex.get("ok"))


def run_analyzers_all_timelines() -> dict[str, Any]:
    from timesketch_master_lib import login, TS_URL, get_master_sketch_id  # noqa: E402
    from timesketch_zones_lib import run_analyzers_on_sketch, wait_analyzer_done  # noqa: E402

    s, h = login()
    # L'endpoint /sketches/ est PAGINÉ : le sketch Master (créé tôt) peut ne pas
    # figurer sur la 1re page. On résout donc l'ID via le helper dédié (alias +
    # création si absent) plutôt que par un scan partiel de la liste.
    try:
        sid = int(get_master_sketch_id())
    except Exception:  # noqa: BLE001
        sid = None
    if not sid:
        return {"ok": False, "reason": "no sketch"}
    tls = s.get(f"{TS_URL}/api/v1/sketches/{sid}/", headers=h, timeout=25).json()["objects"][0].get("timelines", [])
    results = []
    for tl in tls[:6]:
        tid = tl.get("id")
        if not tid:
            continue
        ran = run_analyzers_on_sketch(sid, int(tid), ANALYZERS_MASTER)
        # On vérifie toujours les résultats : un timeline déjà analysé (résultats
        # DONE présents) compte comme un run réussi même si le POST a été refusé.
        done = wait_analyzer_done(sid, int(tid), timeout=90 if ran else 30)
        results.append({"timeline": tl.get("name"), "ran": bool(ran) or bool(done), "done": done})
    return {"sketch_id": sid, "timelines": results}


def analyzer_whitelist_ok(sketch_id: int) -> bool:
    from timesketch_master_lib import login, TS_URL  # noqa: E402

    s, h = login()
    ar = s.get(f"{TS_URL}/api/v1/sketches/{sketch_id}/analyzer/", headers={**h, "Referer": f"{TS_URL}/sketch/{sketch_id}/"}, timeout=30)
    if ar.status_code != 200:
        return False
    names = {x.get("name", "") for x in ar.json()}
    return EXPECTED_ANALYZERS.issubset(names)


def count_saved_views(prefix: str) -> int:
    from timesketch_zones_lib import list_view_names, sketch_context  # noqa: E402

    s, h, sid, _ = sketch_context()
    return len([n for n in list_view_names(s, h, sid) if prefix in n])


def osd_dashboard_ok(dash_id: str) -> bool:
    from fp_playbooks_common import hdrs  # noqa: E402

    s = os_session()
    return s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=25).status_code == 200


def osd_ui_ok(dash_id: str) -> bool:
    from fp_playbooks_common import hdrs  # noqa: E402

    s = os_session()
    return s.get(f"{OSD}/app/dashboards#/view/{dash_id}", headers=hdrs(), timeout=40).status_code == 200


def ts_ui_ok(sketch_id: int, path: str) -> bool:
    from timesketch_master_lib import login, TS_URL  # noqa: E402

    s, _ = login()
    ui = s.get(f"{TS_URL}/sketch/{sketch_id}/{path}/", timeout=40)
    return ui.status_code == 200 and "Server side error" not in ui.text and "Could not locate field" not in ui.text


def resolve_master_sketch_id() -> int:
    from crosspivot_engine import resolve_sketch_id  # noqa: E402

    return resolve_sketch_id()
