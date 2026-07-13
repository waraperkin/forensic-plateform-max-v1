#!/usr/bin/env python3
"""Vérifications API post-E2E Timesketch avancé (POINT 3)."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
TS = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
USER = os.environ.get("TIMESKETCH_USER", "admin")
PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
CASE = os.environ.get("TS_VERIFY_CASE_ID", os.environ.get("TS_ADV_E2E_CASE_ID", ""))
SKETCH_ID = os.environ.get("TS_VERIFY_SKETCH_ID", "").strip()
TI_FILE = ROOT / "ti" / "indicators.json"
EXPECTED_ANALYZERS = {"sigma", "feature_extraction", "domain", "misp_analyzer"}
TI_TAGS = {"APT", "C2", "test", "botnet"}
SIGMA_TAG_HINTS = ("attack.", "ts_sigma_rule", "credential_access", "t1110")


def login() -> tuple[requests.Session, dict[str, str]]:
    s = requests.Session()
    r = s.get(f"{TS}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        print("[e2e-verify] ERREUR: CSRF", file=sys.stderr)
        sys.exit(1)
    s.post(
        f"{TS}/login/",
        data={"username": USER, "password": PASS},
        headers={"Referer": f"{TS}/login/"},
        timeout=25,
    )
    return s, {"X-CSRFToken": m.group(1), "Content-Type": "application/json", "Referer": TS}


def find_sketch(s: requests.Session, h: dict[str, str]) -> tuple[int, dict]:
    if SKETCH_ID.isdigit():
        sid = int(SKETCH_ID)
        det = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()
        return sid, det.get("objects", [{}])[0]

    name = f"[FP] {CASE}"
    page = 1
    while True:
        r = s.get(f"{TS}/api/v1/sketches/", params={"page": page}, headers=h, timeout=20)
        r.raise_for_status()
        data = r.json()
        for sk in data.get("objects", []):
            if sk.get("name") == name:
                sid = sk["id"]
                det = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()
                return sid, det.get("objects", [{}])[0]
        meta = data.get("meta") or {}
        if not meta.get("has_next"):
            break
        page = int(meta.get("next_page") or page + 1)
    print(f"[e2e-verify] ERREUR: sketch {name} introuvable", file=sys.stderr)
    sys.exit(1)


def explore(s: requests.Session, h: dict[str, str], sid: int, body: dict) -> dict:
    h_sk = {**h, "Referer": f"{TS}/sketch/{sid}/explore/"}
    r = s.post(f"{TS}/api/v1/sketches/{sid}/explore/", json=body, headers=h_sk, timeout=60)
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "text": r.text[:200]}
    data = r.json()
    events = data.get("objects", [])
    return {"ok": True, "events": events, "meta": data.get("meta", {})}


def flatten_analyses(objects: list) -> list[dict]:
    out: list[dict] = []
    for item in objects:
        if isinstance(item, list):
            out.extend(x for x in item if isinstance(x, dict))
        elif isinstance(item, dict):
            out.append(item)
    return out


def event_sources(events: list) -> list[dict]:
    out = []
    for ev in events:
        if isinstance(ev, dict):
            src = ev.get("_source") or ev
            if isinstance(src, dict):
                out.append(src)
    return out


def main() -> int:
    checks_passed = 0
    checks_failed = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal checks_passed, checks_failed
        if ok:
            checks_passed += 1
            print(f"[e2e-verify] OK  {label}" + (f" — {detail}" if detail else ""))
        else:
            checks_failed += 1
            print(f"[e2e-verify] KO  {label}" + (f" — {detail}" if detail else ""), file=sys.stderr)

    print(f"[e2e-verify] Timesketch {TS} case={CASE or 'n/a'}")
    s, h = login()
    sid, detail = find_sketch(s, h)
    os.environ["TS_VERIFY_SKETCH_ID"] = str(sid)
    print(f"[e2e-verify] sketch id={sid} name={detail.get('name')}")

    timelines = detail.get("timelines", [])
    check("timeline présente", bool(timelines))
    if not timelines:
        return 1
    tid = timelines[0]["id"]
    idx = (timelines[0].get("searchindex") or {}).get("index_name", "")
    check("index OpenSearch", bool(idx), idx)

    h_sk = {**h, "Referer": f"{TS}/sketch/{sid}/explore/"}
    ar = s.get(f"{TS}/api/v1/sketches/{sid}/analyzer/", headers=h_sk, timeout=30)
    check("GET /analyzer/ HTTP 200", ar.status_code == 200, str(ar.status_code))
    if ar.status_code == 200:
        names = {x.get("name", "") for x in ar.json()}
        check("whitelist analyzers", names == EXPECTED_ANALYZERS, str(sorted(names)))

    ex_all = explore(s, h, sid, {"query_string": "*", "size": 50, "indices": [idx] if idx else []})
    check("POST /explore/ HTTP 200", ex_all.get("ok"), str(ex_all.get("status", "")))
    sources = event_sources(ex_all.get("events", []))
    check("événements ingestés", len(sources) >= 1, f"{len(sources)} event(s)")

    has_4625 = any(str(src.get("event_type", "")) == "4625" for src in sources)
    if not has_4625 and idx:
        ex_4625 = explore(
            s,
            h,
            sid,
            {"query_string": "event_type:4625", "size": 5, "indices": [idx]},
        )
        has_4625 = ex_4625.get("ok") and bool(event_sources(ex_4625.get("events", [])))
    check("champ event_type 4625 (Sigma)", has_4625)

    ioc_domain = "malicious.example.com"
    ioc_ip = "10.10.10.10"
    has_ioc = any(
        ioc_domain in str(src.get("message", "")) or ioc_ip in str(src.get("message", ""))
        for src in sources
    )
    check("IOC TI dans les événements (message)", has_ioc)

    sigma_hit = False
    for src in sources:
        tags = src.get("tag") or src.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        blob = json.dumps(src, default=str).lower()
        if src.get("ts_sigma_rule") or any(t.startswith("attack.") for t in tags):
            sigma_hit = True
            break
        if any(h in blob for h in SIGMA_TAG_HINTS):
            sigma_hit = True
            break
    if not sigma_hit:
        ex_sigma = explore(
            s,
            h,
            sid,
            {
                "query_string": "attack.credential_access OR ts_sigma_rule:* OR tag:attack.t1110",
                "size": 20,
                "indices": [idx],
            },
        )
        if ex_sigma.get("ok") and event_sources(ex_sigma.get("events", [])):
            sigma_hit = True
    check("tags / attributs Sigma", sigma_hit)

    ti_tag_hit = False
    for src in sources:
        tags = src.get("tag") or src.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        if TI_TAGS.intersection(set(tags)):
            ti_tag_hit = True
            break
    ti_file_ok = TI_FILE.is_file()
    check("fichier ti/indicators.json (hôte)", ti_file_ok, str(TI_FILE))
    try:
        out = subprocess.run(
            [
                "docker",
                "exec",
                "forensic-timesketch-web",
                "test",
                "-f",
                "/opt/timesketch/ti/indicators.json",
            ],
            capture_output=True,
            timeout=15,
        )
        check("volume TI monté (conteneur)", out.returncode == 0)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        check("volume TI monté (conteneur)", False, "docker indisponible")
    check(
        "tags TI (MISP / intelligence) ou IOC en données",
        ti_tag_hit or has_ioc,
        "tags MISP=" + ("oui" if ti_tag_hit else "non") + ", IOC message=" + ("oui" if has_ioc else "non"),
    )

    domain_hit = any(
        src.get("domain")
        or "domain_" in json.dumps(src, default=str)
        or any("domain" in str(t).lower() for t in (src.get("tag") or []))
        for src in sources
    )
    if not domain_hit:
        ex_dom = explore(
            s,
            h,
            sid,
            {"query_string": f"message:*{ioc_domain}*", "size": 10, "indices": [idx]},
        )
        domain_hit = ex_dom.get("ok") and bool(event_sources(ex_dom.get("events", [])))
    check("enrichissement domaine / IOC domaine", domain_hit)

    feature_hit = any(
        k.startswith("__ts_") or "extracted" in k.lower()
        for src in sources
        for k in src.keys()
    )
    if feature_hit:
        check("champs feature extraction (__ts_* / extracted)", True)
    else:
        print(
            "[e2e-verify] WARN feature extraction: aucun champ __ts_* "
            "(plugins feature optionnels non configurés)"
        )

    ta = s.get(f"{TS}/api/v1/sketches/{sid}/timelines/{tid}/analysis/", headers=h, timeout=30)
    check("GET timeline /analysis/ HTTP 200", ta.status_code == 200)
    analyses = flatten_analyses(ta.json().get("objects", [])) if ta.status_code == 200 else []
    done_names: list[str] = []
    for item in analyses:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("analyzer_name", "")
        st_list = item.get("status") or []
        st = st_list[-1].get("status", "") if st_list else ""
        if st in ("DONE", "WARNING") and name:
            done_names.append(name)
    expected_run = {"sigma", "domain", "feature_extraction", "misp_analyzer"}
    check(
        "résultats analyzers en base (≥1 DONE)",
        len(done_names) >= 1,
        str(sorted(set(done_names))),
    )
    check(
        "analyzers clés exécutés",
        expected_run.intersection(set(done_names)) >= {"sigma", "misp_analyzer"},
        f"attendu subset de {sorted(expected_run)}",
    )

    agg = s.post(
        f"{TS}/api/v1/sketches/{sid}/explore/",
        json={"query_string": "*", "size": 0, "indices": [idx]},
        headers=h_sk,
        timeout=30,
    )
    check("aggregation explore (size=0) HTTP 200", agg.status_code == 200)

    intel = s.get(f"{TS}/api/v1/intelligence/tagmetadata/", headers=h, timeout=20)
    check("GET /intelligence/tagmetadata/ HTTP 200", intel.status_code == 200)

    ui = s.get(f"{TS}/sketch/{sid}/explore/", timeout=30)
    check("UI sans 'Server side error'", "Server side error" not in ui.text)

    print(f"[e2e-verify] Bilan: {checks_passed} OK, {checks_failed} KO")
    print(f"[e2e-verify] URL: {TS}/sketch/{sid}/explore/")
    return 0 if checks_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
