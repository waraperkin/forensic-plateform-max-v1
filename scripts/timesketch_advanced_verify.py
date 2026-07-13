#!/usr/bin/env python3
"""Vérifications HTTP post-activation Timesketch avancé (POINT 2)."""
from __future__ import annotations

import os
import re
import sys

import requests

TS = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
USER = os.environ.get("TIMESKETCH_USER", "admin")
PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
SKETCH_ID = os.environ.get("TS_ACTIVATE_SKETCH_ID", "").strip()

# Analyzers attendus (whitelist POINT 1)
EXPECTED_ANALYZERS = {"sigma", "feature_extraction", "domain", "misp_analyzer"}


def login() -> tuple[requests.Session, dict[str, str]]:
    s = requests.Session()
    r = s.get(f"{TS}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        print(f"[verify] ERREUR: CSRF introuvable sur {TS}/login/", file=sys.stderr)
        sys.exit(1)
    s.post(
        f"{TS}/login/",
        data={"username": USER, "password": PASS},
        headers={"Referer": f"{TS}/login/"},
        timeout=25,
    )
    return s, {
        "X-CSRFToken": m.group(1),
        "Content-Type": "application/json",
        "Referer": TS,
    }


def pick_sketch_id(s: requests.Session, headers: dict[str, str]) -> int:
    if SKETCH_ID.isdigit():
        return int(SKETCH_ID)
    page = 1
    sketches: list[dict] = []
    while True:
        r = s.get(f"{TS}/api/v1/sketches/", params={"page": page}, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        sketches.extend(data.get("objects", []))
        meta = data.get("meta") or {}
        if not meta.get("has_next"):
            break
        page = int(meta.get("next_page") or page + 1)
    if not sketches:
        print("[verify] ERREUR: aucun sketch", file=sys.stderr)
        sys.exit(1)
    # Préférer un sketch avec au moins une timeline
    for sk in sketches:
        sid = sk["id"]
        detail = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=headers, timeout=20).json()
        if detail.get("objects", [{}])[0].get("timelines"):
            return sid
    return sketches[0]["id"]


def main() -> int:
    print(f"[verify] Timesketch {TS} (user={USER})")
    s, h = login()
    print("[verify] login OK")

    page = 1
    count = 0
    while True:
        r = s.get(f"{TS}/api/v1/sketches/", params={"page": page}, headers=h, timeout=20)
        if r.status_code != 200:
            print(f"[verify] ERREUR sketches HTTP {r.status_code}", file=sys.stderr)
            return 1
        count += len(r.json().get("objects", []))
        meta = r.json().get("meta") or {}
        if not meta.get("has_next"):
            break
        page = int(meta.get("next_page") or page + 1)
    print(f"[verify] GET /api/v1/sketches/ OK ({count} sketch(s))")

    sid = pick_sketch_id(s, h)
    print(f"[verify] sketch de test: id={sid}")

    h_sk = {**h, "Referer": f"{TS}/sketch/{sid}/explore/"}
    ar = s.get(f"{TS}/api/v1/sketches/{sid}/analyzer/", headers=h_sk, timeout=30)
    if ar.status_code != 200:
        print(f"[verify] ERREUR analyzer HTTP {ar.status_code}: {ar.text[:120]}", file=sys.stderr)
        return 1
    names = {x.get("name", "") for x in ar.json()}
    print(f"[verify] analyzer OK — {len(names)} analyzer(s): {sorted(names)}")
    if names != EXPECTED_ANALYZERS:
        extra = names - EXPECTED_ANALYZERS
        missing = EXPECTED_ANALYZERS - names
        if extra:
            print(f"[verify] ERREUR analyzers hors whitelist: {extra}", file=sys.stderr)
        if missing:
            print(f"[verify] ERREUR analyzers manquants: {missing}", file=sys.stderr)
        return 1
    print("[verify] whitelist analyzers conforme (POINT 1)")

    er = s.post(
        f"{TS}/api/v1/sketches/{sid}/explore/",
        json={"query_string": "*", "filter": {}},
        headers=h_sk,
        timeout=60,
    )
    if er.status_code != 200:
        print(f"[verify] ERREUR explore HTTP {er.status_code}: {er.text[:120]}", file=sys.stderr)
        return 1
    total = er.json().get("meta", {}).get("es_total_count", 0)
    print(f"[verify] explore OK — es_total_count={total}")

    ui = s.get(f"{TS}/sketch/{sid}/explore/", timeout=30)
    if "Server side error" in ui.text:
        print("[verify] ERREUR UI contient 'Server side error'", file=sys.stderr)
        return 1
    print("[verify] UI explore sans 'Server side error'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
