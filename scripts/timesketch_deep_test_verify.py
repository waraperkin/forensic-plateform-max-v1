#!/usr/bin/env python3
"""Vérifications deep Timesketch : Sigma config, création règle, TI indicateur, explore."""
from __future__ import annotations

import json
import os
import re
import sys

import requests
import yaml

TS = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
USER = os.environ.get("TIMESKETCH_USER", "admin")
PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
SKETCH_ID = os.environ.get("TS_DEEP_SKETCH_ID", "").strip()

SIGMA_RULE_YAML = """title: FP Deep Test Rule 4625
id: fp-deep-test-4625-0001
status: stable
description: Deep test — event_type 4625
author: Forensic Platform
date: 2024/03/15
logsource:
  product: windows
  service: security
detection:
  selection:
    event_type: "4625"
  condition: selection
level: medium
tags:
  - attack.credential_access
"""


def login() -> tuple[requests.Session, dict[str, str]]:
    s = requests.Session()
    r = s.get(f"{TS}/login/", timeout=20)
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    if not m:
        print("[deep-verify] ERREUR CSRF", file=sys.stderr)
        sys.exit(1)
    s.post(
        f"{TS}/login/",
        data={"username": USER, "password": PASS},
        headers={"Referer": f"{TS}/login/"},
        timeout=25,
    )
    return s, {"X-CSRFToken": m.group(1), "Content-Type": "application/json", "Referer": TS}


def pick_sketch(s: requests.Session, h: dict[str, str]) -> int:
    if SKETCH_ID.isdigit():
        return int(SKETCH_ID)
    page = 1
    while True:
        r = s.get(f"{TS}/api/v1/sketches/", params={"page": page}, headers=h, timeout=20)
        r.raise_for_status()
        data = r.json()
        for sk in data.get("objects", []):
            name = (sk.get("name") or "").upper()
            if "TS-ADV-E2E" in name or "E2E" in name:
                return sk["id"]
        for sk in data.get("objects", []):
            tr = s.get(f"{TS}/api/v1/sketches/{sk['id']}/timelines/", headers=h, timeout=15)
            if tr.status_code == 200 and tr.json().get("objects"):
                return sk["id"]
        meta = data.get("meta") or {}
        if not meta.get("has_next"):
            break
        page = int(meta.get("next_page") or page + 1)
    print("[deep-verify] ERREUR: aucun sketch avec timeline", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    fails = 0
    s, h = login()
    print("[deep-verify] login OK")

    # Sigma rules list
    sr = s.get(f"{TS}/api/v1/sigmarules/", headers=h, timeout=30)
    if sr.status_code == 200:
        n = sr.json().get("meta", {}).get("rules_count", 0)
        print(f"[deep-verify] OK GET /api/v1/sigmarules/ — {n} règle(s)")
    else:
        print(f"[deep-verify] KO sigmarules list HTTP {sr.status_code}", file=sys.stderr)
        fails += 1

    # Sigma rule create (tests sigma_config.yaml)
    pr = s.post(
        f"{TS}/api/v1/sigmarules/",
        json={"rule_yaml": SIGMA_RULE_YAML},
        headers=h,
        timeout=60,
    )
    if pr.status_code in (200, 201):
        print("[deep-verify] OK POST /api/v1/sigmarules/ (parsing Sigma config)")
    elif pr.status_code == 403 and "already found" in (pr.text or "").lower():
        print("[deep-verify] OK POST /api/v1/sigmarules/ (règle déjà présente — idempotent)")
    else:
        print(
            f"[deep-verify] KO POST sigmarules HTTP {pr.status_code}: {pr.text[:300]}",
            file=sys.stderr,
        )
        fails += 1

    sid = pick_sketch(s, h)
    print(f"[deep-verify] sketch de test: {sid}")
    h_sk = {**h, "Referer": f"{TS}/sketch/{sid}/explore/"}

    # Threat Intelligence — save indicator (ontology dict)
    intel_value = {
        "data": [
            {
                "ioc": "malicious.example.com",
                "ioc_type": "domain",
                "tags": ["test", "fp-deep"],
                "externalURI": "https://forensic.local/ti/test",
            }
        ]
    }
    ar = s.get(f"{TS}/api/v1/sketches/{sid}/attribute/", headers=h_sk, timeout=20)
    existing = ar.json() if ar.status_code == 200 else {}
    values = [intel_value]
    if isinstance(existing, dict) and existing.get("intelligence"):
        # merge with existing decoded structure if present
        pass

    pa = s.post(
        f"{TS}/api/v1/sketches/{sid}/attribute/",
        json={
            "name": "intelligence",
            "values": values,
            "ontology": "intelligence",
            "action": "post",
        },
        headers=h_sk,
        timeout=30,
    )
    if pa.status_code in (200, 201):
        print("[deep-verify] OK POST intelligence attribute (save indicator)")
    else:
        print(
            f"[deep-verify] KO save indicator HTTP {pa.status_code}: {pa.text[:300]}",
            file=sys.stderr,
        )
        fails += 1

    # Verify attribute readable
    ar2 = s.get(f"{TS}/api/v1/sketches/{sid}/attribute/", headers=h_sk, timeout=20)
    if ar2.status_code == 200 and ar2.json().get("intelligence"):
        print("[deep-verify] OK GET attribute intelligence")
    else:
        print("[deep-verify] WARN attribute intelligence vide après POST", file=sys.stderr)

    # Explore + analyzer
    det = s.get(f"{TS}/api/v1/sketches/{sid}/", headers=h, timeout=20).json()["objects"][0]
    idx = (det["timelines"][0].get("searchindex") or {}).get("index_name", "")
    er = s.post(
        f"{TS}/api/v1/sketches/{sid}/explore/",
        json={"query_string": "*", "size": 5, "indices": [idx] if idx else []},
        headers=h_sk,
        timeout=60,
    )
    if er.status_code != 200:
        print(f"[deep-verify] KO explore HTTP {er.status_code}", file=sys.stderr)
        fails += 1
    else:
        print(f"[deep-verify] OK explore — events={len(er.json().get('objects', []))}")

    an = s.get(f"{TS}/api/v1/sketches/{sid}/analyzer/", headers=h_sk, timeout=30)
    if an.status_code == 200:
        print(f"[deep-verify] OK GET /analyzer/ — {len(an.json())} analyzer(s)")
    else:
        print(f"[deep-verify] KO analyzer HTTP {an.status_code}", file=sys.stderr)
        fails += 1

    ui = s.get(f"{TS}/sketch/{sid}/explore/", timeout=30)
    if "Server side error" in ui.text:
        print("[deep-verify] KO UI Server side error", file=sys.stderr)
        fails += 1
    else:
        print("[deep-verify] OK UI explore sans Server side error")

    intel_meta = s.get(f"{TS}/api/v1/intelligence/tagmetadata/", headers=h, timeout=20)
    if intel_meta.status_code == 200:
        print("[deep-verify] OK GET /intelligence/tagmetadata/")
    else:
        print(f"[deep-verify] KO tagmetadata HTTP {intel_meta.status_code}", file=sys.stderr)
        fails += 1

    print(f"[deep-verify] Bilan: {fails} KO")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
