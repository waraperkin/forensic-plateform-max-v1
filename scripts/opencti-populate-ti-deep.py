#!/usr/bin/env python3
"""
Alimentation TI OpenCTI : indicateurs + observables (createObservables).
Source principale : flux URLhaus CSV (récent + complément).
"""
from __future__ import annotations

import csv
import io
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

CTI_URL = os.environ.get("OPENCTI_GRAPHQL_URL", "https://localhost/cti/graphql")
TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "a1b2c3d4-e5f6-4789-a012-3456789abcde")
TARGET_IND = int(os.environ.get("OPENCTI_TI_DEEP_MIN_IND", "5000"))
TARGET_OBS = int(os.environ.get("OPENCTI_TI_DEEP_MIN_OBS", "5000"))
MAX_IMPORT = int(os.environ.get("OPENCTI_TI_DEEP_MAX", "6000"))
# Pour 100k+ : utiliser scripts/opencti-populate-ti-massive.py
WORKERS = int(os.environ.get("OPENCTI_TI_DEEP_WORKERS", "8"))
# P05 — deadline interne : le script s'arrête proprement AVANT le timeout de
# l'appelant (master setup), en conservant le progrès déjà importé.
DEADLINE_S = int(os.environ.get("FP_TI_DEEP_DEADLINE_S", "480"))
CHUNK = 200
URLHAUS_CSV = os.environ.get(
    "URLHAUS_CSV_URL", "https://urlhaus.abuse.ch/downloads/csv_recent/"
)

MUTATION = """
mutation($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) { id }
}
"""


def gql(session: requests.Session, query: str, variables: dict | None = None) -> dict:
    r = session.post(
        CTI_URL,
        json={"query": query, "variables": variables or {}},
        timeout=120,
        verify=False,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("errors"):
        raise RuntimeError(str(body["errors"][:2]))
    return body.get("data") or {}


def metrics(session: requests.Session) -> tuple[int, int, int]:
    d = gql(
        session,
        """{
          indicatorsNumber { total }
          stixCyberObservablesNumber { total }
          stixCoreObjectsNumber { total }
        }""",
    )
    return (
        int(d.get("indicatorsNumber", {}).get("total", 0)),
        int(d.get("stixCyberObservablesNumber", {}).get("total", 0)),
        int(d.get("stixCoreObjectsNumber", {}).get("total", 0)),
    )


def fetch_urls(limit: int, skip: int = 0) -> list[str]:
    req = urllib.request.Request(URLHAUS_CSV, headers={"User-Agent": "forensic-platform/2.1"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    urls: list[str] = []
    seen = 0
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3 or row[0].startswith("#"):
            continue
        url = row[2].strip()
        if not url.startswith("http"):
            continue
        if seen < skip:
            seen += 1
            continue
        urls.append(url)
        if len(urls) >= limit:
            break
    return urls


def create_indicator(session: requests.Session, url: str) -> bool:
    esc = url.replace("'", "\\'")
    pattern = f"[url:value = '{esc}']"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        data = gql(
            session,
            MUTATION,
            {
                "input": {
                    "name": f"URLhaus {url[:120]}",
                    "description": "Forensic Platform TI deep populate (URLhaus)",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "createObservables": True,
                    "x_opencti_main_observable_type": "Url",
                }
            },
        )
        return bool(data.get("indicatorAdd", {}).get("id"))
    except Exception:
        return False


def main() -> int:
    session = requests.Session()
    session.headers.update(
        {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    )
    session.verify = False

    ind, obs, stix = metrics(session)
    print(f"[opencti-deep] avant: indicateurs={ind} observables={obs} stix={stix}")
    if ind >= TARGET_IND and obs >= TARGET_OBS:
        print("[opencti-deep] Seuils déjà atteints")
        return 0

    need = max(TARGET_IND - ind, TARGET_OBS - obs, 1)
    batch = min(MAX_IMPORT, need + 500)
    skip = max(0, ind - 50)
    urls = fetch_urls(batch, skip=skip)
    if not urls:
        print("[opencti-deep] Aucune URL URLhaus", file=sys.stderr)
        return 1
    print(f"[opencti-deep] Import {len(urls)} URLs (workers={WORKERS}, skip={skip})...")

    created = 0
    start = time.monotonic()
    processed = 0
    stop = False
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for off in range(0, len(urls), CHUNK):
            if stop or time.monotonic() - start > DEADLINE_S:
                print(
                    f"[opencti-deep] deadline {DEADLINE_S}s atteinte — "
                    f"arrêt propre après {processed}/{len(urls)} (progrès conservé)"
                )
                break
            chunk = urls[off : off + CHUNK]
            futures = {pool.submit(create_indicator, session, u): u for u in chunk}
            for fut in as_completed(futures):
                if fut.result():
                    created += 1
            processed += len(chunk)
            ind, obs, _ = metrics(session)
            print(f"[opencti-deep]   progress {processed}/{len(urls)} ind={ind} obs={obs}")
            if ind >= TARGET_IND and obs >= TARGET_OBS:
                stop = True

    ind, obs, stix = metrics(session)
    print(f"[opencti-deep] créés≈{created} après: indicateurs={ind} observables={obs} stix={stix}")
    ok = ind >= TARGET_IND and obs >= TARGET_OBS
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
