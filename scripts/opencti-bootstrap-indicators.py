#!/usr/bin/env python3
"""Alimente OpenCTI avec des indicateurs réels (URLhaus) si indicatorsNumber == 0."""
from __future__ import annotations

import csv
import io
import os
import sys
import urllib.request
from datetime import datetime, timezone

import requests

CTI_URL = os.environ.get("OPENCTI_GRAPHQL_URL", "https://localhost/cti/graphql")
TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "a1b2c3d4-e5f6-4789-a012-3456789abcde")
MAX_ITEMS = int(os.environ.get("OPENCTI_BOOTSTRAP_MAX", "120"))
MIN_TOTAL = int(os.environ.get("OPENCTI_BOOTSTRAP_MIN", "100"))
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"


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
        raise RuntimeError(body["errors"])
    return body.get("data") or {}


def indicators_total(session: requests.Session) -> int:
    d = gql(session, "{ indicatorsNumber { total } }")
    return int(d.get("indicatorsNumber", {}).get("total", 0))


def create_indicator(session: requests.Session, url: str, name: str) -> bool:
    pattern = f"[url:value = '{url.replace(chr(39), chr(92)+chr(39))}']"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    mutation = """
    mutation($input: IndicatorAddInput!) {
      indicatorAdd(input: $input) { id }
    }
    """
    try:
        data = gql(
            session,
            mutation,
            {
                "input": {
                    "name": name[:250],
                    "description": "Bootstrap URLhaus (scripts/opencti-bootstrap-indicators.py)",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "createObservables": True,
                    "x_opencti_main_observable_type": "Url",
                }
            },
        )
        return bool(data.get("indicatorAdd", {}).get("id"))
    except Exception as exc:
        print(f"  skip {url[:60]}: {exc}", file=sys.stderr)
        return False


def fetch_urlhaus_urls(limit: int, skip: int = 0) -> list[tuple[str, str]]:
    req = urllib.request.Request(URLHAUS_CSV, headers={"User-Agent": "forensic-platform/2.1"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    rows = list(csv.reader(io.StringIO(text)))
    out: list[tuple[str, str]] = []
    seen = 0
    for row in rows:
        if len(row) < 3 or row[0].startswith("#"):
            continue
        url = row[2].strip()
        if not url.startswith("http"):
            continue
        if seen < skip:
            seen += 1
            continue
        out.append((url, f"URLhaus {url[:80]}"))
        if len(out) >= limit:
            break
    return out


def main() -> int:
    session = requests.Session()
    session.headers.update(
        {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    )
    session.verify = False

    total = indicators_total(session)
    if total >= MIN_TOTAL:
        print(f"[opencti-bootstrap] Déjà {total} indicateur(s) (seuil {MIN_TOTAL}) — rien à faire.")
        return 0

    need = max(1, MIN_TOTAL - total)
    batch = min(MAX_ITEMS, need + 20)
    print(f"[opencti-bootstrap] {total} indicateur(s) < {MIN_TOTAL} — import URLhaus (max {batch})...")
    items = fetch_urlhaus_urls(batch, skip=total)
    if not items:
        print("[opencti-bootstrap] Aucune URL récupérée.", file=sys.stderr)
        return 1

    created = 0
    for url, name in items:
        if create_indicator(session, url, name):
            created += 1

    total = indicators_total(session)
    print(f"[opencti-bootstrap] Créés: {created}, total indicateurs: {total}")
    return 0 if total >= MIN_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
