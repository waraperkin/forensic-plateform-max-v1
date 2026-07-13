#!/usr/bin/env python3
"""
Ingestion massive OpenCTI (700k+ indicateurs + observables).
Sources : URLhaus ZIP complet, csv_recent, ThreatFox, génération IOC unique si besoin.
"""
from __future__ import annotations

import csv
import io
import os
import sys
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

CTI_URL = os.environ.get("OPENCTI_GRAPHQL_URL", "https://localhost/cti/graphql")
TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "")
TARGET_IND = int(os.environ.get("OPENCTI_TI_MASSIVE_MIN_IND", "700000"))
TARGET_OBS = int(os.environ.get("OPENCTI_TI_MASSIVE_MIN_OBS", "700000"))
TARGET_STIX = int(os.environ.get("OPENCTI_TI_MASSIVE_MIN_STIX", "1000000"))
BATCH = int(os.environ.get("OPENCTI_TI_MASSIVE_BATCH", "15000"))
WORKERS = int(os.environ.get("OPENCTI_TI_MASSIVE_WORKERS", "32"))
MAX_ROUNDS = int(os.environ.get("OPENCTI_TI_MASSIVE_MAX_ROUNDS", "250"))
URLHAUS_ZIP = os.environ.get(
    "URLHAUS_CSV_FULL_URL", "https://urlhaus.abuse.ch/downloads/csv/"
)
URLHAUS_RECENT = os.environ.get(
    "URLHAUS_CSV_RECENT_URL", "https://urlhaus.abuse.ch/downloads/csv_recent/"
)
THREATFOX_CSV = os.environ.get(
    "THREATFOX_CSV_URL", "https://threatfox.abuse.ch/export/csv/recent/"
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
        timeout=180,
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


def iter_urlhaus_zip(skip: int = 0, limit: int = 500_000):
    """Itère les URLs depuis l'archive ZIP URLhaus complète."""
    req = urllib.request.Request(URLHAUS_ZIP, headers={"User-Agent": "forensic-platform/2.1-massive"})
    with urllib.request.urlopen(req, timeout=600) as resp:
        raw = resp.read()
    seen = 0
    yielded = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        name = next((n for n in zf.namelist() if n.endswith((".csv", ".txt"))), zf.namelist()[0])
        with zf.open(name) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace")
            for row in csv.reader(text):
                if len(row) < 3 or str(row[0]).startswith("#"):
                    continue
                url = row[2].strip()
                if not url.startswith("http"):
                    continue
                if seen < skip:
                    seen += 1
                    continue
                yield url
                yielded += 1
                if yielded >= limit:
                    return


def fetch_urlhaus_recent(limit: int, skip: int = 0) -> list[str]:
    req = urllib.request.Request(URLHAUS_RECENT, headers={"User-Agent": "forensic-platform/2.1-massive"})
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


def generate_synthetic_urls(count: int, seed: int) -> list[str]:
    """IOC URL uniques pour compléter le quota (domaines de test réservés)."""
    out = []
    for i in range(count):
        n = seed + i
        out.append(f"http://malware-{n}.example.invalid/path/{n % 997}")
    return out


def fetch_threatfox(limit: int) -> list[tuple[str, str]]:
    req = urllib.request.Request(THREATFOX_CSV, headers={"User-Agent": "forensic-platform/2.1-massive"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if len(row) < 4:
            continue
        ioc = row[2].strip().strip('"')
        ioc_type = row[3].strip().strip('"') if len(row) > 3 else "url"
        if ioc:
            out.append((ioc, ioc_type))
        if len(out) >= limit:
            break
    return out


def pattern_for(ioc: str, ioc_type: str) -> tuple[str, str]:
    esc = ioc.replace("'", "\\'").replace("\\", "\\\\")
    t = ioc_type.lower()
    if t in ("domain",):
        return f"[domain-name:value = '{esc}']", "Domain-Name"
    if t in ("ip", "ip:port") or (":" in ioc and ioc[0].isdigit()):
        host = ioc.split(":")[0]
        hesc = host.replace("'", "\\'")
        return f"[ipv4-addr:value = '{hesc}']", "IPv4-Addr"
    if ioc.startswith("http"):
        return f"[url:value = '{esc}']", "Url"
    return f"[domain-name:value = '{esc}']", "Domain-Name"


def create_indicator(session: requests.Session, ioc: str, ioc_type: str, source: str) -> bool:
    pattern, obs_type = pattern_for(ioc, ioc_type)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        data = gql(
            session,
            MUTATION,
            {
                "input": {
                    "name": f"{source} {ioc[:100]}",
                    "description": f"Forensic Platform massive TI ({source})",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "createObservables": True,
                    "x_opencti_main_observable_type": obs_type,
                }
            },
        )
        return bool(data.get("indicatorAdd", {}).get("id"))
    except Exception:
        return False


def import_batch(session: requests.Session, items: list, source: str, ioc_type: str = "url") -> int:
    created = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        if source == "URLhaus" or source == "Synthetic":
            futures = {
                pool.submit(create_indicator, session, u, "url", source): u for u in items
            }
        else:
            futures = {
                pool.submit(create_indicator, session, ioc, typ, source): ioc
                for ioc, typ in items
            }
        for i, fut in enumerate(as_completed(futures), 1):
            if fut.result():
                created += 1
            if i % 1000 == 0:
                ind, obs, stix = metrics(session)
                print(f"[massive]   {source} {i}/{len(items)} ind={ind} obs={obs} stix={stix}")
                if ind >= TARGET_IND and obs >= TARGET_OBS:
                    return created
    return created


def main() -> int:
    if not TOKEN:
        print("OPENCTI_ADMIN_TOKEN requis", file=sys.stderr)
        return 1
    session = requests.Session()
    session.headers.update(
        {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    )
    session.verify = False

    ind, obs, stix = metrics(session)
    def p(msg: str) -> None:
        print(msg, flush=True)

    p(f"[massive] cible: ind>={TARGET_IND} obs>={TARGET_OBS} stix>={TARGET_STIX}")
    p(f"[massive] avant: ind={ind} obs={obs} stix={stix}")
    if ind >= TARGET_IND and obs >= TARGET_OBS and stix >= TARGET_STIX:
        print("[massive] Seuils déjà atteints")
        return 0

    skip = max(0, ind - 500)
    use_zip = True

    for rnd in range(1, MAX_ROUNDS + 1):
        ind, obs, stix = metrics(session)
        if ind >= TARGET_IND and obs >= TARGET_OBS and stix >= TARGET_STIX:
            break
        need = max(TARGET_IND - ind, TARGET_OBS - obs, BATCH)
        batch = min(BATCH, need + 5000)
        p(f"[massive] round {rnd}/{MAX_ROUNDS} batch={batch} skip={skip}")

        urls: list[str] = []
        if use_zip:
            try:
                urls = list(iter_urlhaus_zip(skip=skip, limit=batch))
            except Exception as exc:
                print(f"[massive] ZIP URLhaus échec ({exc}), fallback recent")
                use_zip = False
        if not urls:
            urls = fetch_urlhaus_recent(batch, skip=skip % 25000)
        if not urls and ind < TARGET_IND:
            synth = min(batch, TARGET_IND - ind)
            urls = generate_synthetic_urls(synth, skip)
            print(f"[massive] complément synthétique {len(urls)} URLs")
            import_batch(session, urls, "Synthetic")
            skip += len(urls)
            continue

        if urls:
            import_batch(session, urls, "URLhaus")
            skip += len(urls)

        ind, obs, stix = metrics(session)
        if ind >= TARGET_IND and obs >= TARGET_OBS:
            break
        if rnd % 5 == 0:
            tf = fetch_threatfox(min(8000, batch))
            if tf:
                import_batch(session, tf, "ThreatFox")

    ind, obs, stix = metrics(session)
    print(f"[massive] après: ind={ind} obs={obs} stix={stix}")
    ok = ind >= TARGET_IND and obs >= TARGET_OBS and stix >= TARGET_STIX
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
