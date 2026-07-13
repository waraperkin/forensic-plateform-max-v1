#!/usr/bin/env python3
"""
Synchronise les CONNECTOR_*_ID du .env avec les UUID enregistrés dans OpenCTI.
Usage: python3 scripts/opencti-sync-connector-ids.py [--write]
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"

# Nom OpenCTI (partiel) → variable .env
NAME_TO_ENV: dict[str, str] = {
    "MITRE ATT&CK": "CONNECTOR_MITRE_ID",
    "MITRE ATLAS": "CONNECTOR_MITRE_ATLAS_ID",
    "DISARM": "CONNECTOR_DISARM_ID",
    "OpenCTI Datasets": "CONNECTOR_OPENCTI_DATASETS_ID",
    "Common Vulnerabilities": "CONNECTOR_CVE_ID",
    "AlienVault": "CONNECTOR_ALIENVAULT_ID",
    "AbuseIPDB": "CONNECTOR_ABUSEIPDB_ID",
    "Shodan": "CONNECTOR_SHODAN_ID",
    "IPInfo": "CONNECTOR_IPINFO_ID",
    "URLhaus": "CONNECTOR_URLHAUS_ID",
    "VXVault": "CONNECTOR_VXVAULT_ID",
    "MalwareBazaar": "CONNECTOR_MALWAREBAZAAR_ID",
    "ThreatFox": "CONNECTOR_THREATFOX_ID",
    "SSL Blacklist": "CONNECTOR_ABUSE_SSL_ID",
    "Abuse.ch SSL": "CONNECTOR_ABUSE_SSL_ID",
    "CISA Known": "CONNECTOR_CISA_KEV_ID",
    "Cyber Campaign": "CONNECTOR_APT_CAMPAIGN_ID",
    "DNS Twist": "CONNECTOR_DNS_TWIST_ID",
    "ExportReportPdf": "CONNECTOR_EXPORT_REPORT_PDF_ID",
    "ExportFileStix": "CONNECTOR_EXPORT_FILE_STIX_ID",
    "ExportFileCsv": "CONNECTOR_EXPORT_FILE_CSV_ID",
    "ExportFileTxt": "CONNECTOR_EXPORT_FILE_TXT_ID",
    "ImportFileStix": "CONNECTOR_IMPORT_FILE_STIX_ID",
    "ImportDocument": "CONNECTOR_IMPORT_DOCUMENT_ID",
}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if not ENV_PATH.exists():
        return env
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env


def fetch_connectors(url: str, token: str) -> list[dict]:
    q = "{ connectors { id name active } }"
    r = requests.post(
        url,
        json={"query": q},
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=60,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("errors"):
        raise RuntimeError(body["errors"])
    return body.get("data", {}).get("connectors", [])


def match_env_key(name: str) -> str | None:
    for fragment, var in NAME_TO_ENV.items():
        if fragment.lower() in name.lower():
            return var
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Met à jour .env")
    args = parser.parse_args()

    env = load_env()
    url = os.environ.get("OPENCTI_GRAPHQL_URL", env.get("OPENCTI_GRAPHQL_URL", "https://localhost/cti/graphql"))
    token = os.environ.get("OPENCTI_ADMIN_TOKEN", env.get("OPENCTI_ADMIN_TOKEN", ""))
    if not token:
        print("OPENCTI_ADMIN_TOKEN manquant", file=sys.stderr)
        return 1

    connectors = fetch_connectors(url, token)
    env_file = load_env()
    mismatches: list[tuple[str, str, str, str]] = []
    updates: dict[str, str] = {}

    for c in connectors:
        var = match_env_key(c["name"])
        if not var:
            continue
        registered = c["id"]
        current = env_file.get(var, "")
        if current and current != registered:
            mismatches.append((var, c["name"], current, registered))
        if not current:
            updates[var] = registered
            print(f"[sync] {var}={registered}  ({c['name']})")

    for var, name, old, new in mismatches:
        print(f"[MISMATCH] {var} ({name}): .env={old} opencti={new}")
        updates[var] = new

    if not updates and not mismatches:
        print("[sync] Tous les CONNECTOR_ID connus sont alignés")
        return 0

    if args.write and updates:
        text = ENV_PATH.read_text()
        for var, new_id in updates.items():
            pat = re.compile(rf"^{re.escape(var)}=.*$", re.M)
            if pat.search(text):
                text = pat.sub(f"{var}={new_id}", text)
            else:
                text += f"\n{var}={new_id}\n"
        ENV_PATH.write_text(text)
        print(f"[sync] {len(updates)} variable(s) écrite(s) dans .env")
    elif updates:
        print("[sync] Relancer avec --write pour appliquer")

    return 1 if mismatches and not args.write else 0


if __name__ == "__main__":
    sys.exit(main())
