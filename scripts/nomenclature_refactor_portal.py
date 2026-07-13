#!/usr/bin/env python3
"""Phase 3 — Portail CERT/IT (titres, nav, labels master)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_common import OFFICIAL_PATH, load_yaml, log, replace_in_file  # noqa: E402


def apply_portal(dry_run: bool = False) -> int:
    official = load_yaml(OFFICIAL_PATH)
    cert = official.get("portal_cert") or {}
    it = official.get("portal_it") or {}
    pairs: list[tuple[str, str]] = [
        ("Forensic Platform — Portail CERT", cert.get("page_title", "CERT — National Operations Portal")),
        ("FORENSIC PLATFORM v2.1", cert.get("header", "CERT — Forensic Platform")),
        ("PORTAIL CERT", cert.get("badge", "CERT NATIONAL")),
        ("Portail IT — Upload Forensic", it.get("page_title", "IT — Forensic Upload Portal")),
        ("PORTAIL IT — UPLOAD FORENSIC", it.get("header", "IT — Forensic Upload")),
        ("ÉQUIPE IT", it.get("badge", "ÉQUIPE IT — ANSSI")),
        ("📊 Dashboard CERT", cert.get("nav", {}).get("dashboard-cert", "CERT — Situation Overview")),
        ("📊 Dashboard IT", cert.get("nav", {}).get("dashboard-it", "IT — Exposure Overview")),
        ("🚨 Incidents", cert.get("nav", {}).get("incidents", "CERT — Incident Cases")),
        ("📁 Upload CERT", cert.get("nav", {}).get("upload", "CERT — Evidence Uploads")),
        ("🖥 Assets", cert.get("nav", {}).get("assets", "CERT — Exposure Map")),
        ("🔑 Tokens IT", cert.get("nav", {}).get("tokens", "IT — Asset Inventory")),
        ("📥 Reçus IT", cert.get("nav", {}).get("it", "IT — Uploads")),
        ("🔗 Services", cert.get("nav", {}).get("svcs", "IT — System Health")),
        ("FP-Master", cert.get("master_prefix", "CERT")),
    ]
    paths = [
        ROOT / "portal-cert/public/index.html",
        ROOT / "portal-it/public/index.html",
        ROOT / "portal-shared/js/cert-app.js",
        ROOT / "portal-shared/js/it-app.js",
        ROOT / "portal-cert/lib/master-routes.js",
    ]
    changed = 0
    for path in paths:
        if replace_in_file(path, pairs, dry_run=dry_run):
            changed += 1
            log(f"Portal: {path.relative_to(ROOT)}")
    log(f"Portal terminé — {changed} fichier(s)")
    return 0


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    return apply_portal(dry_run=ap.parse_args().dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
