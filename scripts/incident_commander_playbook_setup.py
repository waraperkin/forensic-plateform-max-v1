#!/usr/bin/env python3
"""Déploie Incident Commander Playbook."""
from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

import requests

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fp_playbooks_common import (  # noqa: E402
    hdrs,
    import_ndjson,
    patch_all_fp_dashboards,
    restore_refs,
    run_cmd,
    ensure_notebook,
    ensure_observability_app,
)
from osd_incident_commander_playbook_lib import (  # noqa: E402
    APP_NAME,
    DASH_ID,
    LAUNCHER_ID,
    NOTEBOOK_NAME,
    notebook_paragraphs,
)

NDJSON = ROOT / "dashboards" / "opensearch" / "fp-incident-commander-playbook.ndjson"
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
PY = sys.executable


def main() -> int:
    fails = 0
    if not run_cmd([PY, str(ROOT / "scripts" / "build_incident_commander_playbook.py")], "build IC"):
        fails += 1
    if not import_ndjson(NDJSON):
        fails += 1
    if not restore_refs():
        fails += 1

    s = requests.Session()
    s.verify = False
    fails += patch_all_fp_dashboards(s)
    fails += ensure_observability_app(
        s, APP_NAME, "Panneau latéral Incident Commander — réponse incident",
        "source = forensic-alerts* | where level = 'critical' | head 50",
    )
    fails += ensure_notebook(s, NOTEBOOK_NAME, notebook_paragraphs())

    if s.get(f"{OSD}/api/saved_objects/search/{LAUNCHER_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    if s.get(f"{OSD}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    else:
        print(f"[ic-setup] OK dashboard {DASH_ID}")

    print(f"[ic-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
