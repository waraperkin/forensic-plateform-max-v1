#!/usr/bin/env python3
"""Déploie Blue Team Lead Playbook."""
from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

import requests

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fp_playbooks_common import ensure_notebook, ensure_observability_app, hdrs, import_ndjson, patch_all_fp_dashboards, restore_refs, run_cmd  # noqa: E402
from osd_blue_team_lead_playbook_lib import APP_NAME, DASH_ID, LAUNCHER_ID, NOTEBOOK_NAME, notebook_paragraphs  # noqa: E402

NDJSON = ROOT / "dashboards/opensearch/fp-blue-team-lead-playbook.ndjson"
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
PY = sys.executable


def main() -> int:
    fails = 0
    if not run_cmd([PY, str(ROOT / "scripts/build_blue_team_lead_playbook.py")], "build Blue Team Lead"):
        fails += 1
    if not import_ndjson(NDJSON):
        fails += 1
    if not restore_refs():
        fails += 1
    s = requests.Session()
    s.verify = False
    fails += patch_all_fp_dashboards(s)
    fails += ensure_observability_app(s, APP_NAME, "Panneau latéral Blue Team Lead", "source = fp-events | stats count() by ti_match")
    fails += ensure_notebook(s, NOTEBOOK_NAME, notebook_paragraphs())
    if s.get(f"{OSD}/api/saved_objects/search/{LAUNCHER_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    if s.get(f"{OSD}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    else:
        print(f"[blue-team-setup] OK dashboard {DASH_ID}")
    print(f"[blue-team-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
