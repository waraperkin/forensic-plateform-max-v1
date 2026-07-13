#!/usr/bin/env python3
"""Déploie Global SOC Command Center Playbook."""
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
    ensure_notebook,
    ensure_observability_app,
    hdrs,
    import_ndjson,
    patch_all_fp_dashboards,
    restore_refs,
    run_cmd,
)
from osd_global_soc_command_center_lib import APP_NAME, DASH_ID, LAUNCHER_ID, NOTEBOOK_NAME, notebook_paragraphs  # noqa: E402

NDJSON = ROOT / "dashboards" / "opensearch" / "fp-global-soc-command-center.ndjson"
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
PY = sys.executable


def main() -> int:
    fails = 0
    if not run_cmd([PY, str(ROOT / "scripts" / "build_global_soc_command_center.py")], "build Global SOC"):
        fails += 1
    if not import_ndjson(NDJSON):
        fails += 1
    if not restore_refs():
        fails += 1
    s = requests.Session()
    s.verify = False
    fails += patch_all_fp_dashboards(s)
    fails += ensure_observability_app(
        s, APP_NAME, "Panneau latéral Global SOC Command Center", "source = fp-fusion | stats count() by fusion_type"
    )
    fails += ensure_notebook(s, NOTEBOOK_NAME, notebook_paragraphs())
    if s.get(f"{OSD}/api/saved_objects/search/{LAUNCHER_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    if s.get(f"{OSD}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    else:
        print(f"[global-soc-setup] OK dashboard {DASH_ID}")
    print(f"[global-soc-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
