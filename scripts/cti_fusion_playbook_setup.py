#!/usr/bin/env python3
"""Déploie CTI Fusion Center Playbook."""
from __future__ import annotations

import os, sys, warnings
from pathlib import Path
import requests
warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from fp_playbooks_common import hdrs, import_ndjson, patch_all_fp_dashboards, restore_refs, run_cmd, ensure_notebook, ensure_observability_app  # noqa: E402
from osd_cti_fusion_playbook_lib import APP_NAME, DASH_ID, LAUNCHER_ID, NOTEBOOK_NAME, notebook_paragraphs  # noqa: E402

NDJSON = ROOT / "dashboards/opensearch/fp-cti-fusion-center-playbook.ndjson"
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
PY = sys.executable

def main() -> int:
    fails = 0
    if not run_cmd([PY, str(ROOT / "scripts/build_cti_fusion_playbook.py")], "build"):
        fails += 1
    if not import_ndjson(NDJSON):
        fails += 1
    if not restore_refs():
        fails += 1
    s = requests.Session()
    s.verify = False
    fails += patch_all_fp_dashboards(s)
    fails += ensure_observability_app(s, APP_NAME, "Panneau latéral CTI Fusion Center", "source = forensic-fusion-metrics | head 40")
    fails += ensure_notebook(s, NOTEBOOK_NAME, notebook_paragraphs())
    if s.get(f"{OSD}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=15).status_code == 200:
        print(f"[cti-fusion-setup] OK {DASH_ID}")
    else:
        fails += 1
    print(f"[cti-fusion-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
