#!/usr/bin/env python3
"""Déploie SOC Manager Playbook."""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

import requests

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fp_playbooks_common import (  # noqa: E402
    import_ndjson,
    patch_all_fp_dashboards,
    restore_refs,
    run_cmd,
    ensure_notebook,
    ensure_observability_app,
)
from osd_soc_manager_playbook_lib import (  # noqa: E402
    APP_NAME,
    DASH_ID,
    LAUNCHER_ID,
    NOTEBOOK_NAME,
    notebook_paragraphs,
)

NDJSON = ROOT / "dashboards" / "opensearch" / "fp-soc-manager-playbook.ndjson"
PY = sys.executable


def main() -> int:
    fails = 0
    if not run_cmd([PY, str(ROOT / "scripts" / "build_soc_manager_playbook.py")], "build SOC Manager"):
        fails += 1
    if not import_ndjson(NDJSON):
        fails += 1
    if not restore_refs():
        fails += 1

    s = requests.Session()
    s.verify = False
    fails += patch_all_fp_dashboards(s)
    fails += ensure_observability_app(
        s, APP_NAME, "Panneau latéral SOC Manager — supervision & KPIs",
        "source = fp-platform-logs | stats count() by service, level",
    )
    fails += ensure_notebook(s, NOTEBOOK_NAME, notebook_paragraphs())

    import os
    from fp_playbooks_common import hdrs  # noqa: E402
    OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
    if s.get(f"{OSD}/api/saved_objects/search/{LAUNCHER_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    if s.get(f"{OSD}/api/saved_objects/dashboard/{DASH_ID}", headers=hdrs(), timeout=15).status_code != 200:
        fails += 1
    else:
        print(f"[soc-manager-setup] OK dashboard {DASH_ID}")

    print(f"[soc-manager-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
