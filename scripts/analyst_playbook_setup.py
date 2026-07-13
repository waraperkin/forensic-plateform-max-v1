#!/usr/bin/env python3
"""Déploie Analyst Playbook — build, import, barres Playbook, notebook, side app."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import warnings
from pathlib import Path

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

ROOT = Path(__file__).resolve().parent.parent
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
OS = os.environ.get("OS_URL", "http://localhost:9200").rstrip("/")
OBS_INDEX = ".opensearch-observability"

sys.path.insert(0, str(ROOT / "scripts"))
from fp_playbooks_common import patch_all_fp_dashboards  # noqa: E402
from osd_analyst_playbook_lib import (  # noqa: E402
    PLAYBOOK_APP_NAME,
    PLAYBOOK_DASH_ID,
    PLAYBOOK_LAUNCHER_ID,
    PLAYBOOK_NOTEBOOK_NAME,
    playbook_notebook_paragraphs,
)
from fp_playbooks_common import ensure_notebook, ensure_observability_app  # noqa: E402


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def run(cmd: list[str], label: str) -> bool:
    r = subprocess.run(cmd, cwd=str(ROOT), timeout=900)
    if r.returncode != 0:
        print(f"[playbook-setup] KO {label}", file=sys.stderr)
        return False
    print(f"[playbook-setup] OK {label}")
    return True


def main() -> int:
    py = sys.executable
    scripts = ROOT / "scripts"
    fails = 0

    steps = [
        ([py, str(scripts / "build_opensearch_playbook.py")], "build playbook NDJSON"),
        (["bash", str(scripts / "opensearch_dashboards_import_playbook.sh")], "import playbook"),
        ([py, str(scripts / "opensearch_restore_dashboard_refs.py")], "restore refs"),
    ]
    for cmd, label in steps:
        if not run(cmd, label):
            fails += 1

    s = requests.Session()
    s.verify = False

    fails += patch_all_fp_dashboards(s)
    fails += ensure_observability_app(
        s, PLAYBOOK_APP_NAME, "Panneau latéral Analyst Playbook",
        "source = forensic-ti-* | stats count() by ioc_type, source",
    )
    fails += ensure_notebook(s, PLAYBOOK_NOTEBOOK_NAME, playbook_notebook_paragraphs())

    # Vérifier launcher search
    lr = s.get(f"{OSD}/api/saved_objects/search/{PLAYBOOK_LAUNCHER_ID}", headers=hdrs(), timeout=15)
    if lr.status_code != 200:
        print(f"[playbook-setup] KO launcher search missing", file=sys.stderr)
        fails += 1

    dr = s.get(f"{OSD}/api/saved_objects/dashboard/{PLAYBOOK_DASH_ID}", headers=hdrs(), timeout=15)
    if dr.status_code != 200:
        print(f"[playbook-setup] KO dashboard missing", file=sys.stderr)
        fails += 1
    else:
        print(f"[playbook-setup] OK dashboard {PLAYBOOK_DASH_ID}")

    print(f"[playbook-setup] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
