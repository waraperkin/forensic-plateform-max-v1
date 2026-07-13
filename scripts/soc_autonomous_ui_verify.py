#!/usr/bin/env python3
"""SOC Autonomous UI Verify — OSD + Timesketch pages critiques."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from soc_autonomous_lib import LOG_FILE, OSD, STATUS_FILE, TS_URL, check_ui_url, log  # noqa: E402
from crosspivot_engine import resolve_sketch_id  # noqa: E402
from fp_playbooks_common import hdrs  # noqa: E402
import requests


OSD_PAGES = [
    ("fp-opensearch-security", "FP — Security Events & TI"),
    ("fp-ti-overview", "FP — TI Overview"),
    ("fp-incident-commander-playbook", "FP — Incident Commander"),
    ("fp-purple-team-playbook", "FP — Purple Team"),
    ("fp-platform-health", "FP — Platform Health"),
]

TS_PATHS = ["explore", "aggregate", "story"]


def main() -> int:
    fails = 0
    log("=== soc_autonomous_ui_verify ===")
    s = requests.Session()
    s.verify = False
    ui_results: dict[str, Any] = {}

    for dash_id, label in OSD_PAGES:
        url = f"{OSD}/app/dashboards#/view/{dash_id}"
        dr = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=25)
        ok_api = dr.status_code == 200
        ok_ui, msg = check_ui_url(url)
        ui_results[f"osd:{dash_id}"] = {"api": ok_api, "ui": ok_ui, "msg": msg}
        if not ok_api or not ok_ui:
            print(f"[soc-autonomous-ui] KO OSD {label}", file=sys.stderr)
            fails += 1
        else:
            print(f"[soc-autonomous-ui] OK OSD {dash_id}")

    try:
        sid = resolve_sketch_id()
    except Exception:
        sid = 194

    from timesketch_master_lib import login  # noqa: E402

    ts, th = login()
    for path in TS_PATHS:
        url = f"{TS_URL}/sketch/{sid}/{path}/"
        ui = ts.get(url, headers=th, timeout=45)
        ok = ui.status_code == 200 and "Server side error" not in ui.text and "Could not locate field" not in ui.text
        ui_results[f"ts:{path}"] = {"ok": ok, "http": ui.status_code}
        if not ok:
            print(f"[soc-autonomous-ui] KO Timesketch /{path}/", file=sys.stderr)
            fails += 1
        else:
            print(f"[soc-autonomous-ui] OK Timesketch /{path}/")

    intel = ts.get(f"{TS_URL}/api/v1/intelligence/tagmetadata/", headers=th, timeout=25)
    ui_results["ts:intelligence"] = {"ok": intel.status_code == 200, "http": intel.status_code}
    if intel.status_code != 200:
        print("[soc-autonomous-ui] KO intelligence API", file=sys.stderr)
        fails += 1
    else:
        print("[soc-autonomous-ui] OK intelligence")

    data = {}
    if STATUS_FILE.is_file():
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    data["ui_verify"] = {"fails": fails, "results": ui_results, "sketch_id": sid}
    data["ui_verify_ok"] = fails == 0
    if fails > 0 and data.get("global_status") == "OK":
        data["global_status"] = "WARN"
    STATUS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print(f"[soc-autonomous-ui] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
