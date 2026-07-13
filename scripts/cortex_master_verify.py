#!/usr/bin/env python3
"""Cortex Master Verify — API strict (10 zones + intégrations)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from cortex_master_lib import (  # noqa: E402
    CONFIG_FILE,
    TH_CONFIG,
    client,
    ko,
    load_state,
    metrics,
    ok,
    pivot_os_ts_cti_misp,
)


def main() -> int:
    fails = 0
    c = client()
    m = metrics()

    checks = [
        ("analyzer_definitions", m["analyzer_definitions"], 200),
        ("analyzers_enabled", m["analyzers_enabled"], 50),
        ("responder_definitions", m["responder_definitions"], 50),
        ("responders_enabled", m["responders_enabled"], 30),
        ("jobs", m["jobs"], 1),
    ]
    for label, val, min_v in checks:
        if val < min_v:
            ko(f"{label}={val} min={min_v}")
            fails += 1
        else:
            ok(f"{label}={val}")

    if m["reports_ok"] < 1 and m["jobs"] >= 1:
        ko(f"reports accessibles={m['reports_ok']}")
        fails += 1
    else:
        ok(f"reports_ok={m['reports_ok']}")

    roles = m.get("user_roles") or []
    if "analyze" not in roles:
        ko(f"rôles analyze absents: {roles}")
        fails += 1
    else:
        ok(f"rôles={roles}")

    if not m.get("api_key_len", 0):
        ko("Bearer API key absent")
        fails += 1
    else:
        ok("Bearer API key actif")

    status = c.req("GET", "/api/status")
    caps = (status.get("config") or {}).get("capabilities", [])
    if "authByKey" in caps:
        ok("automation authByKey")
    else:
        ko("capability authByKey absente")
        fails += 1

    cfg_text = CONFIG_FILE.read_text(encoding="utf-8") if CONFIG_FILE.is_file() else ""
    th_text = TH_CONFIG.read_text(encoding="utf-8") if TH_CONFIG.is_file() else ""
    for label, frag, blob in (
        ("OpenSearch", "search {", cfg_text),
        ("Analyzers catalog", "analyzers.json", cfg_text),
        ("Responders catalog", "responders.json", cfg_text),
        ("TheHive Cortex", "Cortex", th_text),
        ("Jobs runner", "job", cfg_text),
    ):
        if frag.lower() in blob.lower():
            ok(f"zone config {label}")
        else:
            ko(f"zone config {label}")
            fails += 1

    st = load_state()
    if not st.get("integrations"):
        ko("state intégrations absent")
        fails += 1
    else:
        ok("state intégrations présent")

    pivot = pivot_os_ts_cti_misp()
    if pivot.get("os_hits", -1) < 0:
        ko("pivot OpenSearch")
        fails += 1
    else:
        ok(f"pivot OpenSearch hits={pivot.get('os_hits')}")
    if not pivot.get("misp_ok"):
        ko("pivot MISP")
        fails += 1
    else:
        ok("pivot MISP")
    if not pivot.get("ts_ok"):
        ko("pivot Timesketch")
        fails += 1
    else:
        ok("pivot Timesketch")
    if not pivot.get("opencti_ok"):
        ko("pivot OpenCTI / CTI Fusion")
        fails += 1
    else:
        ok("pivot OpenCTI / CTI Fusion")

    print(f"[cortex-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
