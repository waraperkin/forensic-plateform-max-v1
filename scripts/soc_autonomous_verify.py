#!/usr/bin/env python3
"""SOC Autonomous Verify — agrège verify existants + statut JSON."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from soc_autonomous_lib import (  # noqa: E402
    COMPONENTS,
    LOG_FILE,
    STATUS_FILE,
    log,
    run_component_checks,
    run_forensic_cmd,
    run_health_checks,
    run_verify_bundle,
    summarize_status,
)


def main() -> int:
    log("=== soc_autonomous_verify ===")
    if not STATUS_FILE.is_file():
        run_health_checks(remediate=False, include_verify=False)

    bundle = run_verify_bundle()
    fails = bundle["verify_bundle_fails"]

    data = json.loads(STATUS_FILE.read_text(encoding="utf-8")) if STATUS_FILE.is_file() else {}
    data["verify_bundle"] = bundle
    data["verify_run_at"] = bundle["updated_at"]
    data["global_status"] = "OK" if fails == 0 else ("WARN" if fails <= 2 else "FAIL")
    data["verify_errors"] = fails

    STATUS_FILE.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log(f"verify_bundle fails={fails} GLOBAL={data['global_status']}")

    if fails > 0:
        for cmd, r in bundle["results"].items():
            if not r["ok"]:
                print(f"[soc-autonomous-verify] KO {cmd}", file=sys.stderr)

    print(f"[soc-autonomous-verify] errors={fails} global={data['global_status']}")
    print(f"[soc-autonomous-verify] status={STATUS_FILE}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
