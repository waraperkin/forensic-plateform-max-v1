#!/usr/bin/env python3
"""Verify E2E strict — statut + preuves navigateur E2E."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from fp_tests_lib import E2E_STATUS, log, verify_status_file  # noqa: E402

E2E_BROWSER = Path("/tmp/fp-e2e-browser-steps.json")


def main() -> int:
    rc = verify_status_file(E2E_STATUS, "fp-e2e-tests-verify")
    if not E2E_BROWSER.is_file():
        log("fp-e2e-tests-verify", "KO — preuves navigateur E2E absentes")
        return 1
    steps = json.loads(E2E_BROWSER.read_text(encoding="utf-8"))
    fails = [s for s in steps if not s.get("ok")]
    if fails:
        for s in fails:
            log("fp-e2e-tests-verify", f"  KO {s.get('name')}: {s.get('detail', '')[:100]}")
        return 1
    if E2E_STATUS.is_file():
        raw = json.loads(E2E_STATUS.read_text(encoding="utf-8"))
        log("fp-e2e-tests-verify", f"scenario={raw.get('scenario_case_id')} — validation humaine requise")
    return rc


if __name__ == "__main__":
    sys.exit(main())
