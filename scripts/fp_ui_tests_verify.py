#!/usr/bin/env python3
"""Verify strict — échoue sans screenshots/preuves sur vues critiques."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_browser_qa_lib import BROWSER_RESULTS  # noqa: E402
from fp_qa_verify_lib import verify_browser_results_strict  # noqa: E402
from fp_tests_lib import UI_STATUS, log, verify_status_file  # noqa: E402


def main() -> int:
    rc_status = verify_status_file(UI_STATUS, "fp-ui-tests-verify")
    rc_strict = verify_browser_results_strict(BROWSER_RESULTS, "fp-ui-tests-verify-strict")

    if UI_STATUS.is_file():
        raw = json.loads(UI_STATUS.read_text(encoding="utf-8"))
        if raw.get("human_validation_required"):
            log(
                "fp-ui-tests-verify",
                "RAPPEL: human_validation_required=true — l'utilisateur doit valider manuellement",
            )

    return 1 if (rc_status != 0 or rc_strict != 0) else 0


if __name__ == "__main__":
    sys.exit(main())
