#!/usr/bin/env python3
"""
Pack tests UI FP — QA strict pessimiste, navigateur réel uniquement.
Jamais de réutilisation silencieuse de résultats OK précédents.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_browser_qa_lib import BROWSER_RESULTS, load_qa_expectations, log_qa  # noqa: E402
from fp_tests_lib import UI_STATUS, log, step_result, summarize_steps, write_status  # noqa: E402


def run_playwright_strict() -> int:
    script = ROOT / "scripts" / "fp_browser_qa_playwright.py"
    env = os.environ.copy()
    env["FP_QA_STRICT"] = "1"
    env["FP_BROWSER_HEADLESS"] = os.environ.get("FP_BROWSER_HEADLESS", "1")
    cmd = [sys.executable, str(script)]
    log("fp-ui", f"exécution stricte navigateur: {script.name}")
    return subprocess.run(cmd, cwd=str(ROOT), env=env, timeout=7200).returncode


def merge_browser_results() -> dict:
    if not BROWSER_RESULTS.is_file():
        return summarize_steps(
            [step_result("browser_qa_missing", False, f"absent: {BROWSER_RESULTS}")]
        )
    raw = json.loads(BROWSER_RESULTS.read_text(encoding="utf-8"))
    steps = []
    for s in raw.get("steps", []):
        steps.append(
            step_result(
                s.get("name", "?"),
                bool(s.get("ok")),
                s.get("detail", ""),
                extra={
                    "url": s.get("url"),
                    "screenshot": s.get("screenshot"),
                    "expectation_key": s.get("expectation_key"),
                    "critical": s.get("critical"),
                    "metrics": s.get("metrics"),
                },
            )
        )
    data = summarize_steps(steps)
    data["browser_engine"] = raw.get("engine")
    data["human_validation_required"] = True
    data["human_validation_note"] = raw.get(
        "human_validation_note",
        "Validation humaine obligatoire avant de conclure que la plateforme est saine.",
    )
    exp = load_qa_expectations()
    if raw.get("global_status") == "OK" and exp.get("meta", {}).get("pessimistic"):
        data["automated_claim"] = "NE PAS interpréter OK automatique comme validation produit finale"
    return data


def main() -> int:
    log("fp-ui", "=== Tests UI FP — HARD LOCK (pessimiste) ===")
    log_qa("fp-ui", f"expectations: {ROOT / 'config' / 'qa_expectations.yaml'}")

    rc = run_playwright_strict()
    data = merge_browser_results()

    if rc != 0 and data.get("global_status") == "OK":
        data["global_status"] = "FAIL"
        data["error_count"] = data.get("error_count", 0) + 1
        data["steps"].append(step_result("playwright_exit_code", False, f"exit {rc}"))

    write_status(UI_STATUS, data)
    log("fp-ui", f"GLOBAL={data['global_status']} errors={data['error_count']}/{data['total_steps']}")
    log("fp-ui", "→ validation humaine requise avant conclusion « tout est bon »")
    return 0 if data["global_status"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
