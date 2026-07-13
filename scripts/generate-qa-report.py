#!/usr/bin/env python3
"""Agrège résultats pytest + Playwright → qa-report.json + qa-report.html."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "tests" / "reports"
PYTEST_JSON = REPORTS / "pytest-report.json"
PW_JSON = REPORTS / "playwright-report.json"
OUT_JSON = REPORTS / "qa-report.json"
OUT_HTML = REPORTS / "qa-report.html"


def load_json(path: Path) -> dict:
    if not path.is_file():
        return {"missing": True, "path": str(path)}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"error": str(exc), "path": str(path)}


def summarize_pytest(data: dict) -> dict:
    if data.get("missing"):
        return {"status": "unknown", "total": 0, "passed": 0, "failed": 0}
    summary = data.get("summary") or data
    return {
        "status": "passed" if summary.get("failed", 0) == 0 and summary.get("errors", 0) == 0 else "failed",
        "total": summary.get("total", 0),
        "passed": summary.get("passed", 0),
        "failed": summary.get("failed", 0),
        "skipped": summary.get("skipped", 0),
    }


def summarize_playwright(data: dict) -> dict:
    if data.get("missing") or not isinstance(data, dict):
        return {"status": "unknown", "total": 0, "passed": 0, "failed": 0}
    suites = data.get("suites") or []
    passed = failed = skipped = 0

    def walk(suite_list):
        nonlocal passed, failed, skipped
        for s in suite_list:
            for spec in s.get("specs") or []:
                for t in spec.get("tests") or []:
                    for r in t.get("results") or []:
                        st = r.get("status", "")
                        if st == "passed":
                            passed += 1
                        elif st == "skipped":
                            skipped += 1
                        else:
                            failed += 1
            walk(s.get("suites") or [])

    walk(suites)
    total = passed + failed + skipped
    return {
        "status": "passed" if failed == 0 and total > 0 else ("failed" if failed else "unknown"),
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
    }


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    pytest_data = load_json(PYTEST_JSON)
    pw_data = load_json(PW_JSON)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "portal_url": os.environ.get("CERT_PORTAL_URL", "http://localhost:3000"),
        "pytest": summarize_pytest(pytest_data),
        "playwright": summarize_playwright(pw_data),
        "backup": os.environ.get("QA_BACKUP_PATH", ""),
    }
    overall_ok = (
        report["pytest"]["status"] in ("passed", "unknown")
        and report["playwright"]["status"] in ("passed", "unknown")
        and report["pytest"].get("failed", 0) == 0
        and report["playwright"].get("failed", 0) == 0
    )
    report["overall"] = "PASS" if overall_ok else "FAIL"
    OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>QA Report — CERT CYBERCORP</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f1419;color:#e6edf3}}
.ok{{color:#3fb950}}.ko{{color:#f85149}}table{{border-collapse:collapse}}td,th{{border:1px solid #30363d;padding:.5rem 1rem}}</style></head>
<body>
<h1>QA Report — CERT CYBERCORP</h1>
<p>Généré : {report["generated_at"]}</p>
<p>Global : <strong class="{'ok' if report['overall']=='PASS' else 'ko'}">{report["overall"]}</strong></p>
<table>
<tr><th>Suite</th><th>Statut</th><th>Pass</th><th>Fail</th><th>Skip</th><th>Total</th></tr>
<tr><td>pytest</td><td>{report["pytest"]["status"]}</td><td>{report["pytest"].get("passed",0)}</td>
<td>{report["pytest"].get("failed",0)}</td><td>{report["pytest"].get("skipped",0)}</td><td>{report["pytest"].get("total",0)}</td></tr>
<tr><td>playwright</td><td>{report["playwright"]["status"]}</td><td>{report["playwright"].get("passed",0)}</td>
<td>{report["playwright"].get("failed",0)}</td><td>{report["playwright"].get("skipped",0)}</td><td>{report["playwright"].get("total",0)}</td></tr>
</table>
<p>Backup : {report.get("backup") or "—"}</p>
<p>Détails : <code>tests/reports/playwright-html/</code></p>
</body></html>"""
    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"[qa-report] {OUT_JSON}")
    print(f"[qa-report] {OUT_HTML}")
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
