#!/usr/bin/env python3
"""Agrège pytest V2 + Playwright → qa-report-v2.json + qa-report-v2.html."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "tests" / "reports"
PYTEST_JSON = REPORTS / "pytest-v2-report.json"
PW_JSON = REPORTS / "playwright-v2-report.json"
PW_FALLBACK = REPORTS / "playwright-report.json"
# playwright.config.ts V2 écrit directement playwright-v2-report.json
OUT_JSON = REPORTS / "qa-report-v2.json"
OUT_HTML = REPORTS / "qa-report-v2.html"


def load_json(path: Path) -> dict:
    if not path.is_file():
        return {"missing": True, "path": str(path)}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"error": str(exc), "path": str(path)}


def summarize_pytest(data: dict) -> dict:
    if data.get("missing"):
        return {"status": "unknown", "total": 0, "passed": 0, "failed": 0, "skipped": 0}
    summary = data.get("summary") or data
    failed = summary.get("failed", 0) + summary.get("errors", 0)
    return {
        "status": "passed" if failed == 0 else "failed",
        "total": summary.get("total", 0),
        "passed": summary.get("passed", 0),
        "failed": failed,
        "skipped": summary.get("skipped", 0),
    }


def summarize_playwright(data: dict) -> dict:
    if data.get("missing") or not isinstance(data, dict):
        return {"status": "unknown", "total": 0, "passed": 0, "failed": 0, "skipped": 0}
    stats = data.get("stats")
    if isinstance(stats, dict):
        passed = stats.get("expected", 0) + stats.get("flaky", 0)
        failed = stats.get("unexpected", 0)
        skipped = stats.get("skipped", 0)
        total = passed + failed + skipped
        return {
            "status": "passed" if failed == 0 and total > 0 else ("failed" if failed else "unknown"),
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        }
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

    walk(data.get("suites") or [])
    total = passed + failed + skipped
    return {
        "status": "passed" if failed == 0 and total > 0 else ("failed" if failed else "unknown"),
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
    }


def count_suites_by_marker(pytest_data: dict) -> dict:
    """Compte approximatif par chemin de test."""
    buckets = {
        "api_v2": 0,
        "chaos": 0,
        "perf_v2": 0,
        "ia": 0,
        "soc": 0,
        "regression": 0,
        "other": 0,
    }
    tests = pytest_data.get("tests") or []
    for t in tests:
        nodeid = t.get("nodeid", "")
        outcome = t.get("outcome", "")
        if outcome not in ("passed", "failed", "skipped"):
            continue
        placed = False
        for key in ("api_v2", "chaos", "perf_v2", "ia", "soc", "regression"):
            if f"/{key}/" in nodeid or f"\\{key}\\" in nodeid:
                buckets[key] += 1
                placed = True
                break
        if not placed:
            buckets["other"] += 1
    return buckets


def summarize_playwright_log(log_path: Path) -> dict | None:
    if not log_path.is_file():
        return None
    text = log_path.read_text(encoding="utf-8", errors="replace")
    import re

    m = re.search(r"(\d+)\s+passed(?:.*?(\d+)\s+failed)?(?:.*?(\d+)\s+skipped)?", text)
    if not m:
        return None
    passed = int(m.group(1))
    failed = int(m.group(2) or 0)
    skipped = int(m.group(3) or 0)
    total = passed + failed + skipped
    return {
        "status": "passed" if failed == 0 and total > 0 else ("failed" if failed else "unknown"),
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "source": "log",
    }


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    pytest_data = load_json(PYTEST_JSON)
    pw_path = PW_JSON if PW_JSON.is_file() else PW_FALLBACK
    pw_data = load_json(pw_path)

    pytest_sum = summarize_pytest(pytest_data)
    pw_sum = summarize_playwright(pw_data)
    if pw_sum.get("total", 0) == 0:
        log_sum = summarize_playwright_log(REPORTS / "playwright-v2.log")
        if log_sum:
            pw_sum = log_sum
    markers = count_suites_by_marker(pytest_data) if not pytest_data.get("missing") else {}

    report = {
        "version": "2.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "portal_url": os.environ.get("CERT_PORTAL_URL", "http://localhost:3000"),
        "backup": os.environ.get("QA_BACKUP_PATH", ""),
        "pytest": pytest_sum,
        "playwright": pw_sum,
        "pytest_buckets": markers,
        "thresholds": {
            "fps_min": os.environ.get("QA_FPS_MIN", "50"),
            "api_ms": os.environ.get("QA_API_V2_MAX_MS", "150"),
            "panel_ms": os.environ.get("QA_PANEL_MAX_MS", "1200"),
        },
    }
    overall_ok = (
        pytest_sum.get("failed", 0) == 0
        and pw_sum.get("failed", 0) == 0
        and (pytest_sum.get("total", 0) > 0 or pw_sum.get("total", 0) > 0)
    )
    report["overall"] = "PASS" if overall_ok else "FAIL"
    OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")

    bucket_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in sorted(markers.items())
    )
    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>QA Report V2 — CERT CYBERCORP</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#0a0e14;color:#e6edf3}}
h1{{color:#3dffb8}}
.ok{{color:#3fb950}}.ko{{color:#f85149}}
table{{border-collapse:collapse;margin:1rem 0}}
td,th{{border:1px solid #30363d;padding:.5rem 1rem}}
.section{{margin-top:2rem}}
</style></head>
<body>
<h1>QA 2.0 — CERT CYBERCORP</h1>
<p>Généré : {report["generated_at"]}</p>
<p>Global : <strong class="{'ok' if report['overall']=='PASS' else 'ko'}">{report["overall"]}</strong></p>
<div class="section">
<h2>Pytest</h2>
<table>
<tr><th>Statut</th><th>Pass</th><th>Fail</th><th>Skip</th><th>Total</th></tr>
<tr><td>{pytest_sum["status"]}</td><td>{pytest_sum.get("passed",0)}</td>
<td>{pytest_sum.get("failed",0)}</td><td>{pytest_sum.get("skipped",0)}</td><td>{pytest_sum.get("total",0)}</td></tr>
</table>
<h3>Répartition</h3>
<table><tr><th>Bucket</th><th>Tests</th></tr>{bucket_rows}</table>
</div>
<div class="section">
<h2>Playwright</h2>
<table>
<tr><th>Statut</th><th>Pass</th><th>Fail</th><th>Skip</th><th>Total</th></tr>
<tr><td>{pw_sum["status"]}</td><td>{pw_sum.get("passed",0)}</td>
<td>{pw_sum.get("failed",0)}</td><td>{pw_sum.get("skipped",0)}</td><td>{pw_sum.get("total",0)}</td></tr>
</table>
<p>Projets : ui, ui-v2, chaos, perf, perf-v2</p>
</div>
<div class="section">
<h2>Seuils</h2>
<ul>
<li>FPS min : {report["thresholds"]["fps_min"]}</li>
<li>API latence cible : {report["thresholds"]["api_ms"]} ms (×6 en CI)</li>
<li>Panneau lourd : {report["thresholds"]["panel_ms"]} ms (×4 en CI)</li>
</ul>
</div>
<p>Backup : {report.get("backup") or "—"}</p>
<p>Détails Playwright : <code>tests/reports/playwright-html/</code></p>
</body></html>"""
    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"[qa-v2-report] {OUT_JSON}")
    print(f"[qa-v2-report] {OUT_HTML}")
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
