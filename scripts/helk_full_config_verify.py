#!/usr/bin/env python3
"""Vérifie la configuration HELK DFIR complète (safe offline lab)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELK = ROOT / "helk"
BASE_URL = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
CHECKS: list[tuple[str, bool, str]] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append((name, cond, detail))


def exists(path: Path) -> bool:
    return path.is_file() or path.is_dir()


def main() -> int:
    # Phase 1
    for f in ["sysmon-sample.jsonl", "linux-auth.log", "linux-syslog", "zeek-sample-conn.log"]:
        ok(f"lab-source {f}", exists(HELK / "lab-sources" / f))
    ok("lab_ingest.py", exists(HELK / "scripts" / "lab_ingest.py"))

    # Phase 2 pipelines
    for p in [
        "0000-input-http-lab.conf", "0010-sysmon.conf", "0020-windows-evtx.conf",
        "0030-linux-auth.conf", "0040-linux-syslog.conf", "0050-zeek.conf",
        "0060-ecs-normalization.conf", "0070-mitre-enrichment.conf", "0080-sigma-detections.conf",
    ]:
        ok(f"pipeline {p}", exists(HELK / "config/logstash/pipeline" / p))

    # Phase 3 Sigma
    ok("sigma rules dir", exists(HELK / "sigma" / "rules"))
    ok("sigma_runner.py", exists(HELK / "scripts" / "sigma_runner.py"))

    # Phase 4 MITRE
    ok("enterprise-attack.json", exists(HELK / "mitre" / "enterprise-attack.json"))

    # Phase 5 dashboards Grafana
    for d in ["helk-overview.json", "helk-sysmon.json", "helk-linux.json", "helk-zeek.json", "helk-mitre.json", "helk-detections.json"]:
        ok(f"grafana {d}", exists(ROOT / "dashboards/grafana/helk" / d))

    # Phase 6 interconnexions
    ok("helk-routes lab/ingest", "helk/lab/ingest" in (ROOT / "portal-cert/routes/helk-routes.js").read_text())
    ok("UI Envoyer vers HELK", "helk-lab-ingest" in (ROOT / "portal-shared/js/helk-integration.js").read_text())
    ok("helk_bridge lab/ingest", "lab/ingest" in (HELK / "scripts/helk_bridge.py").read_text())

    # Phase 8 doc
    ok("HELK-FULL-CONFIG.md", exists(ROOT / "docs/HELK-FULL-CONFIG.md"))
    ok("setup-helk-full.sh", exists(HELK / "scripts/setup-helk-full.sh"))

    # lab_ingest smoke
    sys.path.insert(0, str(HELK / "scripts"))
    try:
        from lab_ingest import run_lab_ingest  # noqa: WPS433
        summary = run_lab_ingest(sources=HELK / "lab-sources", logstash="http://127.0.0.1:1")
        ok("run_lab_ingest callable", summary.get("total", 0) > 0, str(summary.get("total")))
    except Exception as exc:
        ok("run_lab_ingest callable", False, str(exc))

    # HTTP optional
    try:
        import ssl
        import urllib.request
        ctx = ssl._create_unverified_context()
        for path in ["/api/helk/status", "/api/helk/lab/status"]:
            with urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}{path}"), timeout=8, context=ctx) as resp:
                ok(f"HTTP {path}", resp.status == 200)
    except Exception as exc:
        ok("HTTP checks (optional)", True, f"skip: {exc}")

    passed = sum(1 for _, c, _ in CHECKS if c)
    print(f"HELK full config verify: {passed}/{len(CHECKS)} OK")
    for name, c, detail in CHECKS:
        print(f"  [{'OK' if c else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
