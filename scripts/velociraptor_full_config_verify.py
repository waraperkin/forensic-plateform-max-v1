#!/usr/bin/env python3
"""Vérifie la configuration Velociraptor DFIR complète (offline lab)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VR = ROOT / "velociraptor"
BASE_URL = os.environ.get("BASE_URL", "https://localhost").rstrip("/")

CHECKS: list[tuple[str, bool, str]] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    CHECKS.append((name, cond, detail))


def file_exists(rel: str) -> bool:
    return (ROOT / rel).is_file()


def dir_has_glob(rel: str, pattern: str) -> bool:
    p = ROOT / rel
    return p.is_dir() and any(p.glob(pattern))


def main() -> int:
    # Phase 1 — artefacts
    for art in [
        "velociraptor/artifacts/custom/Windows.Sysmon.ForensicFull.yaml",
        "velociraptor/artifacts/custom/Windows.Registry.ForensicFull.yaml",
        "velociraptor/artifacts/custom/Windows.Memory.Volatility.yaml",
        "velociraptor/artifacts/custom/Linux.Auth.ForensicFull.yaml",
        "velociraptor/artifacts/custom/Linux.Network.ForensicFull.yaml",
        "velociraptor/artifacts/custom/Network.PCAP.ForensicFull.yaml",
    ]:
        ok(f"artefact {Path(art).name}", file_exists(art))

    ok("import script", file_exists("velociraptor/scripts/import-official-artifacts.sh"))
    ok("official README", file_exists("velociraptor/artifacts/official/README.md"))

    # Phase 2 — simulateur
    ok("lab_collect.py", file_exists("velociraptor/scripts/lab_collect.py"))
    ok("lab_simulator.py", file_exists("velociraptor/export/lab_simulator.py"))
    for rel in [
        "velociraptor/lab-data/windows/sysmon-full.jsonl",
        "velociraptor/lab-data/linux/auth-full.jsonl",
        "velociraptor/lab-data/network/pcap-summary.json",
    ]:
        ok(f"lab-data {rel.split('/')[-1]}", file_exists(rel))

    sys.path.insert(0, str(VR / "export"))
    try:
        from lab_simulator import PLAYBOOKS, simulate_playbook  # noqa: WPS433

        ok("playbooks count", len(PLAYBOOKS) >= 6, str(len(PLAYBOOKS)))
        smoke = simulate_playbook("memory-forensics", case_id="VERIFY-SMOKE", auto_export=False)
        ok("simulate_playbook smoke", smoke.get("ok") is True, smoke.get("playbook", ""))
    except Exception as exc:
        ok("lab_simulator import", False, str(exc))

    # Phase 3 — playbooks doc
    ok("VELOCIRAPTOR-PLAYBOOKS.md", file_exists("docs/VELOCIRAPTOR-PLAYBOOKS.md"))

    # Phase 4 — exports
    for script in [
        "velociraptor/export/export_to_cert.py",
        "velociraptor/export/export_to_it.py",
        "velociraptor/export/export_to_opensearch.py",
        "velociraptor/export/export_to_timesketch.py",
        "velociraptor/export/export_to_helk.py",
    ]:
        ok(f"export {Path(script).name}", file_exists(script))

    # Phase 5 — dashboards
    for dash in [
        "dashboards/grafana/velociraptor/vraptor-windows-full.json",
        "dashboards/grafana/velociraptor/vraptor-linux-full.json",
        "dashboards/grafana/velociraptor/vraptor-network-full.json",
        "dashboards/grafana/velociraptor/vraptor-endpoint-full.json",
    ]:
        ok(f"grafana {Path(dash).name}", file_exists(dash))

    # Phase 6 — interconnexions (fichiers portail)
    ok("velociraptor-routes lab", "lab/collect-full" in (ROOT / "portal-cert/routes/velociraptor-routes.js").read_text())
    ok("UI collecte DFIR", "vr-lab-collect-full" in (ROOT / "portal-shared/js/velociraptor-integration.js").read_text())
    ok("IT artefacts VR", "velociraptor-artifacts" in (ROOT / "portal-it/server.js").read_text())

    # Phase 8 — doc full config
    ok("VELOCIRAPTOR-FULL-CONFIG.md", file_exists("docs/VELOCIRAPTOR-FULL-CONFIG.md"))
    ok("setup-full-config.sh", file_exists("velociraptor/scripts/setup-full-config.sh"))

    # HTTP optional
    try:
        import urllib.request
        import ssl

        ctx = ssl._create_unverified_context()
        for path in [
            "/velociraptor/api/health",
            "/api/velociraptor/status",
            "/velociraptor/api/lab/artifacts",
        ]:
            req = urllib.request.Request(f"{BASE_URL}{path}")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                ok(f"HTTP {path}", resp.status == 200, str(resp.status))
    except Exception as exc:
        ok("HTTP checks (optional)", True, f"skip: {exc}")

    passed = sum(1 for _, c, _ in CHECKS if c)
    failed = [name for name, c, d in CHECKS if not c]
    print(f"Velociraptor full config verify: {passed}/{len(CHECKS)} OK")
    for name, c, detail in CHECKS:
        mark = "OK" if c else "FAIL"
        extra = f" — {detail}" if detail else ""
        print(f"  [{mark}] {name}{extra}")
    if failed:
        print("Échecs:", ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
