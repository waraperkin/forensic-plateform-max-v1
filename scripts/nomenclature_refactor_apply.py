#!/usr/bin/env python3
"""Phase 3 — Application orchestrée nomenclature (backup → refactor → rebuild → verify → rollback si échec)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_common import BACKUP_ROOT, PLAN_PATH, ROOT as NC_ROOT, backup_paths, log, rollback_from, utc_stamp  # noqa: E402

FORENSIC = NC_ROOT / "forensic.sh"

BACKUP_GLOBS = [
    "scripts/build_opensearch*.py",
    "scripts/osd_*_lib.py",
    "scripts/osd_*_playbook_lib.py",
    "scripts/build_grafana_master_dashboards.py",
    "scripts/dashboard_metrics_lib.py",
    "scripts/fp_browser_qa_lib.py",
    "scripts/detection_intel_master_lib.py",
    "scripts/timesketch_master_lib.py",
    "scripts/ts_*.py",
    "portal-cert/public/index.html",
    "portal-it/public/index.html",
    "portal-shared/js/*.js",
    "portal-cert/lib/master-routes.js",
    "dashboards/grafana/fp-master/*.json",
    "config/nomenclature_official.yaml",
]


def collect_backup_files() -> list[Path]:
    out: set[Path] = set()
    for g in BACKUP_GLOBS:
        for p in NC_ROOT.glob(g):
            if p.is_file():
                out.add(p)
    return sorted(out)


def run_cmd(cmd: list[str], timeout: int = 600) -> tuple[int, str]:
    r = subprocess.run(cmd, cwd=str(NC_ROOT), capture_output=True, text=True, timeout=timeout)
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out


def verify_stack() -> tuple[bool, str]:
    checks = [
        (["python3", str(NC_ROOT / "scripts" / "cluster_repair.py")], 120),
    ]
    for cmd, to in checks:
        rc, out = run_cmd(cmd, timeout=to)
        if rc != 0:
            return False, f"{' '.join(cmd)} rc={rc}\n{out[-800:]}"
    return True, "cluster_repair OK"


def rebuild_artifacts() -> tuple[bool, str]:
    steps = [
        ["python3", "scripts/build_opensearch_dashboards.py"],
        ["python3", "scripts/build_opensearch_siem_ti_dashboards.py"],
        ["python3", "scripts/build_opensearch_enterprise.py"],
        ["python3", "scripts/build_opensearch_observability.py"],
        ["python3", "scripts/osd_platform_health_lib.py"],
        ["python3", "scripts/build_grafana_master_dashboards.py"],
    ]
    for cmd in steps:
        script = NC_ROOT / cmd[1]
        if not script.is_file():
            continue
        rc, out = run_cmd(cmd, timeout=300)
        if rc != 0:
            return False, f"{cmd[1]} rc={rc}\n{out[-500:]}"
    # Playbook NDJSON builders
    for name in (
        "build_purple_team_playbook.py",
        "build_incident_commander_playbook.py",
        "build_analyst_playbook.py",
    ):
        p = NC_ROOT / "scripts" / name
        if p.is_file():
            rc, out = run_cmd(["python3", str(p)], timeout=180)
            if rc != 0:
                return False, f"{name} rc={rc}\n{out[-400:]}"
    return True, "rebuild OK"


def apply_refactors(dry_run: bool) -> int:
    mods = [
        "nomenclature_refactor_osd.py",
        "nomenclature_refactor_grafana.py",
        "nomenclature_refactor_timesketch.py",
        "nomenclature_refactor_portal.py",
    ]
    for m in mods:
        cmd = ["python3", str(NC_ROOT / "scripts" / m)]
        if dry_run:
            cmd.append("--dry-run")
        rc, out = run_cmd(cmd, timeout=120)
        log(out.strip()[-200:] if out else m)
        if rc != 0:
            return rc
    return 0


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--skip-rebuild", action="store_true")
    ap.add_argument("--skip-verify", action="store_true")
    args = ap.parse_args()

    stamp = utc_stamp()
    backup_dir = BACKUP_ROOT / stamp
    files = collect_backup_files()
    log(f"Backup {len(files)} fichiers → {backup_dir}")
    if not args.dry_run:
        backup_paths(files, backup_dir)

    if apply_refactors(args.dry_run) != 0:
        log("ÉCHEC refactor — rollback")
        if not args.dry_run:
            rollback_from(backup_dir)
        return 1

    if args.dry_run:
        log("Dry-run terminé — aucune modification persistée")
        return 0

    if not args.skip_rebuild:
        ok, msg = rebuild_artifacts()
        if not ok:
            log(f"ÉCHEC rebuild: {msg}")
            rollback_from(backup_dir)
            return 2
        log(msg)

    if FORENSIC.is_file():
        for target in ("grafana-master-setup",):
            rc, out = run_cmd([str(FORENSIC), target], timeout=300)
            if rc != 0:
                log(f"WARN {target}: {out[-300:]}")

    if not args.skip_verify:
        ok, msg = verify_stack()
        if not ok:
            log(f"ÉCHEC verify: {msg}")
            rollback_from(backup_dir)
            return 3
        log(msg)

    log(f"OK nomenclature appliquée — rollback: {backup_dir}")
    log(f"Plan: {PLAN_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
