#!/usr/bin/env python3
"""Pack Final de Consolidation — orchestration setup/verify + intégrations FP."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_consolidation_lib import (  # noqa: E402
    STATUS_JSON,
    build_status,
    check_id_coherence,
    check_integrations,
    check_module_files,
    log,
    run_forensic_cmd,
    run_setup_bundle,
    run_verify_bundle,
    write_status,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="FP Consolidation Master")
    ap.add_argument("--skip-setup", action="store_true", help="Ne pas relancer les setup")
    ap.add_argument("--run-setup", action="store_true", help="Forcer tous les setup master")
    ap.add_argument("--no-retry", action="store_true", help="Pas de retry sur verify")
    args = ap.parse_args()

    log("=== FP Consolidation Master ===")

    log("Prérequis: forensic.sh start (stack)")
    ok, msg = run_forensic_cmd("status", timeout=120)
    if not ok:
        log("WARN status — poursuite (stack peut être déjà up)")

    modules = check_module_files()
    log(f"Modules fichiers: {modules['status']} ({len(modules['present'])}/{modules['total_modules']})")

    setup = None
    if args.run_setup and not args.skip_setup:
        log("Phase setup master…")
        setup = run_setup_bundle()
    else:
        log("Phase setup: ignorée (utiliser --run-setup pour forcer)")

    log("Phase verify bundle (22 commandes)…")
    verify = run_verify_bundle(retry=not args.no_retry)

    log("Phase intégrations…")
    integrations = check_integrations()

    log("Phase cohérence IDs…")
    ids = check_id_coherence()

    data = build_status(
        modules=modules,
        integrations=integrations,
        ids=ids,
        verify=verify,
        setup=setup,
    )
    write_status(data)

    print(f"[fp-consolidation-master] GLOBAL={data['global_status']} errors={data['error_count']}")
    print(f"[fp-consolidation-master] verify_fails={verify['verify_fails']}/{verify['verify_total']}")
    print(f"[fp-consolidation-master] status={STATUS_JSON}")

    if data["global_status"] != "OK":
        for cmd, r in verify["results"].items():
            if not r.get("ok"):
                print(f"  KO {cmd}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
