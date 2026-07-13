#!/usr/bin/env python3
"""SOC Autonomous Mode — cycle complet health + correction + statut global."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from soc_autonomous_lib import LOG_FILE, STATUS_FILE, log, run_health_checks, summarize_status  # noqa: E402


def run_full_health_cycle(remediate: bool = True, *, include_verify: bool = False) -> int:
    log("=== SOC Autonomous — run_full_health_cycle ===")
    payload = run_health_checks(remediate=remediate, include_verify=include_verify)
    gs = payload["global_status"]
    sm = payload["summary"]
    log(f"GLOBAL_STATUS={gs} OK={sm['ok']} WARN={sm['warn']} FAIL={sm['fail']}")
    if sm.get("critical_failures"):
        log(f"critical_failures={sm['critical_failures']}")
    return 0 if gs in ("OK", "WARN") else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="SOC Autonomous Mode")
    parser.add_argument("--loop", action="store_true", help="Mode daemon (boucle)")
    parser.add_argument("--interval", type=int, default=30, help="Minutes entre cycles (mode loop)")
    parser.add_argument("--no-remediate", action="store_true", help="Pas de correction auto")
    args = parser.parse_args()

    LOG_FILE.write_text("", encoding="utf-8")
    log("SOC Autonomous Master démarré")

    if args.loop:
        log(f"Mode loop — interval={args.interval} min (Ctrl+C pour arrêter)")
        while True:
            rc = run_full_health_cycle(remediate=not args.no_remediate)
            log(f"cycle rc={rc} status file={STATUS_FILE}")
            time.sleep(max(args.interval, 5) * 60)
    return run_full_health_cycle(remediate=not args.no_remediate)


if __name__ == "__main__":
    sys.exit(main())
