#!/usr/bin/env python3
"""Active 400+ règles Sigma (OS + Timesketch) + catalogue détection + sync TI."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from detection_intel_master_lib import (  # noqa: E402
    import_sigma_timesketch,
    index_sigma_rules_os,
    sigma_rules_count_ts,
)
from fp_runtime_env import load_runtime_env

load_runtime_env()


def main() -> int:
    target = int(__import__("os").environ.get("FP_SIGMA_TARGET", "400"))
    print(f"[detection-activate] cible={target} règles Sigma")

    ti = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ti_platform_interconnect.py"), "--skip-detection"],
        cwd=str(ROOT),
    )
    if ti.returncode != 0:
        print("[detection-activate] WARN ti_platform_interconnect partiel", file=sys.stderr)

    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sigma_convert.py")],
        cwd=str(ROOT),
        env={**dict(__import__("os").environ), "FP_SIGMA_TARGET": str(target)},
    )
    if r.returncode != 0:
        print("[detection-activate] WARN sigma_convert partiel", file=sys.stderr)

    os_n = index_sigma_rules_os(target)
    print(f"[detection-activate] OK OpenSearch fp-sigma-rules indexed={os_n}")

    imp, skip = import_sigma_timesketch(target)
    ts_n = sigma_rules_count_ts()
    print(f"[detection-activate] OK Timesketch import={imp} skip={skip} total={ts_n}")

    det = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opensearch_generate_detection_rules.py")],
        cwd=str(ROOT),
    )
    if det.returncode != 0:
        print("[detection-activate] WARN fp-detection-rules partiel", file=sys.stderr)

    ioc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "cert_forensic_use_cases_e2e.py"), "--bootstrap-only"],
        cwd=str(ROOT),
    )
    if ioc.returncode != 0:
        print("[detection-activate] WARN bootstrap IOC partiel", file=sys.stderr)

    ti_rules = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "opensearch_alerts_ti_generate.py")],
        cwd=str(ROOT),
    )
    if ti_rules.returncode != 0:
        print("[detection-activate] WARN alertes TI partiel", file=sys.stderr)

    ok = os_n >= target and ts_n >= target
    if not ok:
        print(f"[detection-activate] FAIL os={os_n} ts={ts_n} (cible {target})", file=sys.stderr)
        return 1
    print("[detection-activate] OK — règles actives, TI ingest-worker enrichit les uploads (ti_match)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
