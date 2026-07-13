#!/usr/bin/env python3
"""MinIO Master Setup — buckets premium, RBAC, encryption, replication, notifications."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from minio_master_lib import (  # noqa: E402
    MINIO_API,
    PREMIUM_BUCKETS,
    check_fp_integration_config,
    enable_versioning,
    ensure_premium_buckets,
    ko,
    metrics,
    ok,
    pivot_os_ts_cti,
    save_state,
    seed_fp_integration_markers,
    setup_encryption,
    setup_lifecycle,
    setup_notifications,
    setup_policies,
    setup_replication,
    setup_users_groups,
    start_minio_stack,
    sync_integrations,
)


def main() -> int:
    fails = 0
    print(f"[minio-master-setup] API={MINIO_API}")

    start_minio_stack()
    if ensure_premium_buckets() < len(PREMIUM_BUCKETS):
        fails += 1

    if setup_policies() < 3:
        fails += 1
    setup_users_groups()
    enable_versioning()
    setup_replication()
    setup_encryption()
    setup_lifecycle()
    seed_fp_integration_markers()

    if setup_notifications() < 1:
        ko("notifications insuffisantes")
        fails += 1
    cfg = check_fp_integration_config()
    if not cfg.get("thehive_s3_artefacts"):
        fails += 1

    integ = sync_integrations()
    pivot = pivot_os_ts_cti()
    m = metrics()
    save_state({"metrics": m, "integrations": integ, "config": cfg, "pivot": pivot})

    ok(f"buckets={m['buckets_total']} premium={m['buckets_premium']}")
    print(f"[minio-master-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
