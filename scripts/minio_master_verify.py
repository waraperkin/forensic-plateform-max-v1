#!/usr/bin/env python3
"""MinIO Master Verify — API strict (9 zones + intégrations FP)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from minio_master_lib import (  # noqa: E402
    PREMIUM_BUCKETS,
    TH_CONFIG,
    ko,
    load_state,
    metrics,
    ok,
    pivot_os_ts_cti,
    run_mc,
)


def main() -> int:
    fails = 0
    m = metrics()

    if m["health"] != 200:
        ko(f"health={m['health']}")
        fails += 1
    else:
        ok("MinIO health live")

    if m["buckets_premium"] < len(PREMIUM_BUCKETS):
        ko(f"buckets_premium={m['buckets_premium']} min={len(PREMIUM_BUCKETS)}")
        fails += 1
    else:
        ok(f"buckets_premium={m['buckets_premium']}")

    if m["buckets_total"] < 18:
        ko(f"buckets_total={m['buckets_total']}")
        fails += 1
    else:
        ok(f"buckets_total={m['buckets_total']}")

    if m["policies_fp"] < 3:
        ko(f"policies_fp={m['policies_fp']}")
        fails += 1
    else:
        ok(f"policies_fp={m['policies_fp']}")

    if m["users"] < 2:
        ko(f"users={m['users']}")
        fails += 1
    else:
        ok(f"users={m['users']}")

    if m["versioning_premium"] < len(PREMIUM_BUCKETS):
        ko(f"versioning_premium={m['versioning_premium']}")
        fails += 1
    else:
        ok(f"versioning_premium={m['versioning_premium']}")

    if m["replication_rules"] < 1:
        ko(f"replication_rules={m['replication_rules']}")
        fails += 1
    else:
        ok(f"replication_rules={m['replication_rules']}")

    if m["notification_buckets"] < 1:
        ko(f"notification_buckets={m['notification_buckets']}")
        fails += 1
    else:
        ok(f"notification_buckets={m['notification_buckets']}")

    if m["lifecycle_rules"] < 1:
        ko(f"lifecycle_rules={m['lifecycle_rules']}")
        fails += 1
    else:
        ok(f"lifecycle_rules={m['lifecycle_rules']}")

    rc, enc_out = run_mc('mc tag list "local/fp-dfir" 2>/dev/null')
    if rc == 0 and "fp-sse" in enc_out:
        ok("encryption tags fp-sse")
    else:
        ko("encryption (tags fp-sse) non confirmée")
        fails += 1

    rc, tag_out = run_mc('mc stat "local/fp-cases/integration/case-storage-marker.txt" 2>/dev/null')
    if rc != 0 and "case-storage-marker" not in tag_out:
        ko("marqueur intégration fp-cases absent")
        fails += 1
    else:
        ok("marqueur intégration fp-cases")

    th = TH_CONFIG.read_text(encoding="utf-8") if TH_CONFIG.is_file() else ""
    if "minio:9000" not in th or "artefacts" not in th:
        ko("config TheHive→MinIO absente")
        fails += 1
    else:
        ok("config TheHive S3 artefacts")

    st = load_state()
    if not st.get("integrations"):
        ko("state intégrations absent")
        fails += 1
    else:
        ok("state intégrations présent")

    pivot = pivot_os_ts_cti()
    if pivot.get("os_hits", -1) < 0:
        ko("pivot OpenSearch")
        fails += 1
    else:
        ok(f"pivot OpenSearch hits={pivot.get('os_hits')}")
    if not pivot.get("ts_ok"):
        ko("pivot Timesketch")
        fails += 1
    else:
        ok("pivot Timesketch")
    if not pivot.get("misp_ok"):
        ko("pivot MISP")
        fails += 1
    else:
        ok("pivot MISP")
    if not pivot.get("opencti_ok"):
        ko("pivot OpenCTI")
        fails += 1
    else:
        ok("pivot OpenCTI")

    print(f"[minio-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
