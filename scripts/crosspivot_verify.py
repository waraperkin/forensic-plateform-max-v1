#!/usr/bin/env python3
"""Verify API Cross-Pivot — tous les pivots OS + TS."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import PIVOT_BUILDERS, load_state, verify_pivot  # noqa: E402


def main() -> int:
    fails = 0
    results = []
    for kind in PIVOT_BUILDERS:
        pr = verify_pivot(kind)
        results.append(pr)
        os_ok = pr.os_hits >= 0
        ts_ok = pr.ts_ok
        if not ts_ok:
            print(f"[crosspivot-verify] KO {kind} Timesketch explore", file=sys.stderr)
            fails += 1
        elif pr.os_hits < 0:
            print(f"[crosspivot-verify] KO {kind} OpenSearch HTTP", file=sys.stderr)
            fails += 1
        elif pr.os_hits == 0 and kind in ("ioc", "ip"):
            print(f"[crosspivot-verify] WARN {kind} os_hits=0 (requête OK)", file=sys.stderr)
            print(f"[crosspivot-verify] OK {kind} os_hits={pr.os_hits} ts={ts_ok}")
        else:
            print(f"[crosspivot-verify] OK {kind} os_hits={pr.os_hits} ts={ts_ok}")
    from crosspivot_engine import save_state  # noqa: E402

    save_state(results, {"verify": "ok" if fails == 0 else "partial"})
    st = load_state()
    if not st.get("pivots"):
        print("[crosspivot-verify] KO état absent", file=sys.stderr)
        fails += 1
    print(f"[crosspivot-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
