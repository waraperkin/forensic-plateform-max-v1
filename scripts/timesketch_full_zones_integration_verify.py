#!/usr/bin/env python3
"""Verify global — intégration 11 zones Timesketch Master."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import STATE_PATH, ZONE_SETUP, load_state, run_zone_verify, sketch_context  # noqa: E402
from timesketch_master_lib import TS_URL, explore, login  # noqa: E402

ZONES = list(ZONE_SETUP.keys())


def main() -> int:
    fails = 0
    st = load_state()
    if not st.get("zones"):
        print("[full-zones] KO état zones absent — lancer timesketch-zones-setup", file=sys.stderr)
        return 1

    for zone in ZONES:
        zst = st.get("zones", {}).get(zone, {})
        if not zst.get("ok"):
            print(f"[full-zones] KO setup zone {zone}", file=sys.stderr)
            fails += 1
            continue
        if run_zone_verify(zone) != 0:
            print(f"[full-zones] KO verify zone {zone}", file=sys.stderr)
            fails += 1
        else:
            print(f"[full-zones] OK {zone}")

    s, h, sid, indices = sketch_context()
    pages = [
        "explore",
        "overview",
        "aggregate",
        "story",
        "intelligence",
    ]
    for p in pages:
        ui = s.get(f"{TS_URL}/sketch/{sid}/{p}/", timeout=35)
        if ui.status_code != 200 or "Server side error" in ui.text:
            print(f"[full-zones] KO UI /{p}/", file=sys.stderr)
            fails += 1

    ex = explore(s, h, sid, {"query_string": "*", "size": 10, "indices": indices[:10]})
    if not ex.get("ok"):
        fails += 1

    from timesketch_zones_lib import list_view_names  # noqa: E402

    vn = len(list_view_names(s, h, sid))
    if vn < 200:
        print(f"[full-zones] KO saved views count={vn}", file=sys.stderr)
        fails += 1

    sub = subprocess.run([sys.executable, str(ROOT / "scripts" / "timesketch_master_ui_verify.py")], cwd=str(ROOT))
    if sub.returncode != 0:
        fails += 1

    if STATE_PATH.is_file():
        rep = ROOT / "docs" / "TIMESKETCH_FULL_ZONES_REPORT.md"
        rep.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Timesketch Full Zones — rapport\n\n",
            f"**Sketch ID:** {sid}\n\n",
            f"**URL:** {TS_URL}/sketch/{sid}/explore/\n\n",
            "## Zones\n\n",
        ]
        for zone in ZONES:
            z = st["zones"].get(zone, {})
            lines.append(f"- **{zone}**: {'OK' if z.get('ok') else 'KO'} — `{json.dumps(z, default=str)[:200]}`\n")
        lines.append(f"\n## Saved views: {vn}\n\n")
        lines.append(f"## Bilan integration: {'OK' if fails == 0 else f'{fails} erreur(s)'}\n")
        rep.write_text("".join(lines), encoding="utf-8")

    print(f"[full-zones] errors={fails} views={vn}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
