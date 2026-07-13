#!/usr/bin/env python3
"""Timesketch UI Test Engine — pages sketch, timeline, explore, stories, tags."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import LOG_DIR, MASTER_SKETCH, TS_URL, explore, login  # noqa: E402

UI_PATHS = ("explore", "overview", "story", "aggregate", "intelligence")


def main() -> int:
    failed = 0
    s, h = login()

    home = s.get(f"{TS_URL}/", timeout=25)
    if home.status_code != 200 or "timesketch" not in home.text.lower():
        print("[ui-verify] KO page accueil", file=sys.stderr)
        failed += 1
    else:
        print("[ui-verify] OK UI chargement /")

    login_p = s.get(f"{TS_URL}/login/", timeout=20)
    if login_p.status_code != 200:
        failed += 1

    sid = None
    state_path = LOG_DIR / "timesketch_master_state.json"
    if state_path.is_file():
        sid = json.loads(state_path.read_text(encoding="utf-8")).get("sketch_id")
    if not sid:
        r = s.get(f"{TS_URL}/api/v1/sketches/", headers=h, timeout=20)
        for sk in r.json().get("objects", []):
            if sk.get("name") == MASTER_SKETCH:
                sid = sk["id"]
                break
    if not sid:
        print("[ui-verify] KO sketch Master", file=sys.stderr)
        return 1
    sid = int(sid)

    for path in UI_PATHS:
        url = f"{TS_URL}/sketch/{sid}/{path}/"
        ui = s.get(url, timeout=35)
        if ui.status_code != 200:
            print(f"[ui-verify] KO {path} HTTP {ui.status_code}", file=sys.stderr)
            failed += 1
            continue
        if "Server side error" in ui.text:
            print(f"[ui-verify] KO {path} Server side error", file=sys.stderr)
            failed += 1
            continue
        print(f"[ui-verify] OK {path}")

    ex = explore(s, h, sid, {"query_string": "*", "size": 25, "chronology": True, "order": "asc"})
    if not ex.get("ok"):
        print("[ui-verify] KO timeline chronology", file=sys.stderr)
        failed += 1

    for q in ("tag:dfir", "hostname:*", "user:*", "message:*ti*"):
        pr = explore(s, h, sid, {"query_string": q, "size": 5})
        if not pr.get("ok"):
            print(f"[ui-verify] KO filtre/pivot {q}", file=sys.stderr)
            failed += 1

    stories = s.get(
        f"{TS_URL}/api/v1/sketches/{sid}/stories/",
        headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/story/"},
        timeout=25,
    )
    if stories.status_code != 200 or not stories.json().get("objects"):
        print("[ui-verify] KO stories API", file=sys.stderr)
        failed += 1

    agg = s.post(
        f"{TS_URL}/api/v1/sketches/{sid}/explore/",
        json={"query_string": "*", "size": 0},
        headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/explore/"},
        timeout=40,
    )
    if agg.status_code != 200:
        print("[ui-verify] KO aggregation explore", file=sys.stderr)
        failed += 1

    url_file = LOG_DIR / "timesketch_master_sketch.url"
    url_file.write_text(f"{TS_URL}/sketch/{sid}/explore/\n", encoding="utf-8")
    print(f"[ui-verify] URL={TS_URL}/sketch/{sid}/explore/ errors={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
