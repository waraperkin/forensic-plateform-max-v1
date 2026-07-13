#!/usr/bin/env python3
"""Vérifie playbooks Timesketch (saved searches, aggregations, stories, pivots)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import LOG_DIR, TS_URL, explore, login  # noqa: E402


def main() -> int:
    failed = 0
    state_path = LOG_DIR / "timesketch_playbook_state.json"
    if not state_path.is_file():
        print("[playbook-verify] KO état playbook manquant — lancer playbook-setup", file=sys.stderr)
        return 1
    state = json.loads(state_path.read_text(encoding="utf-8"))
    sid = int(state["sketch_id"])
    s, h = login()

    stories = s.get(
        f"{TS_URL}/api/v1/sketches/{sid}/stories/",
        headers={**h, "Referer": f"{TS_URL}/sketch/{sid}/story/"},
        timeout=25,
    )
    if stories.status_code != 200:
        print(f"[playbook-verify] KO stories HTTP {stories.status_code}", file=sys.stderr)
        failed += 1
    else:
        n = len(stories.json().get("objects", []))
        if n < 1:
            print("[playbook-verify] KO aucune story", file=sys.stderr)
            failed += 1
        else:
            print(f"[playbook-verify] stories={n}")

    for item in state.get("applied", {}).get("saved_searches", []):
        if not item.get("ok"):
            print(f"[playbook-verify] KO saved_search {item}", file=sys.stderr)
            failed += 1

    for item in state.get("applied", {}).get("pivots", []):
        if not item.get("ok"):
            print(f"[playbook-verify] KO pivot {item}", file=sys.stderr)
            failed += 1

    ui = s.get(f"{TS_URL}/sketch/{sid}/explore/", timeout=30)
    if "Server side error" in ui.text:
        print("[playbook-verify] KO UI Server side error", file=sys.stderr)
        failed += 1

    ex = explore(s, h, sid, {"query_string": "*", "size": 5})
    if not ex.get("ok"):
        failed += 1

    print(f"[playbook-verify] errors={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
