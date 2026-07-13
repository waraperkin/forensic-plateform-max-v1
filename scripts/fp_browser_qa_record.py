#!/usr/bin/env python3
"""Enregistre une étape QA depuis le navigateur Cursor (CLI pour l'agent)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from fp_browser_qa_lib import BROWSER_RESULTS, utc_now  # noqa: E402

CURSOR_OUT = Path("/tmp/fp-ui-browser-qa-results.json")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="")
    ap.add_argument("--ok", type=int, choices=(0, 1), default=None)
    ap.add_argument("--detail", default="")
    ap.add_argument("--url", default="")
    ap.add_argument("--actions", default="")
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()

    if args.reset or not CURSOR_OUT.is_file():
        data = {"updated_at": utc_now(), "engine": "cursor_mcp", "steps": []}
        CURSOR_OUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
        BROWSER_RESULTS.write_text(json.dumps(data, indent=2), encoding="utf-8")
        if args.reset and args.ok is None:
            print("reset OK")
            return 0

    data = json.loads(CURSOR_OUT.read_text(encoding="utf-8"))
    if args.ok is None:
        print("specify --ok 0|1", file=sys.stderr)
        return 2

    data["steps"].append(
        {
            "name": args.name,
            "ok": bool(args.ok),
            "detail": args.detail,
            "url": args.url,
            "actions": args.actions.split(",") if args.actions else [],
            "at": utc_now(),
        }
    )
    fails = sum(1 for s in data["steps"] if not s.get("ok"))
    data["error_count"] = fails
    data["total_steps"] = len(data["steps"])
    data["global_status"] = "OK" if fails == 0 else "FAIL"
    data["updated_at"] = utc_now()

    CURSOR_OUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    BROWSER_RESULTS.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"recorded {args.name} ok={args.ok}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
