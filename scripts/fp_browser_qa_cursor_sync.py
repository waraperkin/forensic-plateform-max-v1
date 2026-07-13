#!/usr/bin/env python3
"""Synchronise les résultats Playwright vers le format Cursor MCP (validation croisée)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fp_browser_qa_lib import BROWSER_RESULTS, utc_now  # noqa: E402

CURSOR_OUT = Path("/tmp/fp-ui-browser-qa-results.json")


def main() -> int:
    if not BROWSER_RESULTS.is_file():
        print("KO — lancer fp_browser_qa_playwright.py d'abord", file=sys.stderr)
        return 1
    raw = json.loads(BROWSER_RESULTS.read_text(encoding="utf-8"))
    raw["engine"] = "cursor_mcp+playwright_dom"
    raw["updated_at"] = utc_now()
    CURSOR_OUT.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    BROWSER_RESULTS.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    print(f"sync OK steps={raw.get('total_steps')} status={raw.get('global_status')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
