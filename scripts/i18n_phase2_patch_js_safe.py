#!/usr/bin/env python3
"""Safe JS i18n.t() replacement — whole string literals only."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import argparse

def load_map(phase: str) -> list:
    p2 = ROOT / "portal-shared/i18n/phase2-string-map.json"
    pmap = ROOT / f"portal-shared/i18n/phase{phase}-string-map.json"
    entries: list = []
    if p2.is_file():
        entries.extend(json.loads(p2.read_text(encoding="utf-8")))
    if pmap.is_file() and pmap != p2:
        entries.extend(json.loads(pmap.read_text(encoding="utf-8")))
    return entries
JS_DIRS = [
    ROOT / "portal-shared/js",
    ROOT / "portal-cert/js",
    ROOT / "portal-it/js",
]
SKIP = {"i18n.js"}


def key_rank(k: str) -> int:
    return 10 if k.startswith("msg.") else 0


def patch(text: str, entries: list) -> tuple[str, int]:
    n = 0
    for e in sorted(entries, key=lambda x: (key_rank(x["key"]), -len(x["fr"]))):
        fr, key = e["fr"], e["key"]
        if not fr or len(fr) < 2:
            continue
        rep = f"i18n.t('{key}')"
        if f"i18n.t('{key}'" in text:
            continue
        for q in ("'", '"', "`"):
            old = f"{q}{fr}{q}"
            if old in text:
                text = text.replace(old, rep)
                n += 1
        # Simple HTML wrappers (single-quoted innerHTML)
        for wrapper in (
            (f"<p class=\"fp-muted\">{fr}</p>", f"`<p class=\"fp-muted\">${{i18n.t('{key}')}}</p>`"),
            (f"<p class='fp-muted'>{fr}</p>", f"`<p class='fp-muted'>${{i18n.t('{key}')}}</p>`"),
            (f"<tr><td colspan=\"6\" class=\"fp-table-empty\">{fr}</td></tr>",
             f"`<tr><td colspan=\"6\" class=\"fp-table-empty\">${{i18n.t('{key}')}}</td></tr>`"),
            (f"<tr><td colspan=\"4\" class=\"fp-table-empty\">{fr}</td></tr>",
             f"`<tr><td colspan=\"4\" class=\"fp-table-empty\">${{i18n.t('{key}')}}</td></tr>`"),
        ):
            if wrapper[0] in text and rep not in text:
                text = text.replace(f"'{wrapper[0]}'", wrapper[1])
                text = text.replace(f'"{wrapper[0]}"', wrapper[1])
                n += 1
    return text, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", default="3")
    phase = ap.parse_args().phase
    MAP = load_map(phase)
    by_fr = {}
    for e in MAP:
        if e["fr"] not in by_fr or key_rank(e["key"]) < key_rank(by_fr[e["fr"]]["key"]):
            by_fr[e["fr"]] = e
    entries = list(by_fr.values())
    total = 0
    for js_dir in JS_DIRS:
        if not js_dir.is_dir():
            continue
        for path in sorted(js_dir.glob("*.js")):
            if path.name in SKIP or ".min." in path.name:
                continue
            text, n = patch(path.read_text(encoding="utf-8"), entries)
            if n:
                path.write_text(text, encoding="utf-8")
                print(f"{path.relative_to(ROOT)}: {n}")
                total += n
    print("total", total)


if __name__ == "__main__":
    main()
