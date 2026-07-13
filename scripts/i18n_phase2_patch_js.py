#!/usr/bin/env python3
"""Replace French string literals with i18n.t('key') in portal-shared JS."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAP = json.loads((ROOT / "portal-shared/i18n/phase2-string-map.json").read_text(encoding="utf-8"))
JS_DIR = ROOT / "portal-shared/js"
SKIP = {"i18n.js", "portal-lazy.js", "portal-v2-lazy.js", "portal-perf.js", "portal-v2-perf.js"}

# Prefer structured keys over auto msg.*
def key_rank(k: str) -> int:
    if k.startswith("msg."):
        return 10
    return 0


def patch_file(path: Path, entries: list) -> int:
    text = path.read_text(encoding="utf-8")
    orig = text
    n = 0
    sorted_entries = sorted(entries, key=lambda e: (key_rank(e["key"]), -len(e["fr"])))
    for e in sorted_entries:
        fr, key = e["fr"], e["key"]
        if f"i18n.t('{key}'" in text or f'i18n.t("{key}"' in text:
            continue
        if fr not in text:
            continue
        rep = f"i18n.t('{key}')"
        for q in ("'", '"'):
            old = f"{q}{fr}{q}"
            if old in text:
                text = text.replace(old, rep)
                n += 1
        # Template literals: `...fr...` single segment
        if f"`{fr}`" in text:
            text = text.replace(f"`{fr}`", f"`${{{rep[5:-1] if False else ''}}}`")  # skip broken
        if f">${fr}<" in text or f">{fr}<" in text:
            text = text.replace(f">{fr}<", f">${{{rep}}}<")
            n += 1
    if text != orig:
        path.write_text(text, encoding="utf-8")
    return n


def main():
    by_fr = {}
    for e in MAP:
        k = e["key"]
        if k not in by_fr or key_rank(k) < key_rank(by_fr[k]["key"]):
            by_fr[e["fr"]] = e
    entries = list(by_fr.values())
    total = 0
    for path in sorted(JS_DIR.glob("*.js")):
        if path.name in SKIP:
            continue
        c = patch_file(path, entries)
        if c:
            print(f"{path.name}: {c}")
            total += c
    print(f"total replacements logged: {total}")


if __name__ == "__main__":
    main()
