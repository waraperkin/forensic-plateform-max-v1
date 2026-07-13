#!/usr/bin/env python3
"""Apply phase-2 i18n: HTML data-i18n + JS i18n.t() from phase2-string-map.json."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAP_FILE = ROOT / "portal-shared/i18n/phase2-string-map.json"

HTML_TARGETS = [
    ROOT / "portal-cert/public/index.html",
    ROOT / "portal-it/public/index.html",
]

JS_TARGETS = list((ROOT / "portal-shared/js").glob("*.js"))
JS_TARGETS = [p for p in JS_TARGETS if p.name not in ("i18n.js",)]

SKIP_JS_PATTERNS = (
    "i18n.t(",
    "i18nT(",
    "data-i18n",
    "PANEL_COPY",
    "COPY =",
)


def load_map() -> list[dict]:
    return json.loads(MAP_FILE.read_text(encoding="utf-8"))


def apply_html(path: Path, entries: list[dict]) -> int:
    text = path.read_text(encoding="utf-8")
    original = text
    n = 0
    # longest first to avoid partial replacements
    for item in sorted(entries, key=lambda x: -len(x["fr"])):
        fr = item["fr"]
        key = item["key"]
        if fr not in text or f'data-i18n="{key}"' in text:
            continue
        # >text< without existing data-i18n on same tag
        pat = re.compile(
            rf"(>)\s*{re.escape(fr)}\s*(<)",
            re.UNICODE,
        )

        def repl(m, k=key):
            return f'{m.group(1)}<span data-i18n="{k}"></span>{m.group(2)}'

        new_text, c = pat.subn(lambda m: repl(m), text)
        if c:
            text = new_text
            n += c
        # title="fr" / placeholder="fr"
        for attr in ("title", "placeholder", "aria-label"):
            pat2 = re.compile(rf'({attr})="{re.escape(fr)}"')
            text2, c2 = pat2.subn(rf'\1="i18n:{key}" data-i18n-\2="{key}"'.replace(r"\2", attr.split("-")[0] if False else attr), text)
            # simpler:
            text2, c2 = pat2.subn(rf'data-i18n-{attr}="{key}"', text)
            if c2:
                text = text2
                n += c2
    if text != original:
        path.write_text(text, encoding="utf-8")
    return n


def apply_js(path: Path, entries: list[dict]) -> int:
    text = path.read_text(encoding="utf-8")
    if any(s in text for s in SKIP_JS_PATTERNS) and path.name == "i18n.js":
        return 0
    original = text
    n = 0
    for item in sorted(entries, key=lambda x: -len(x["fr"])):
        fr = item["fr"]
        key = item["key"]
        if f"i18n.t('{key}'" in text or f'i18n.t("{key}"' in text:
            continue
        if fr not in text:
            continue
        # skip if inside i18n.t already
        for q in ("'", '"', "`"):
            old = f"{q}{fr}{q}"
            new = f"i18n.t('{key}')"
            if old in text:
                text = text.replace(old, new)
                n += text.count(new) - original.count(new) if False else 1
        # template literal plain text segments `...fr...`
        if f">{fr}<" in text:
            text = text.replace(f">{fr}<", f">${{i18n.t('{key}')}}<")
            n += 1
    if text != original:
        path.write_text(text, encoding="utf-8")
    return n


def main() -> None:
    if not MAP_FILE.is_file():
        print("Run i18n_phase2_catalog.py first")
        raise SystemExit(1)
    entries = load_map()
    total = 0
    for p in HTML_TARGETS:
        if p.is_file():
            c = apply_html(p, entries)
            print(f"HTML {p.name}: {c} replacements")
            total += c
    for p in JS_TARGETS:
        c = apply_js(p, entries)
        if c:
            print(f"JS {p.name}: {c}")
            total += c
    print(f"Done total~{total}")


if __name__ == "__main__":
    main()
