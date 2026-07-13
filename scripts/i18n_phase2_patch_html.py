#!/usr/bin/env python3
"""Add data-i18n to HTML elements with known French text (additive)."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAP = json.loads((ROOT / "portal-shared/i18n/phase2-string-map.json").read_text(encoding="utf-8"))
HTML_FILES = [
    ROOT / "portal-cert/public/index.html",
    ROOT / "portal-it/public/index.html",
]


def main() -> None:
    by_fr = {e["fr"]: e["key"] for e in MAP}
    total = 0
    for path in HTML_FILES:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        orig = text
        for fr in sorted(by_fr, key=len, reverse=True):
            key = by_fr[fr]
            if f'data-i18n="{key}"' in text:
                continue
            # h2.fp-section-title
            pat = re.compile(
                rf'(<h2\s+class="fp-section-title")(\s*>)\s*{re.escape(fr)}\s*(</h2>)',
                re.I,
            )
            text, n = pat.subn(rf'\1 data-i18n="{key}"\2{fr}\3', text)
            total += n
            # p.fp-muted
            pat2 = re.compile(
                rf'(<p\s+class="fp-muted")(\s*>)\s*{re.escape(fr)}\s*(</p>)',
                re.I,
            )
            text, n2 = pat2.subn(rf'\1 data-i18n="{key}"\2{fr}\3', text)
            total += n2
            # title attribute
            pat3 = re.compile(
                rf'(\btitle\s*=\s*"){re.escape(fr)}(")',
                re.I,
            )
            text, n3 = pat3.subn(rf'\1{fr}\2 data-i18n-title="{key}"', text)
            total += n3
        if text != orig:
            path.write_text(text, encoding="utf-8")
            print(f"{path.relative_to(ROOT)}: patched")
    print("total attrs", total)


if __name__ == "__main__":
    main()
