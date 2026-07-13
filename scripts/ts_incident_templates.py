#!/usr/bin/env python3
"""Templates de recherche IR — phases + incident complet."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_zones_lib import ZONES_DIR, create_saved_view, explore, sketch_context  # noqa: E402

TEMPLATES = [
    ("[FP-IR-Tpl] Detection", "message:*ir.phase=detection*"),
    ("[FP-IR-Tpl] Containment", "message:*ir.phase=containment*"),
    ("[FP-IR-Tpl] Eradication", "message:*ir.phase=eradication*"),
    ("[FP-IR-Tpl] Recovery", "message:*ir.phase=recovery*"),
    ("[FP-IR-Tpl] Full Incident", "tag:ir OR message:*ir.phase*"),
]

YAML_NAME = "search_templates_incident_fp.yaml"


def main() -> int:
    ZONES_DIR.mkdir(parents=True, exist_ok=True)
    lines = ["---\n"]
    for i, (name, q) in enumerate(TEMPLATES):
        lines.append(f"fp_ir_template_{i}:\n  query_string: '{q}'\n  short_name: '{name}'\n")
    (ZONES_DIR / YAML_NAME).write_text("".join(lines), encoding="utf-8")

    s, h, sid, indices = sketch_context()
    ok = 0
    for name, q in TEMPLATES:
        if create_saved_view(s, h, sid, name, q, indices, f"IR template — {name}"):
            ok += 1
        ex = explore(s, h, sid, {"query_string": q, "size": 2, "indices": indices[:8]})
        if not ex.get("ok"):
            print(f"[ts-incident-tpl] WARN {name}", file=sys.stderr)

    try:
        subprocess.run(
            ["docker", "cp", str(ZONES_DIR / YAML_NAME), "forensic-timesketch-web:/etc/timesketch/search_templates_incident_fp.yaml"],
            check=True,
            timeout=30,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print(f"[ts-incident-tpl] created={ok}/{len(TEMPLATES)}")
    return 0 if ok >= len(TEMPLATES) else 1


if __name__ == "__main__":
    sys.exit(main())
