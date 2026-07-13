#!/usr/bin/env python3
"""Vérifie l'alignement FP-ECS-LIKE du Timesketch ECS Adapter."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_ecs_adapter import (  # noqa: E402
    CONVERTERS,
    _flat_get,
    ecs_document_validate,
    sample_events,
    to_timesketch_row,
)

REQUIRED = [
    "event.dataset",
    "event.category",
    "event.type",
    "host.name",
    "user.name",
]


def main() -> int:
    failed = 0
    batches = sample_events()
    print(f"[ecs-verify] sources={len(batches)}")
    for src, events in batches.items():
        for i, ev in enumerate(events):
            for f in REQUIRED:
                if not _flat_get(ev, f):
                    print(f"[ecs-verify] KO {src}[{i}] missing {f}", file=sys.stderr)
                    failed += 1
            errs = ecs_document_validate(ev)
            if errs and not src.startswith("ti"):
                for e in errs:
                    if e.startswith("missing:"):
                        print(f"[ecs-verify] KO {src} {e}", file=sys.stderr)
                        failed += 1
            row = to_timesketch_row(ev, {"filename": src})
            if not row.get("datetime") or not row.get("message"):
                print(f"[ecs-verify] KO {src} row invalide", file=sys.stderr)
                failed += 1
            if src in ("ioc", "cti") and "ti" not in row.get("tag", "") and "MISP" not in row.get("tag", ""):
                if "ti" not in row.get("message", ""):
                    print(f"[ecs-verify] WARN {src} tag ti faible", file=sys.stderr)
    for name, fn in CONVERTERS.items():
        if name not in batches:
            print(f"[ecs-verify] KO converter {name} sans échantillon", file=sys.stderr)
            failed += 1
    print(f"[ecs-verify] bilan errors={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
