#!/usr/bin/env python3
"""Vérifie /tmp/fp-consolidation-status.json — échoue si un seul FAIL."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_consolidation_lib import STATUS_JSON, VERIFY_COMMANDS  # noqa: E402


def main() -> int:
    if not STATUS_JSON.is_file():
        print(f"[fp-consolidation-verify] KO fichier absent: {STATUS_JSON}", file=sys.stderr)
        print("[fp-consolidation-verify] Exécutez: ./forensic.sh fp-consolidation-master", file=sys.stderr)
        return 1

    data = json.loads(STATUS_JSON.read_text(encoding="utf-8"))
    ko: list[str] = []

    if data.get("global_status") != "OK":
        ko.append(f"global_status={data.get('global_status')}")

    mods = data.get("modules", {})
    if mods.get("status") == "FAIL":
        ko.append(f"modules_missing={mods.get('missing')}")

    integ = data.get("integrations", {})
    if integ.get("status") == "FAIL":
        for c in integ.get("checks", []):
            if not c.get("ok"):
                ko.append(f"integration:{c.get('name')}")

    vb = data.get("verify_bundle", {})
    for cmd in VERIFY_COMMANDS:
        r = vb.get("results", {}).get(cmd)
        if not r:
            ko.append(f"verify_missing:{cmd}")
        elif not r.get("ok"):
            ko.append(f"verify_fail:{cmd}")

    if vb.get("verify_fails", 0) > 0:
        ko.append(f"verify_fails={vb.get('verify_fails')}")

    if ko:
        print("[fp-consolidation-verify] KO:", file=sys.stderr)
        for k in ko:
            print(f"  - {k}", file=sys.stderr)
        return 1

    print("[fp-consolidation-verify] OK — consolidation 0 erreur")
    print(f"[fp-consolidation-verify] status={STATUS_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
