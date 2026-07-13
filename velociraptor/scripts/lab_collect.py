#!/usr/bin/env python3
"""Simulateur lab — génère artefacts JSON/CSV offline et pousse vers le bridge Velociraptor."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "export"))

import requests

from lab_simulator import (  # noqa: E402
    FORENSIC_FULL_ARTIFACTS,
    PLAYBOOKS,
    list_artifacts,
    simulate_collect,
    simulate_playbook,
)


def push_bridge(url: str, path: str, body: dict) -> dict:
    r = requests.post(f"{url.rstrip('/')}{path}", json=body, timeout=300)
    r.raise_for_status()
    return r.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Collecteur offline Velociraptor (lab)")
    parser.add_argument("--case-id", default=os.environ.get("CASE_ID", "LAB-OFFLINE"))
    parser.add_argument("--artifact", choices=FORENSIC_FULL_ARTIFACTS)
    parser.add_argument("--playbook", choices=list(PLAYBOOKS.keys()))
    parser.add_argument("--list", action="store_true", help="Lister artefacts et playbooks")
    parser.add_argument("--bridge", default=os.environ.get("VR_BRIDGE_URL", "http://127.0.0.1:8097"))
    parser.add_argument("--no-export", action="store_true")
    parser.add_argument("--local-only", action="store_true", help="Ne pas appeler le bridge HTTP")
    args = parser.parse_args()

    if args.list:
        print(json.dumps(list_artifacts(), indent=2, ensure_ascii=False))
        return 0

    auto_export = not args.no_export

    if args.playbook:
        if args.local_only:
            result = simulate_playbook(args.playbook, case_id=args.case_id, auto_export=auto_export)
        else:
            result = push_bridge(args.bridge, "/lab/collect-full", {
                "playbook": args.playbook,
                "case_id": args.case_id,
                "auto_export": auto_export,
            })
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("ok") else 1

    artifact = args.artifact or FORENSIC_FULL_ARTIFACTS[0]
    if args.local_only:
        result = simulate_collect(artifact, case_id=args.case_id, auto_export=auto_export)
    else:
        result = push_bridge(args.bridge, "/lab/collect", {
            "artifact": artifact,
            "case_id": args.case_id,
            "auto_export": auto_export,
        })
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
