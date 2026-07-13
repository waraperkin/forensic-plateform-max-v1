#!/usr/bin/env python3
"""Réapplique la barre 18 playbooks sur tous les dashboards FP (après imports SIEM/drilldown)."""
from __future__ import annotations

import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fp_playbooks_common import patch_all_fp_dashboards  # noqa: E402


def main() -> int:
    s = requests.Session()
    s.verify = False
    fails = patch_all_fp_dashboards(s)
    print(f"[fp-playbooks-bars] Bilan: {fails} échec(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
