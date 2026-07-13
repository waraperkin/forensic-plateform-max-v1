#!/usr/bin/env python3
"""Vérifie complétude du rapport d'audit global."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

AUDIT_JSON = Path("/tmp/fp-audit-global.json")
REPORT_MD = ROOT / "docs" / "FP_AUDIT_GLOBAL_REPORT.md"

REQUIRED_SECTIONS = [
    "## 1. Synthèse exécutive",
    "## 2. OpenSearch",
    "## 3. Timesketch",
    "## 4. Grafana",
    "## 5. CTI",
    "## 6. MinIO",
    "## 7. Portails CERT / IT",
    "## 8. SOC Autonomous",
    "## 9. Consolidation",
    "## 10. Docker",
    "## 11. Incohérences",
]

REQUIRED_JSON_KEYS = [
    "opensearch",
    "timesketch",
    "grafana",
    "cti",
    "minio",
    "portals",
    "soc_platform",
    "docker",
    "global_status",
]


def main() -> int:
    ko: list[str] = []

    if not AUDIT_JSON.is_file():
        ko.append(f"JSON absent: {AUDIT_JSON}")
    if not REPORT_MD.is_file():
        ko.append(f"Rapport absent: {REPORT_MD}")

    if REPORT_MD.is_file():
        text = REPORT_MD.read_text(encoding="utf-8")
        if len(text) < 500:
            ko.append("rapport trop court")
        for sec in REQUIRED_SECTIONS:
            if sec not in text:
                ko.append(f"section manquante: {sec}")

    if AUDIT_JSON.is_file():
        data = json.loads(AUDIT_JSON.read_text(encoding="utf-8"))
        for k in REQUIRED_JSON_KEYS:
            if k not in data:
                ko.append(f"clé JSON manquante: {k}")
        if data.get("global_status") == "FAIL":
            ko.append(f"audit global_status=FAIL issues={data.get('issues')}")

    if ko:
        print("[fp-audit-global-verify] KO:", file=sys.stderr)
        for k in ko:
            print(f"  - {k}", file=sys.stderr)
        return 1

    print("[fp-audit-global-verify] OK — rapport complet")
    print(f"[fp-audit-global-verify] {REPORT_MD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
