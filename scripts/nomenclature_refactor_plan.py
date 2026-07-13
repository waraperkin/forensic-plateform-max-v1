#!/usr/bin/env python3
"""Phase 2 — Génère config/nomenclature_refactor_plan.yaml depuis inventaire + nomenclature officielle."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_common import (  # noqa: E402
    INVENTORY_PATH,
    OFFICIAL_PATH,
    PLAN_PATH,
    collect_dashboard_title_map,
    collect_old_new_pairs,
    load_yaml,
    save_yaml,
    utc_stamp,
)


def main() -> int:
    official = load_yaml(OFFICIAL_PATH)
    inv: dict[str, Any] = {}
    if INVENTORY_PATH.is_file():
        inv = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    title_map = collect_dashboard_title_map(official)
    pairs = collect_old_new_pairs(official)

    changes: list[dict[str, Any]] = []
    for old, new in pairs:
        changes.append(
            {
                "ancien_nom": old,
                "nouveau_nom": new,
                "justification": "Alignement nomenclature Premium SOC + CERT-FR/ANSSI (titres affichés uniquement)",
                "preserve_id": True,
                "actions": [
                    "Remplacer chaîne dans scripts/*.py et dashboards/*",
                    "Régénérer NDJSON via build_*",
                    "Réimporter saved objects OSD/Grafana",
                ],
                "rollback": f"backups/nomenclature/<stamp>/ + git checkout -- <fichiers>",
            }
        )

    for oid, new_title in title_map.items():
        changes.append(
            {
                "object_id": oid,
                "ancien_nom": "(voir inventaire / NDJSON)",
                "nouveau_nom": new_title,
                "type": "dashboard",
                "justification": f"Catégorie {official.get('osd_security', {}).get(oid, {}).get('category', 'SOC')}",
                "dependencies": ["fp_browser_qa_lib.py", "dashboard_metrics_lib.py", "osd_fp_playbooks_bars_lib.py"],
                "actions": [f'Mettre à jour DASH_TITLE / dashboard("{oid}", ...)', "forensic.sh opensearch-dashboards-build"],
                "rollback": "restaurer backup + rebuild",
            }
        )

    plan = {
        "meta": {
            "version": "1.0.0",
            "generated_at": utc_stamp(),
            "inventory": str(INVENTORY_PATH),
            "anti_regression": {
                "preserve_ids": True,
                "no_index_delete": True,
                "no_data_mutation": True,
                "rollback_on_any_failure": True,
            },
        },
        "string_replacements": [{"ancien_nom": a, "nouveau_nom": b} for a, b in pairs],
        "dashboards": title_map,
        "playbook_patterns": official.get("playbook_title_patterns") or [],
        "portal": {
            "cert": official.get("portal_cert") or {},
            "it": official.get("portal_it") or {},
        },
        "timesketch": official.get("timesketch") or {},
        "changes": changes,
        "verify_commands": [
            "./forensic.sh cluster-repair",
            "./forensic.sh opensearch-dashboards-import",
            "./forensic.sh grafana-master-setup",
            "./forensic.sh dashboard-panels-check",
            "./forensic.sh dashboard-metrics-extract",
            "./forensic.sh dashboard-metrics-compare",
        ],
    }
    save_yaml(PLAN_PATH, plan)
    print(f"[nomenclature-plan] OK → {PLAN_PATH} ({len(changes)} entrées)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
