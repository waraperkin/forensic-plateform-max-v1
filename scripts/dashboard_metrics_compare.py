#!/usr/bin/env python3
"""Compare les métriques extraites (DOM) aux règles de cohérence — une incohérence = FAIL."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dashboard_metrics_lib import (  # noqa: E402
    COMPARE_JSON,
    METRICS_JSON,
    check_required_metrics,
    eval_rule,
    load_metrics_store,
    load_relations,
    log,
    utc_now,
)


def main() -> int:
    relations = load_relations()
    store = load_metrics_store(METRICS_JSON)
    if not store.get("targets"):
        log(f"KO — {METRICS_JSON} absent ou vide (lancer dashboard-metrics-extract)")
        return 2

    default_tol = float((relations.get("meta") or {}).get("default_tolerance_pct", 2.0))
    rules = relations.get("rules") or []
    required_failures = check_required_metrics(store, relations)

    rule_results = []
    failed_rules = 0
    skipped_rules = 0
    for rule in rules:
        r = eval_rule(store, rule, default_tol)
        rule_results.append(r)
        if r.get("skipped"):
            skipped_rules += 1
        elif not r.get("passed"):
            failed_rules += 1
            log(f"FAIL {r['id']}: {r.get('detail')}")

    compare = {
        "meta": {
            "compared_at": utc_now(),
            "pessimistic": True,
            "human_validation_required": True,
            "metrics_source": str(METRICS_JSON),
            "rules_source": str(ROOT / "config" / "dashboard_expected_relations.yaml"),
        },
        "summary": {
            "targets_count": len(store.get("targets") or {}),
            "rules_total": len(rules),
            "rules_failed": failed_rules,
            "rules_skipped": skipped_rules,
            "rules_passed": len(rules) - failed_rules - skipped_rules,
            "required_failures": len(required_failures),
        },
        "required_failures": required_failures,
        "rules": rule_results,
    }

    COMPARE_JSON.parent.mkdir(parents=True, exist_ok=True)
    COMPARE_JSON.write_text(json.dumps(compare, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log(f"écrit {COMPARE_JSON}")

    if required_failures:
        log(f"KO — {len(required_failures)} échec(s) métriques requises")
        for f in required_failures[:10]:
            log(f"  → {f}")
        return 1

    if failed_rules:
        log(f"KO — {failed_rules} règle(s) violée(s) sur {len(rules)}")
        return 1

    log(f"comparaison: {compare['summary']['rules_passed']} règles OK, {skipped_rules} skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
