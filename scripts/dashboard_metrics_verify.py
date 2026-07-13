#!/usr/bin/env python3
"""Vérification stricte + rapport QA dashboard metrics — validation humaine obligatoire."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dashboard_metrics_lib import (  # noqa: E402
    COMPARE_JSON,
    METRICS_JSON,
    PANELS_JSON,
    REPORT_MD,
    load_metrics_store,
    log,
    utc_now,
)


def build_report(store: dict, compare: dict, panels: dict | None) -> str:
    lines = [
        "# Rapport — Comparaison métriques dashboards",
        "",
        f"**Généré :** {utc_now()}",
        "",
        "> Mode pessimiste : toute incohérence, valeur manquante, panel cassé ou screenshot absent → **FAIL**.",
        "> **Validation humaine requise** avant conclusion « OK ».",
        "",
        "## Synthèse",
        "",
    ]
    summ = compare.get("summary") or {}
    lines.append(f"- Cibles extraites (DOM) : **{summ.get('targets_count', 0)}**")
    lines.append(f"- Règles évaluées : **{summ.get('rules_total', 0)}**")
    lines.append(f"- Règles OK : **{summ.get('rules_passed', 0)}**")
    lines.append(f"- Règles ignorées (optionnel) : **{summ.get('rules_skipped', 0)}**")
    lines.append(f"- Règles FAIL : **{summ.get('rules_failed', 0)}**")
    lines.append(f"- Échecs métriques requises : **{summ.get('required_failures', 0)}**")

    panel_targets = (panels or {}).get("targets") or {}
    panel_fail = [t for t, v in panel_targets.items() if not v.get("check_ok")]
    lines.append(f"- Panels/pages FAIL : **{len(panel_fail)}**")
    lines.append("")

    meta = store.get("meta") or {}
    lines.append("## Extraction")
    lines.append("")
    lines.append(f"- Moteur : `{meta.get('engine', '?')}`")
    lines.append(f"- Date : `{meta.get('extracted_at', '?')}`")
    lines.append(f"- Validation humaine déclarée : **{meta.get('human_validated', False)}**")
    lines.append("")

    lines.append("## Chiffres extraits (DOM)")
    lines.append("")
    lines.append("| Cible | Métrique | Brut | Normalisé | Source |")
    lines.append("|-------|----------|------|-----------|--------|")
    for tid, tgt in sorted((store.get("targets") or {}).items()):
        ok = "✓" if tgt.get("extract_ok") else "✗"
        for mk, mv in sorted((tgt.get("metrics") or {}).items()):
            norm = mv.get("normalized")
            lines.append(
                f"| {ok} `{tid}` | `{mk}` | {mv.get('raw', '—')} | {norm if norm is not None else '**MANQUANT**'} | {mv.get('source', '')} |"
            )
    lines.append("")

    lines.append("## Captures d'écran — métriques")
    lines.append("")
    for tid, tgt in sorted((store.get("targets") or {}).items()):
        shot = tgt.get("screenshot") or ""
        if shot:
            lines.append(f"- `{tid}` : [{Path(shot).name}]({shot})")
        else:
            lines.append(f"- `{tid}` : **MANQUANT**")
    lines.append("")

    if panel_targets:
        lines.append("## Panels / pages blanches")
        lines.append("")
        lines.append("| Cible | Résultat | Issues | Screenshot |")
        lines.append("|-------|----------|--------|------------|")
        for tid, pt in sorted(panel_targets.items()):
            st = "OK" if pt.get("check_ok") else "**FAIL**"
            issues = "; ".join(pt.get("issues") or []) or "—"
            shot = pt.get("screenshot") or ""
            shot_cell = f"[{Path(shot).name}]({shot})" if shot else "**MANQUANT**"
            lines.append(f"| `{tid}` | {st} | {issues} | {shot_cell} |")
        lines.append("")

    lines.append("## Règles de cohérence")
    lines.append("")
    lines.append("| ID | Résultat | Gauche | Op | Droite | Détail |")
    lines.append("|----|----------|--------|----|--------|--------|")
    for r in compare.get("rules") or []:
        st = "SKIP" if r.get("skipped") else ("OK" if r.get("passed") else "**FAIL**")
        lines.append(
            f"| {r.get('id')} | {st} | `{r.get('left')}` = {r.get('left_value')} | {r.get('op')} | "
            f"`{r.get('right')}` = {r.get('right_value')} | {r.get('detail', '')} |"
        )
    lines.append("")

    rf = compare.get("required_failures") or []
    if rf:
        lines.append("## Métriques requises manquantes")
        lines.append("")
        for f in rf:
            lines.append(f"- `{f.get('target', '?')}` / `{f.get('metric', f.get('reason', ''))}` : {f.get('reason')}")
        lines.append("")

    lines.append("## Validation humaine")
    lines.append("")
    lines.append("Cocher après revue manuelle dans le navigateur :")
    lines.append("")
    lines.append("- [ ] Chiffres portail = chiffres Grafana « cumul »")
    lines.append("- [ ] Aucune page blanche / panel cassé")
    lines.append("- [ ] Captures jointes conformes (dashboards + panels)")
    lines.append("- [ ] Divergences acceptées documentées")
    lines.append("")
    lines.append("### Divergences documentées (revue humaine)")
    lines.append("")
    lines.append("| Métrique | Source réelle | Index / API | Fenêtre |")
    lines.append("|----------|---------------|-------------|---------|")
    lines.append("| OSD Security `total_events_24h_siem` | Panel « Total events (24h) » | `fp-events` (pattern SIEM) | Dashboard `now-24h` |")
    lines.append("| Grafana `total_events_siem` | Stat « Events 24h (SIEM) » | `forensic-all` / pattern fp-events | Panel `now-24h` (live count) |")
    lines.append("| OSD Security `total_events` (legacy) | Discover « of N » max | `fp-events` | Fenêtre dashboard (souvent 24h) |")
    lines.append("| Grafana/OSD `events_24h` | `platform_health_lib` | `forensic-*` | Rolling 24h |")
    lines.append("| Grafana/OSD `events_24h_siem` | `platform_health_lib` | `fp-events` | Rolling 24h |")
    lines.append("| Grafana TS `total_events` | Health `explore_events` | API Explore | Instantané |")
    lines.append("| TS Explore `total_events` | DOM UI Explore | Timeline active | Filtre UI |")
    lines.append("| Portail `events_*` | `/api/stats/parsing` | Par index | **Cumul all-time** |")
    lines.append("| TI `total_ioc` | Cardinality `ioc_value` | `forensic-ti-opencti-*` | All-time panel |")
    lines.append("")
    lines.append("- **TS explore vs index timeline** : l'UI Explore affiche un sous-ensemble/agrégat ; Grafana/OSD health `timeline_events` compte les docs OpenSearch des index timeline.")
    lines.append("- **Analyzer runs Grafana vs lignes TS Intelligence** : Grafana = exécutions API sketch ; Intelligence = lignes tableau UI.")
    lines.append("- **Platform Health IOC actifs vs TI uniques** : health = snapshot `ioc_active` ; TI overview = cardinalité uniques index OpenCTI.")
    lines.append("- **R001b** : compare `total_events_24h_siem` (viz dédiée) vs Grafana live count SIEM (tolérance 15 %).")
    lines.append("")
    lines.append("Pour valider programmatiquement (après revue) :")
    lines.append("")
    lines.append("```bash")
    lines.append("export FP_DASHBOARD_METRICS_HUMAN_OK=1")
    lines.append("./forensic.sh dashboard-metrics-verify")
    lines.append("```")
    lines.append("")

    failed = int(summ.get("rules_failed", 0)) + int(summ.get("required_failures", 0)) + len(panel_fail)
    technical_ok = failed == 0
    lines.append("## Verdict")
    lines.append("")
    if not technical_ok:
        lines.append("**FAIL — anomalies techniques** (règles, métriques requises ou panels).")
    elif not meta.get("human_validated"):
        lines.append("**EN ATTENTE — validation humaine obligatoire** (ne pas conclure « OK technique » ni « OK produit »).")
    else:
        lines.append("**PASS après validation humaine** — conserver ce rapport pour audit.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    if not METRICS_JSON.is_file():
        log(f"KO — manquant {METRICS_JSON}")
        return 2
    if not COMPARE_JSON.is_file():
        log(f"KO — manquant {COMPARE_JSON} (lancer dashboard-metrics-compare)")
        return 2
    if not PANELS_JSON.is_file():
        log(f"KO — manquant {PANELS_JSON} (lancer dashboard-panels-check)")
        return 2

    store = load_metrics_store(METRICS_JSON)
    compare = json.loads(COMPARE_JSON.read_text(encoding="utf-8"))
    panels = json.loads(PANELS_JSON.read_text(encoding="utf-8"))

    missing_shots = []
    for tid, tgt in (store.get("targets") or {}).items():
        shot = tgt.get("screenshot") or ""
        if not shot or not Path(shot).is_file():
            missing_shots.append(tid)

    missing_panel_shots = []
    for tid, pt in (panels.get("targets") or {}).items():
        shot = pt.get("screenshot") or ""
        if not shot or not Path(shot).is_file():
            missing_panel_shots.append(tid)

    if missing_shots:
        log(f"KO — screenshot(s) métriques manquant(s): {', '.join(missing_shots)}")
    if missing_panel_shots:
        log(f"KO — screenshot(s) panels manquant(s): {', '.join(missing_panel_shots)}")

    failed_extractions = [t for t, v in (store.get("targets") or {}).items() if not v.get("extract_ok")]
    failed_panels = [t for t, v in (panels.get("targets") or {}).items() if not v.get("check_ok")]
    summ = compare.get("summary") or {}
    human_ok = os.environ.get("FP_DASHBOARD_METRICS_HUMAN_OK", "") == "1"

    report = build_report(store, compare, panels)
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    REPORT_MD.write_text(report, encoding="utf-8")
    log(f"rapport → {REPORT_MD}")

    exit_code = 0
    if missing_shots or missing_panel_shots:
        exit_code = 1
    if failed_extractions:
        log(f"KO — extraction DOM échouée: {', '.join(failed_extractions)}")
        exit_code = 1
    if failed_panels:
        log(f"KO — panels/pages invalides: {', '.join(failed_panels)}")
        exit_code = 1
    if int(summ.get("rules_failed", 0)) > 0 or int(summ.get("required_failures", 0)) > 0:
        log("KO — règles ou métriques requises en échec")
        exit_code = 1
    elif not human_ok:
        log("EN ATTENTE — validation humaine obligatoire (ne pas conclure OK technique/produit)")
        exit_code = 1
    if exit_code == 0:
        log("PASS technique + validation humaine — voir rapport")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
