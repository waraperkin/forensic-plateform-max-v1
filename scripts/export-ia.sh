#!/usr/bin/env bash
# Export Intelligence SOC 2.0 — incidents, corrélations, recommandations, anomalies, règles générées.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CERT_URL="${CERT_PORTAL_URL:-http://localhost:3000}"
OUT_DIR="${OUT_DIR:-$ROOT/release/exports}"
TS="$(date +%Y%m%d-%H%M%S)"
WORK="$OUT_DIR/ia-export-${TS}"
ZIP_NAME="cybercorp-ia-export-${TS}.zip"

log() { echo "[export-ia] $*"; }

mkdir -p "$WORK"
log "Export IA vers $WORK"

export CERT_PORTAL_URL="$CERT_URL"
export PYTHONPATH="$ROOT/scripts"
export WORK="$WORK"

python3 <<'PY'
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("PYTHONPATH", "."))
from portal_cert_master_lib import cert_login_session

work = Path(os.environ["WORK"])
cert_url = os.environ["CERT_PORTAL_URL"].rstrip("/")
s = cert_login_session(force=True)
s.verify = False


def get(path):
    r = s.get(f"{cert_url}{path}", timeout=120)
    body = r.json() if r.text.strip() else {}
    return {"status": r.status_code, "body": body}


def items(resp):
    b = resp.get("body") or {}
    if isinstance(b.get("items"), list):
        return b["items"]
    return b if isinstance(b, list) else []


def detect_anomalies(rules, intakes, connectors):
    out = []
    for r in rules:
        name = str(r.get("name") or r.get("uuid") or "")
        enabled = r.get("enabled") is not False and r.get("status") != "disabled"
        blob = json.dumps(r)
        if enabled and re.search(r"allow\s*all|any\s*any", blob, re.I):
            out.append({
                "type": "rule",
                "severity": "high",
                "title": "Règle potentiellement trop permissive",
                "detail": name,
                "score": 78,
            })
        if enabled and re.search(r"test|debug|sample", name, re.I):
            out.append({
                "type": "rule",
                "severity": "medium",
                "title": "Règle de test active",
                "detail": name,
                "score": 55,
            })
    for i in intakes:
        if not i.get("format_uuid") and not i.get("dialect_uuid"):
            out.append({
                "type": "intake",
                "severity": "medium",
                "title": "Intake sans format",
                "detail": i.get("name") or i.get("uuid"),
                "score": 50,
            })
    for c in connectors:
        if c.get("status") == "error" or c.get("health") == "down":
            out.append({
                "type": "connector",
                "severity": "high",
                "title": "Connecteur en erreur",
                "detail": c.get("name") or "",
                "score": 70,
            })
    return sorted(out, key=lambda x: -x.get("score", 0))


def build_incidents(anomalies, rules):
    inc = []
    for a in anomalies:
        if a.get("severity") == "high":
            inc.append({
                "priority": a.get("score", 70),
                "title": a.get("title"),
                "source": a.get("type"),
                "status": "open",
                "summary": a.get("detail"),
            })
    for r in rules[:20]:
        name = str(r.get("name") or "")
        if re.search(r"failed|brute|malware|ransom|powershell", name, re.I):
            inc.append({
                "priority": 65,
                "title": f"Signal détection : {name[:48]}",
                "source": "sekoia-rule",
                "status": "triaged",
                "summary": "Corrélation automatique",
            })
    return sorted(inc, key=lambda x: -x.get("priority", 0))[:40]


def recommendations(anomalies, intakes, rules):
    sug = []
    if any("permissive" in a.get("title", "").lower() for a in anomalies):
        sug.append({
            "priority": "high",
            "message": "Vous devriez vérifier les règles marquées comme trop permissives.",
        })
    if len(intakes) > 20:
        sug.append({
            "priority": "normal",
            "message": "Vous devriez vérifier les intakes inactifs ou sans format.",
        })
    if len(rules) > 100:
        sug.append({
            "priority": "normal",
            "message": "Cette règle semble trop permissive ou bruyante — revue tuning recommandée.",
        })
    if not sug:
        sug.append({"priority": "low", "message": "Aucune alerte critique détectée."})
    return sug


def build_correlations(intakes, rules, modules):
    nodes, edges = [], []
    for i in intakes[:40]:
        nid = f"intake:{i.get('uuid') or i.get('id')}"
        nodes.append({"id": nid, "name": str(i.get("name") or "intake")[:32]})
        fmt = i.get("format_uuid") or i.get("dialect_uuid")
        if fmt:
            fid = f"fmt:{fmt}"
            nodes.append({"id": fid, "name": str(fmt)[:20]})
            edges.append({"source": nid, "target": fid})
    for r in rules[:35]:
        rid = f"rule:{r.get('uuid') or r.get('name')}"
        nodes.append({"id": rid, "name": str(r.get("name") or "rule")[:28]})
    for m in modules[:20]:
        nodes.append({"id": f"mod:{m.get('uuid')}", "name": str(m.get("name") or "mod")[:24]})
    return {"nodes": nodes, "edges": edges, "pivots": [
        "Pivot intake → events on-demand",
        "Pivot rule → Telemetry",
        "Cross-check SentinelOne endpoints",
    ]}


def generated_rules(incidents):
    out = []
    for inc in incidents[:5]:
        title = inc.get("title") or "Detection"
        out.append({
            "title": f"IA — {title[:40]}",
            "yaml": f"title: IA Auto — {title[:60]}\nstatus: experimental\ndetection:\n  condition: selection\n  selection: event.action:failure\n",
            "from_incident": inc.get("title"),
        })
    return out


rules = items(get("/api/threat/sekoia/rules?v2_nocache=1"))
intakes = items(get("/api/threat/sekoia/intakes?v2_nocache=1"))
connectors = items(get("/api/threat/sekoia/connectors?v2_nocache=1"))
modules = items(get("/api/threat/sekoia/modules?v2_nocache=1"))
s1_eps = items(get("/api/threat/s1/endpoints?v2_nocache=1"))

anomalies = detect_anomalies(rules, intakes, connectors)
incidents = build_incidents(anomalies, rules)
recs = recommendations(anomalies, intakes, rules)
corr = build_correlations(intakes, rules, modules)
gen_rules = generated_rules(incidents)

bundle = {
    "version": "2.0",
    "exported_at": datetime.now(timezone.utc).isoformat(),
    "portal": cert_url,
    "incidents_ia": incidents,
    "anomalies_ia": anomalies,
    "recommendations_ia": recs,
    "correlations_ia": corr,
    "generated_rules_ia": gen_rules,
    "stats": {
        "rules": len(rules),
        "intakes": len(intakes),
        "s1_endpoints": len(s1_eps),
        "anomalies": len(anomalies),
        "incidents": len(incidents),
    },
}

(work / "ia_incidents.json").write_text(json.dumps(incidents, indent=2, ensure_ascii=False), encoding="utf-8")
(work / "ia_anomalies.json").write_text(json.dumps(anomalies, indent=2, ensure_ascii=False), encoding="utf-8")
(work / "ia_recommendations.json").write_text(json.dumps(recs, indent=2, ensure_ascii=False), encoding="utf-8")
(work / "ia_correlations.json").write_text(json.dumps(corr, indent=2, ensure_ascii=False), encoding="utf-8")
(work / "ia_generated_rules.json").write_text(json.dumps(gen_rules, indent=2, ensure_ascii=False), encoding="utf-8")
(work / "ia_bundle.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
(work / "manifest.json").write_text(json.dumps({
    "exported_at": bundle["exported_at"],
    "files": [
        "ia_incidents.json",
        "ia_anomalies.json",
        "ia_recommendations.json",
        "ia_correlations.json",
        "ia_generated_rules.json",
        "ia_bundle.json",
    ],
}, indent=2), encoding="utf-8")
print(f"[export-ia] {len(incidents)} incidents, {len(anomalies)} anomalies")
PY

(
  cd "$OUT_DIR"
  zip -qr "$ZIP_NAME" "$(basename "$WORK")"
)
log "Archive : $OUT_DIR/$ZIP_NAME"
log "Dossier : $WORK"
