#!/usr/bin/env python3
"""UX Analyste Premium — optimise NDJSON (tooltips, refresh, couleurs, requêtes)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NDJSON_DIR = ROOT / "dashboards" / "opensearch"

UX_REFRESH_PAUSE = {"pause": True, "value": 0}
UX_DESCRIPTION = "FP Enterprise UX — storyboard analyste, tooltips enrichis, refresh optimisé"

sys.path.insert(0, str(ROOT / "scripts"))
from osd_enterprise_lib import UX_TOOLTIPS  # noqa: E402


def optimize_dashboard_attrs(attrs: dict, dash_id: str) -> None:
    attrs["description"] = UX_DESCRIPTION
    try:
        opts = json.loads(attrs.get("optionsJSON", "{}"))
    except json.JSONDecodeError:
        opts = {}
    opts["hidePanelTitles"] = False
    opts["useMargins"] = True
    attrs["optionsJSON"] = json.dumps(opts)
    # Réduire refresh auto (performance)
    attrs["refreshInterval"] = UX_REFRESH_PAUSE
    if dash_id in ("fp-ti-overview", "fp-opensearch-security", "fp-threat-hunting", "fp-mitre-dashboard"):
        attrs["timeFrom"] = "now-7d"
        attrs["timeTo"] = "now"


def optimize_visualization(attrs: dict, vid: str) -> None:
    tip = UX_TOOLTIPS.get(vid, "Forensic Platform — analyste SOC")
    attrs["description"] = tip
    try:
        vs = json.loads(attrs.get("visState", "{}"))
    except json.JSONDecodeError:
        return
    params = vs.get("params", {})
    if vs.get("type") == "metric":
        style = params.get("metric", {}).get("style", {})
        style["bgColor"] = False
        style["labelColor"] = True
        style["subText"] = tip[:80]
        params["metric"]["style"] = style
    if vs.get("type") == "pie":
        params["isDonut"] = True
        params["legendPosition"] = "right"
    vs["params"] = params
    attrs["visState"] = json.dumps(vs)


def optimize_search(attrs: dict, sid: str) -> None:
    tip = UX_TOOLTIPS.get(sid, "Drill-down / hunt FP")
    attrs["description"] = tip


def process_ndjson(path: Path) -> int:
    if not path.exists():
        return 0
    lines_out = []
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        otype = obj.get("type")
        oid = obj.get("id", "")
        attrs = obj.get("attributes", {})
        if otype == "dashboard":
            optimize_dashboard_attrs(attrs, oid)
            n += 1
        elif otype == "visualization":
            optimize_visualization(attrs, oid)
            n += 1
        elif otype == "search":
            optimize_search(attrs, oid)
            n += 1
        obj["attributes"] = attrs
        lines_out.append(json.dumps(obj, ensure_ascii=False))
    path.write_text("\n".join(lines_out) + "\n", encoding="utf-8")
    return n


def main() -> int:
    total = 0
    for p in sorted(NDJSON_DIR.glob("*.ndjson")):
        c = process_ndjson(p)
        if c:
            print(f"[ux] OK {p.name} — {c} objets optimisés")
            total += c
    print(f"[ux] OK UX optimize — {total} objets")
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
