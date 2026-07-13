#!/usr/bin/env python3
"""Phase 1 — Inventaire complet nomenclature FP (anti-régression)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nomenclature_common import INVENTORY_PATH, OFFICIAL_PATH, ROOT as NC_ROOT, load_yaml, utc_stamp  # noqa: E402

ROLLBACK_BASE = NC_ROOT / "backups" / "nomenclature"


def scan_py_constants(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not path.is_file():
        return items
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(
        r'^(DASH_ID|DASH_TITLE|PLAYBOOK_DASH_ID|PLAYBOOK_DASH_TITLE|LAUNCHER_ID|NOTEBOOK_NAME|APP_NAME)\s*=\s*["\']([^"\']+)["\']',
        text,
        re.M,
    ):
        items.append(
            {
                "type": "constant",
                "key": m.group(1),
                "old_name": m.group(2),
                "file": str(path),
            }
        )
    for m in re.finditer(r'_e\(\s*["\']([^"\']+)["\'],\s*["\']([^"\']+)["\']', text):
        items.append(
            {
                "type": "playbook_search",
                "object_id": m.group(1),
                "old_name": m.group(2),
                "file": str(path),
            }
        )
    return items


def scan_ndjson(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not path.is_file():
        return items
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        otype = obj.get("type")
        attrs = obj.get("attributes") or {}
        oid = obj.get("id", "")
        title = attrs.get("title") or attrs.get("name") or ""
        if otype in ("dashboard", "visualization", "search", "index-pattern"):
            items.append(
                {
                    "type": otype,
                    "object_id": oid,
                    "old_name": title,
                    "file": str(path),
                    "rollback_path": str(ROLLBACK_BASE / utc_stamp() / path.relative_to(ROOT)),
                }
            )
    return items


def scan_grafana_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    uid = d.get("uid") or path.stem
    panels = []
    for p in d.get("panels") or []:
        if p.get("title"):
            panels.append({"panel_id": p.get("id"), "old_name": p.get("title")})
    return {
        "type": "grafana_dashboard",
        "object_id": uid,
        "old_name": d.get("title", ""),
        "panels": panels,
        "file": str(path),
        "rollback_path": str(ROLLBACK_BASE / utc_stamp() / path.relative_to(ROOT)),
    }


def build_inventory() -> dict[str, Any]:
    official = load_yaml(OFFICIAL_PATH)
    items: list[dict[str, Any]] = []

    # Python libs
    for pat in (
        "scripts/osd_*_lib.py",
        "scripts/osd_*_playbook_lib.py",
        "scripts/build_*.py",
        "scripts/*_master_lib.py",
    ):
        for path in sorted(ROOT.glob(pat)):
            for it in scan_py_constants(path):
                it["dependencies"] = [it.get("object_id") or it.get("key", "")]
                it["impact_potential"] = "medium" if "DASH_ID" in it.get("key", "") else "low"
                it["rollback_path"] = str(ROLLBACK_BASE / "{stamp}" / path.relative_to(ROOT))
                items.append(it)

    # NDJSON
    for path in sorted((ROOT / "dashboards" / "opensearch").glob("*.ndjson")):
        for it in scan_ndjson(path):
            it["impact_potential"] = "high" if it["type"] == "dashboard" else "medium"
            items.append(it)

    # Grafana
    for path in sorted((ROOT / "dashboards" / "grafana").rglob("*.json")):
        g = scan_grafana_json(path)
        if g:
            g["impact_potential"] = "high"
            items.append(g)

    # Portal
    for portal in ("portal-cert", "portal-it"):
        html = ROOT / portal / "public" / "index.html"
        if html.is_file():
            ht = html.read_text(encoding="utf-8", errors="replace")
            tm = re.search(r"<title>([^<]+)</title>", ht, re.I)
            items.append(
                {
                    "type": "portal_page",
                    "object_id": portal,
                    "old_name": tm.group(1) if tm else portal,
                    "file": str(html),
                    "impact_potential": "medium",
                    "rollback_path": str(ROLLBACK_BASE / "{stamp}" / html.relative_to(ROOT)),
                }
            )

    # QA targets
    try:
        from dashboard_metrics_lib import all_extraction_targets  # noqa: E402

        for t in all_extraction_targets():
            items.append(
                {
                    "type": "qa_target",
                    "object_id": t.target_id,
                    "old_name": t.title,
                    "url": t.url,
                    "file": "scripts/dashboard_metrics_lib.py",
                    "impact_potential": "high",
                    "rollback_path": "scripts/dashboard_metrics_lib.py",
                }
            )
    except Exception as exc:
        items.append({"type": "qa_target", "error": str(exc)})

    # Timesketch libs
    for name in ("timesketch_master_lib.py", "ts_incident_commander_lib.py", "ts_purple_team_lib.py", "ts_cti_fusion_lib.py"):
        p = ROOT / "scripts" / name
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r'["\'](\[FP[^\]]*\][^"\']*|FP-[A-Za-z-]+)["\']', text):
                items.append(
                    {
                        "type": "timesketch_label",
                        "old_name": m.group(1),
                        "file": str(p),
                        "impact_potential": "low",
                        "rollback_path": str(ROLLBACK_BASE / "{stamp}" / p.relative_to(ROOT)),
                    }
                )

    stamp = utc_stamp()
    for it in items:
        rp = it.get("rollback_path", "")
        if "{stamp}" in rp:
            it["rollback_path"] = rp.replace("{stamp}", stamp)

    return {
        "meta": {
            "generated_at": stamp,
            "repo": str(ROOT),
            "item_count": len(items),
            "official_config": str(OFFICIAL_PATH),
            "preserve_ids": True,
        },
        "items": items,
    }


def main() -> int:
    inv = build_inventory()
    INVENTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY_PATH.write_text(json.dumps(inv, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[nomenclature-inventory] OK {len(inv['items'])} éléments → {INVENTORY_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
