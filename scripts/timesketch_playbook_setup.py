#!/usr/bin/env python3
"""Timesketch Playbook Engine — saved searches, views, stories, pivots (DFIR/SOC/CTI)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_master_lib import (  # noqa: E402
    CONFIG_DIR,
    DASHBOARD_PACK_JSON,
    LOG_DIR,
    PLAYBOOKS_JSON,
    explore,
    login,
    write_sketch_url,
)

TS = __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")


def load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def create_story(session, headers: dict, sketch_id: int, title: str) -> bool:
    h = {**headers, "Referer": f"{TS}/sketch/{sketch_id}/story/"}
    r = session.post(
        f"{TS}/api/v1/sketches/{sketch_id}/stories/",
        json={"title": title, "components": []},
        headers={**h, "Content-Type": "application/json"},
        timeout=30,
    )
    return r.status_code in (200, 201)


def apply_labels(session, headers: dict, sketch_id: int, labels: list[str]) -> bool:
    """Labels sketch via API attribute (ontology label, name=labels)."""
    if not labels:
        return True
    h = {**headers, "Referer": f"{TS}/sketch/{sketch_id}/"}
    r = session.post(
        f"{TS}/api/v1/sketches/{sketch_id}/attribute/",
        json={
            "name": "labels",
            "values": labels,
            "ontology": "label",
            "action": "post",
        },
        headers={**h, "Content-Type": "application/json"},
        timeout=25,
    )
    return r.status_code in (200, 201)


def main() -> int:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    playbooks = load_json(PLAYBOOKS_JSON)
    pack = load_json(DASHBOARD_PACK_JSON)
    if not playbooks:
        print("[playbook-setup] KO playbooks.json manquant", file=sys.stderr)
        return 1

    s, h = login()
    state_path = LOG_DIR / "timesketch_master_state.json"
    sid = None
    if state_path.is_file():
        sid = json.loads(state_path.read_text(encoding="utf-8")).get("sketch_id")
    if not sid:
        name = playbooks.get("sketch", "[FP] Timesketch Master")
        page = 1
        while True:
            r = s.get(f"{TS}/api/v1/sketches/", params={"page": page}, headers=h, timeout=20)
            for sk in r.json().get("objects", []):
                if sk.get("name") == name:
                    sid = sk["id"]
                    break
            meta = r.json().get("meta") or {}
            if sid or not meta.get("has_next"):
                break
            page = int(meta.get("next_page") or page + 1)
    if not sid:
        print("[playbook-setup] KO sketch introuvable", file=sys.stderr)
        return 1
    sid = int(sid)

    det = s.get(f"{TS}/api/v1/sketches/{sid}/", headers={**h, "Referer": f"{TS}/sketch/{sid}/"}, timeout=25).json()
    indices = [
        (tl.get("searchindex") or {}).get("index_name", "")
        for tl in det.get("objects", [{}])[0].get("timelines", [])
        if (tl.get("searchindex") or {}).get("index_name")
    ]

    applied: dict[str, list] = {"saved_searches": [], "aggregations": [], "stories": [], "labels": [], "pivots": []}

    for view in playbooks.get("views", []):
        q = view.get("query", "*")
        ex = explore(s, h, sid, {"query_string": q, "size": 1, "indices": indices[:6]})
        applied["saved_searches"].append({"name": view["name"], "ok": ex.get("ok", False)})

    for role_id, role in playbooks.get("roles", {}).items():
        for ss in role.get("saved_searches", []):
            ex = explore(s, h, sid, {"query_string": ss["query"], "size": 3, "indices": indices[:6]})
            applied["saved_searches"].append({"role": role_id, "name": ss["name"], "ok": ex.get("ok", False)})
        for agg in role.get("aggregations", []):
            ex = explore(
                s,
                h,
                sid,
                {"query_string": agg.get("query", "*"), "size": 0, "indices": indices[:4]},
            )
            applied["aggregations"].append({"role": role_id, "name": agg["name"], "ok": ex.get("ok", False)})
        for pivot in role.get("pivots", []):
            field, _, val = pivot.partition(":")
            q = f"{field}:{val}" if val else pivot
            ex = explore(s, h, sid, {"query_string": q, "size": 5, "indices": indices[:4]})
            applied["pivots"].append({"role": role_id, "query": q, "ok": ex.get("ok", False)})
        for story_title in role.get("stories", []):
            ok = create_story(s, h, sid, f"[FP] {role['title']} — {story_title}")
            applied["stories"].append({"title": story_title, "ok": ok})

    for ss in pack.get("saved_searches", []):
        ex = explore(s, h, sid, {"query_string": ss["query"], "size": 3, "indices": indices[:6]})
        applied["saved_searches"].append({"pack": ss["id"], "ok": ex.get("ok", False)})

    pack_labels = pack.get("labels", [])
    ok_labels = apply_labels(s, h, sid, pack_labels)
    for label in pack_labels:
        applied["labels"].append({"label": label, "ok": ok_labels})

    for title in ("DFIR Senior Playbook", "SOC Manager Overview", "Threat Hunting CTI"):
        ok = create_story(s, h, sid, f"[FP] {title}")
        applied["stories"].append({"title": title, "ok": ok})

    out = LOG_DIR / "timesketch_playbook_state.json"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"sketch_id": sid, "applied": applied}, indent=2), encoding="utf-8")
    write_sketch_url(sid)

    ko = sum(
        1
        for section in applied.values()
        for item in section
        if isinstance(item, dict) and not item.get("ok", True)
    )
    print(f"[playbook-setup] sketch={sid} ko_checks={ko}")
    return 0 if ko == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
