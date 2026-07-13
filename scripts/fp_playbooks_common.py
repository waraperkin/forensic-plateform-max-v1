#!/usr/bin/env python3
"""Utilitaires communs — import, patch barres, notebook, application Observability."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import requests
from fp_runtime_env import OSD_URL

ROOT = Path(__file__).resolve().parent.parent
OSD = OSD_URL


def hdrs() -> dict[str, str]:
    return {"osd-xsrf": "true", "Content-Type": "application/json", "securitytenant": "global"}


def run_cmd(cmd: list[str], label: str) -> bool:
    r = subprocess.run(cmd, cwd=str(ROOT), timeout=900)
    if r.returncode != 0:
        print(f"[fp-playbooks] KO {label}", file=sys.stderr)
        return False
    print(f"[fp-playbooks] OK {label}")
    return True


def import_ndjson(ndjson_path: Path) -> bool:
    if not ndjson_path.is_file():
        print(f"[fp-playbooks] KO fichier absent: {ndjson_path}", file=sys.stderr)
        return False
    import urllib3
    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False
    with ndjson_path.open("rb") as fh:
        r = s.post(
            f"{OSD}/api/saved_objects/_import?overwrite=true",
            headers={"osd-xsrf": "true", "securitytenant": "global"},
            files={"file": (ndjson_path.name, fh, "application/ndjson")},
            timeout=120,
        )
    if r.status_code != 200:
        print(f"[fp-playbooks] KO import HTTP {r.status_code}: {r.text[:300]}", file=sys.stderr)
        return False
    data = r.json()
    if data.get("successCount", 0) < 1:
        print(f"[fp-playbooks] KO import 0 objects", file=sys.stderr)
        return False
    print(f"[fp-playbooks] OK import {data.get('successCount')} objects from {ndjson_path.name}")
    return True


def ensure_launcher_searches(s: requests.Session) -> int:
    """Crée les 18 launchers si absents (barre playbooks FP)."""
    from osd_drilldown_lib import saved_search_attrs  # noqa: E402
    from osd_analyst_playbook_lib import PLAYBOOK_LAUNCHER  # noqa: E402
    from osd_soc_manager_playbook_lib import LAUNCHER as SM_LAUNCHER  # noqa: E402
    from osd_incident_commander_playbook_lib import LAUNCHER as IC_LAUNCHER  # noqa: E402
    from osd_soc_director_playbook_lib import LAUNCHER as SD_LAUNCHER  # noqa: E402
    from osd_ti_lead_playbook_lib import LAUNCHER as TL_LAUNCHER  # noqa: E402
    from osd_dfir_senior_playbook_lib import LAUNCHER as DFIR_LAUNCHER  # noqa: E402
    from osd_purple_team_playbook_lib import LAUNCHER as PT_LAUNCHER  # noqa: E402
    from osd_threat_hunting_lead_playbook_lib import LAUNCHER as THL_LAUNCHER  # noqa: E402
    from osd_soc_automation_playbook_lib import LAUNCHER as SOCA_LAUNCHER  # noqa: E402
    from osd_cti_fusion_playbook_lib import LAUNCHER as CTF_LAUNCHER  # noqa: E402
    from osd_global_soc_command_center_lib import LAUNCHER as GSCC_LAUNCHER  # noqa: E402
    from osd_cyber_crisis_management_lib import LAUNCHER as CCM_LAUNCHER  # noqa: E402
    from osd_nation_state_cti_playbook_lib import LAUNCHER as NSC_LAUNCHER  # noqa: E402
    from osd_autonomous_soc_playbook_lib import LAUNCHER as ASOC_LAUNCHER  # noqa: E402
    from osd_soc_director_executive_playbook_lib import LAUNCHER as SDE_LAUNCHER  # noqa: E402
    from osd_red_team_lead_playbook_lib import LAUNCHER as RTL_LAUNCHER  # noqa: E402
    from osd_blue_team_lead_playbook_lib import LAUNCHER as BTL_LAUNCHER  # noqa: E402
    from osd_cti_fusion_global_playbook_lib import LAUNCHER as CTFG_LAUNCHER  # noqa: E402

    fails = 0
    for entry in (
        PLAYBOOK_LAUNCHER, SM_LAUNCHER, IC_LAUNCHER, SD_LAUNCHER, TL_LAUNCHER, DFIR_LAUNCHER,
        PT_LAUNCHER, THL_LAUNCHER, SOCA_LAUNCHER, CTF_LAUNCHER,
        GSCC_LAUNCHER, CCM_LAUNCHER, NSC_LAUNCHER, ASOC_LAUNCHER,
        SDE_LAUNCHER, RTL_LAUNCHER, BTL_LAUNCHER, CTFG_LAUNCHER,
    ):
        sid, title, idx, q, cols, desc = entry
        r = s.get(f"{OSD}/api/saved_objects/search/{sid}", headers=hdrs(), timeout=15)
        if r.status_code == 200:
            continue
        attrs, refs = saved_search_attrs(sid, title, idx, q, cols)
        attrs["description"] = desc
        pr = s.post(
            f"{OSD}/api/saved_objects/search/{sid}",
            json={"attributes": attrs, "references": refs},
            headers=hdrs(),
            timeout=30,
        )
        if pr.status_code not in (200, 201):
            print(f"[fp-playbooks] KO launcher {sid} HTTP {pr.status_code}", file=sys.stderr)
            fails += 1
        else:
            print(f"[fp-playbooks] OK launcher {sid}")
    return fails


def patch_all_fp_dashboards(s: requests.Session) -> int:
    from osd_fp_playbooks_bars_lib import FP_DASHBOARDS_ALL, inject_fp_playbooks_bar  # noqa: E402

    fails = ensure_launcher_searches(s)
    for dash_id in FP_DASHBOARDS_ALL:
        r = s.get(f"{OSD}/api/saved_objects/dashboard/{dash_id}", headers=hdrs(), timeout=30)
        if r.status_code != 200:
            print(f"[fp-playbooks] skip {dash_id} HTTP {r.status_code}")
            continue
        body = r.json()
        attrs = body["attributes"]
        panels = json.loads(attrs["panelsJSON"])
        new_panels, new_refs = inject_fp_playbooks_bar(panels)
        if new_panels == panels:
            continue
        attrs["panelsJSON"] = json.dumps(new_panels)
        refs = body.get("references") or []
        for ref in new_refs:
            if not any(x.get("name") == ref["name"] for x in refs):
                refs.append(ref)
        pr = s.put(
            f"{OSD}/api/saved_objects/dashboard/{dash_id}",
            json={"attributes": attrs, "references": refs},
            headers=hdrs(),
            timeout=60,
        )
        if pr.status_code not in (200, 201):
            print(f"[fp-playbooks] KO patch {dash_id}", file=sys.stderr)
            fails += 1
        else:
            print(f"[fp-playbooks] OK barre 18 playbooks: {dash_id}")
    return fails


def ensure_observability_app(s: requests.Session, app_name: str, description: str, base_query: str) -> int:
    r = s.get(f"{OSD}/api/observability/application/", headers=hdrs(), timeout=20)
    if r.status_code != 200:
        return 0
    if any(app_name in (a.get("name") or "") for a in (r.json().get("data") or [])):
        print(f"[fp-playbooks] OK app '{app_name}' déjà présente")
        return 0
    cr = s.post(
        f"{OSD}/api/observability/application/",
        json={
            "name": app_name,
            "description": description,
            "baseQuery": base_query,
            "servicesEntities": ["opensearch", "timesketch", "thehive", "opencti"],
            "traceGroups": [],
        },
        headers=hdrs(),
        timeout=30,
    )
    if cr.status_code != 200:
        print(f"[fp-playbooks] WARN app '{app_name}' HTTP {cr.status_code}")
        return 0
    print(f"[fp-playbooks] OK app '{app_name}' créée")
    return 0


def ensure_notebook(s: requests.Session, note_name: str, paragraphs: list[tuple[str, str]]) -> int:
    r = s.get(f"{OSD}/api/observability/notebooks/", headers=hdrs(), timeout=20)
    if r.status_code != 200:
        return 1
    note_id = None
    for n in r.json().get("data") or []:
        label = n.get("name") or n.get("path") or ""
        if note_name in label:
            note_id = n.get("id")
            break
    if not note_id:
        cr = s.post(
            f"{OSD}/api/observability/notebooks/note",
            json={"name": note_name},
            headers=hdrs(),
            timeout=30,
        )
        if cr.status_code != 200:
            return 1
        note_id = (cr.text or "").strip().strip('"')
    det = s.get(f"{OSD}/api/observability/notebooks/note/{note_id}", headers=hdrs(), timeout=30)
    para_count = len(det.json().get("paragraphs") or []) if det.status_code == 200 else 0
    if para_count >= len(paragraphs) - 1:
        print(f"[fp-playbooks] OK notebook '{note_name}' ({para_count} paragraphes)")
        return 0
    for idx, (para_input, input_type) in enumerate(paragraphs[para_count:], start=para_count):
        pr = s.post(
            f"{OSD}/api/observability/notebooks/paragraph/",
            json={"noteId": note_id, "paragraphIndex": idx, "paragraphInput": para_input, "inputType": input_type},
            headers=hdrs(),
            timeout=60,
        )
        if pr.status_code != 200:
            print(f"[fp-playbooks] WARN paragraph {idx} HTTP {pr.status_code}")
    print(f"[fp-playbooks] OK notebook '{note_name}'")
    return 0


def restore_refs() -> bool:
    py = os.environ.get("PYTHON", "python3")
    return run_cmd([py, str(ROOT / "scripts" / "opensearch_restore_dashboard_refs.py")], "restore dashboard refs")
