#!/usr/bin/env python3
"""Vérifie l'API rapports forensic (templates, collecte, génération)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from fp_runtime_env import CERT_PORTAL_URL, load_runtime_env  # noqa: E402

load_runtime_env()
import portal_cert_master_lib as pcm  # noqa: E402

pcm.CERT_URL = CERT_PORTAL_URL
from portal_cert_master_lib import cert_req  # noqa: E402

CASE = os.environ.get("FP_REPORT_VERIFY_CASE", "CASE-UC01-RANSOM")


def main() -> int:
    problems = []
    try:
        tpl = cert_req("/api/reports/templates")
        if not tpl.get("templates"):
            problems.append("templates vides")
        else:
            print(f"[report-verify] OK templates={len(tpl['templates'])}")
    except Exception as e:
        problems.append(f"templates: {e}")

    try:
        llm = cert_req("/api/reports/llm/status")
        print(
            f"[report-verify] LLM available={llm.get('available')} configured={llm.get('configured')}"
        )
    except Exception as e:
        problems.append(f"llm status: {e}")

    try:
        col = cert_req("/api/reports/collect", "POST", {"case_id": CASE})
        ev = col.get("evidence") or {}
        st = ev.get("stats") or {}
        print(
            f"[report-verify] OK collect case={CASE} events={st.get('events_total')} uploads={st.get('uploads_count')}"
        )
    except Exception as e:
        problems.append(f"collect: {e}")

    try:
        gen = cert_req(
            "/api/reports/generate",
            "POST",
            {
                "case_id": CASE,
                "template_id": "standard-ir",
                "enrich_ai": False,
                "title": f"Verify — {CASE}",
            },
            timeout=120,
        )
        rep = gen.get("report") or {}
        rid = rep.get("id")
        if not rid:
            problems.append("generate: pas d'id rapport")
        else:
            sections = rep.get("sections") or {}
            print(f"[report-verify] OK generate id={rid} sections={len(sections)}")
            exp = cert_req(f"/api/reports/{rid}/export?format=json", timeout=60)
            if not exp.get("sections"):
                problems.append("export json: sections manquantes")
            else:
                print("[report-verify] OK export json")
    except Exception as e:
        problems.append(f"generate: {e}")

    if problems:
        print(f"[report-verify] FAIL {len(problems)}:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("[report-verify] 0 problème(s) — OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
