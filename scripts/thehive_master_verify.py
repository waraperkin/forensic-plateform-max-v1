#!/usr/bin/env python3
"""TheHive Master Verify — API strict (14 zones + intégrations)."""
from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from thehive_master_lib import (  # noqa: E402
    ADMIN_LOGIN,
    ADMIN_PASS,
    CONFIG_FILE,
    ORG_NAME,
    TAG_MASTER,
    find_master_case,
    ko,
    load_state,
    metrics,
    ok,
    pivot_os_ts_cti_misp,
    th_query,
    th_req,
)


def main() -> int:
    fails = 0
    m = metrics()

    if m["cases"] < 1:
        ko(f"cases={m['cases']}")
        fails += 1
    else:
        ok(f"cases={m['cases']}")

    case = find_master_case()
    if not case:
        ko("case FP-Master absent")
        fails += 1
    else:
        ok(f"case FP-Master id={case.get('_id')}")

    if m["alerts"] < 1:
        ko(f"alerts={m['alerts']}")
        fails += 1
    else:
        ok(f"alerts={m['alerts']}")

    alerts = th_query("listAlert")
    if not any(TAG_MASTER in (a.get("tags") or []) for a in alerts):
        ko("alert fp-master tag absente")
        fails += 1
    else:
        ok("alert FP-Master taguée")

    if m["case_templates"] < 2:
        ko(f"case_templates={m['case_templates']}")
        fails += 1
    else:
        ok(f"case_templates={m['case_templates']}")

    if m["tasks"] < 1:
        ko(f"tasks={m['tasks']}")
        fails += 1
    else:
        ok(f"tasks={m['tasks']}")

    if m["functions"] < 1:
        ko(f"playbooks/functions={m['functions']}")
        fails += 1
    else:
        ok(f"playbooks={m['functions']}")

    if m["users"] < 1:
        ko(f"users={m['users']}")
        fails += 1
    else:
        ok(f"users={m['users']}")

    orgs = th_req(
        "POST",
        "/api/v1/query",
        {"query": [{"_name": "listOrganisation"}]},
        org="",
        user=ADMIN_LOGIN,
        password=ADMIN_PASS,
    )
    if not isinstance(orgs, list) or not any(o.get("name") == ORG_NAME for o in orgs):
        ko(f"organisation {ORG_NAME} absente")
        fails += 1
    else:
        ok(f"organisation {ORG_NAME}")

    cfg_text = CONFIG_FILE.read_text(encoding="utf-8") if CONFIG_FILE.is_file() else ""
    for label, frag in (
        ("Cortex", "Cortex-Forensic"),
        ("MISP", "MISP-Forensic"),
        ("Notifications", "notification.webhook"),
        ("OpenSearch", "opensearch"),
    ):
        if frag.lower() in cfg_text.lower():
            ok(f"integration config {label}")
        else:
            ko(f"integration config {label}")
            fails += 1

    st = load_state()
    integ = st.get("integrations", {})
    if not integ:
        ko("state intégrations absent")
        fails += 1
    else:
        ok("state intégrations présent")

    pivot = pivot_os_ts_cti_misp()
    if pivot.get("os_hits", -1) < 0:
        ko("pivot OpenSearch")
        fails += 1
    else:
        ok(f"pivot OpenSearch hits={pivot.get('os_hits')}")
    if not pivot.get("ts_ok"):
        ko("pivot Timesketch")
        fails += 1
    else:
        ok("pivot Timesketch")

    print(f"[thehive-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
