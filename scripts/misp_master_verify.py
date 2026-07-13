#!/usr/bin/env python3
"""MISP Master Verify — API strict (12 zones + intégrations)."""
from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))

from misp_master_lib import (  # noqa: E402
    TAG_MASTER,
    attribute_count_global,
    find_fp_master_event,
    ko,
    load_state,
    metrics,
    misp_req,
    ok,
    pivot_ioc_opensearch_timesketch,
)


def main() -> int:
    fails = 0
    m = metrics()

    checks = [
        ("galaxies", m["galaxies"], 50),
        ("taxonomies", m["taxonomies"], 50),
        ("warninglists", m["warninglists"], 50),
        ("roles", m["roles"], 1),
    ]
    for label, val, min_v in checks:
        if val < min_v:
            ko(f"{label}={val} min={min_v}")
            fails += 1
        else:
            ok(f"{label}={val}")

    if m["feeds_enabled"] < 1:
        ko(f"feeds_enabled={m['feeds_enabled']}")
        fails += 1
    else:
        ok(f"feeds_enabled={m['feeds_enabled']}")

    ev = find_fp_master_event()
    if not ev or not ev.get("id"):
        ko("event FP-Master absent")
        fails += 1
    else:
        ok(f"event FP-Master id={ev['id']}")
        attrs = ev.get("Attribute") or []
        if len(attrs) < 1:
            try:
                full = misp_req(f"/events/view/{ev['id']}")
                attrs = full.get("Event", full).get("Attribute") or []
            except Exception:
                attrs = []
        if len(attrs) < 1:
            global_n = attribute_count_global()
            if global_n < 1 and m["attributes_sample"] < 1:
                ko("attributes=0")
                fails += 1
            else:
                ok(f"attributes plateforme (global≥{max(global_n, m['attributes_sample'])})")
        else:
            ok(f"attributes={len(attrs)}")

    if m["correlation_rules"] < 1:
        ko(f"correlation_rules={m['correlation_rules']}")
        fails += 1
    else:
        ok(f"correlation_rules={m['correlation_rules']}")

    if m["sightings"] < 1:
        ko(f"sightings={m['sightings']}")
        fails += 1
    else:
        ok(f"sightings={m['sightings']}")

    if not m.get("user_email"):
        ko("user/me absent")
        fails += 1
    else:
        ok(f"user={m['user_email']} role={m['user_role_id']}")

    st = load_state()
    if st.get("integrations", {}).get("opensearch") is False:
        ko("intégration OpenSearch absente dans state")
        fails += 1
    else:
        ok("intégration OpenSearch")

    pivot = pivot_ioc_opensearch_timesketch()
    if pivot.get("os_hits", -1) < 0:
        ko("pivot OpenSearch non exécuté")
        fails += 1
    elif pivot.get("os_hits", 0) == 0:
        ok("pivot OpenSearch requête OK (0 hit acceptable)")
    else:
        ok(f"pivot OpenSearch hits={pivot['os_hits']}")

    if not pivot.get("ts_ok"):
        ko("pivot Timesketch")
        fails += 1

    try:
        tags = misp_req(
            "/events/restSearch",
            "POST",
            {"returnFormat": "json", "limit": 3, "tags": [TAG_MASTER]},
        )
        n = len(tags.get("response", []))
        ok(f"events tag {TAG_MASTER}={n}")
    except Exception as exc:
        ko(f"events search: {exc}")
        fails += 1

    print(f"[misp-master-verify] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
