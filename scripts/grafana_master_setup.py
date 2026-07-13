#!/usr/bin/env python3
"""Grafana Master Setup — datasources, dashboards, alerting, admin."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from grafana_master_lib import (  # noqa: E402
    GF,
    create_alert_rules,
    create_contact_point,
    create_notification_policy,
    ensure_folder,
    ensure_obs_stack,
    grafana_get_resilient,
    import_all_dashboards,
    ko,
    list_datasources,
    ok,
    restart_grafana,
    run_timesketch_pipeline,
    save_state,
    setup_admin,
    wait_grafana_ready,
    REQUIRED_DS,
    ds_health_ok,
)


def refresh_platform_health() -> None:
    ph = ROOT / "scripts" / "platform_health_dashboard_setup.py"
    if ph.is_file():
        try:
            subprocess.run([sys.executable, str(ph)], cwd=str(ROOT), timeout=420, check=False)
        except subprocess.TimeoutExpired:
            print("[grafana-master-setup] WARN platform_health timeout (non bloquant)", file=sys.stderr)


def main() -> int:
    fails = 0
    print(f"[grafana-master-setup] Grafana URL: {GF}")

    refresh_platform_health()
    if not ensure_obs_stack():
        fails += 1
    if not run_timesketch_pipeline():
        fails += 1

    if __import__("os").environ.get("GRAFANA_RESTART", "1") == "1":
        restart_grafana()

    import requests
    from grafana_master_lib import session

    s = session()
    import urllib3
    urllib3.disable_warnings()
    wait_grafana_ready(180)
    try:
        hr = grafana_get_resilient(f"{GF}/api/health", timeout=15)
    except requests.RequestException as e:
        ko(f"Grafana injoignable: {e}")
        return 1
    if hr.status_code != 200:
        ko(f"Grafana health HTTP {hr.status_code}")
        return 1
    ok(f"Grafana health v{hr.json().get('version', '?')}")

    by_uid = list_datasources(s)
    for uid in REQUIRED_DS:
        if uid not in by_uid:
            ko(f"datasource manquant {uid}")
            fails += 1
            continue
        healthy, msg = ds_health_ok(s, uid)
        if healthy:
            ok(f"datasource {uid} ({msg})")
        else:
            ko(f"datasource {uid} {msg}")
            fails += 1

    folder_uid = ensure_folder(s)
    if not folder_uid:
        fails += 1
    else:
        n = import_all_dashboards(s, folder_uid)
        ok(f"imported {n} dashboards")

    if not create_contact_point(s):
        fails += 1
    create_notification_policy(s)
    rules = create_alert_rules(s)
    ar = s.get(f"{GF}/api/v1/provisioning/alert-rules", timeout=20)
    prov_count = len(ar.json()) if ar.status_code == 200 else 0
    total_rules = rules + prov_count
    if total_rules < 2:
        ko(f"alert rules insuffisantes (api={rules} prov={prov_count})")
        fails += 1
    else:
        ok(f"alert rules total={total_rules}")

    setup_admin(s)

    save_state({"fails_setup": fails, "folder_uid": folder_uid, "alert_rules": rules})
    print(f"[grafana-master-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
