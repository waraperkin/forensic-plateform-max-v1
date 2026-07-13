#!/usr/bin/env python3
"""Setup dashboard FP — Platform Health (métriques + import OSD + story TS)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from fp_playbooks_common import import_ndjson, patch_all_fp_dashboards, hdrs  # noqa: E402
from platform_health_lib import (  # noqa: E402
    STATUS_FILE,
    build_summary_markdown,
    bulk_index_metrics,
    collect_all_metrics,
    _load_soc_status,
)
from osd_platform_health_lib import DASH_ID, DASH_TITLE  # noqa: E402

NDJSON_CONFIG = ROOT / "config" / "opensearch" / "dashboards" / "fp-platform-health.ndjson"
NDJSON_DASH = ROOT / "dashboards" / "opensearch" / "fp-platform-health.ndjson"
BUILD_SCRIPT = ROOT / "scripts" / "build_platform_health_dashboard.py"
TS_URL = __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
STORY_TITLE = "[FP] Platform Health"


def ensure_ndjson() -> bool:
    r = subprocess.run([sys.executable, str(BUILD_SCRIPT)], cwd=str(ROOT), timeout=120)
    if r.returncode != 0:
        print("[platform-health-setup] KO build ndjson", file=sys.stderr)
        return False
    return NDJSON_CONFIG.is_file()


def ensure_timesketch_story(md: str) -> bool:
    try:
        from timesketch_playbook_setup import create_story  # noqa: E402
        from timesketch_master_lib import login, get_master_sketch_id  # noqa: E402
        import requests

        ts, th = login()
        sid = get_master_sketch_id()
        h = {**th, "Referer": f"{TS_URL}/sketch/{sid}/story/"}
        sr = ts.get(f"{TS_URL}/api/v1/sketches/{sid}/stories/", headers=h, timeout=25)
        if sr.status_code == 200:
            payload = sr.json()
            stories = payload.get("objects", payload) if isinstance(payload, dict) else payload
            if not isinstance(stories, list):
                stories = []
            for st in stories:
                title = st.get("title", "") if isinstance(st, dict) else ""
                if STORY_TITLE in title:
                    print("[platform-health-setup] OK story existante")
                    return True
        ok = create_story(ts, th, sid, STORY_TITLE)
        if ok:
            print("[platform-health-setup] OK story Timesketch créée")
        return ok
    except Exception as exc:
        print(f"[platform-health-setup] WARN story TS: {exc}", file=sys.stderr)
        return True


def main() -> int:
    fails = 0
    print("[platform-health-setup] collecte métriques…")
    docs = collect_all_metrics()
    n = bulk_index_metrics(docs)
    if n < 5:
        print(f"[platform-health-setup] KO indexation health n={n}", file=sys.stderr)
        fails += 1
    else:
        print(f"[platform-health-setup] OK indexé {n} documents → forensic-platform-health")

    if not ensure_ndjson():
        fails += 1
    elif not import_ndjson(NDJSON_CONFIG):
        if NDJSON_DASH.is_file() and not import_ndjson(NDJSON_DASH):
            print("[platform-health-setup] KO import OSD", file=sys.stderr)
            fails += 1
    else:
        print("[platform-health-setup] OK import OSD")

    import urllib3
    urllib3.disable_warnings()
    import requests

    s = requests.Session()
    s.verify = False
    from osd_fp_playbooks_bars_lib import FP_DASHBOARDS_ALL  # noqa: E402

    if DASH_ID not in FP_DASHBOARDS_ALL:
        pass
    patch_all_fp_dashboards(s)

    dr = s.get(
        f"{__import__('os').environ.get('OSD_URL', 'http://localhost:5601/dashboards')}/api/saved_objects/dashboard/{DASH_ID}",
        headers=hdrs(),
        timeout=25,
    )
    if dr.status_code != 200:
        print(f"[platform-health-setup] KO dashboard {DASH_ID}", file=sys.stderr)
        fails += 1
    else:
        print(f"[platform-health-setup] OK dashboard {DASH_TITLE}")

    soc = _load_soc_status()
    md = build_summary_markdown(docs, soc)
    (ROOT / "logs").mkdir(parents=True, exist_ok=True)
    (ROOT / "logs" / "platform_health_summary.md").write_text(md, encoding="utf-8")
    ensure_timesketch_story(md)

    if STATUS_FILE.is_file():
        print(f"[platform-health-setup] SOC status: {soc.get('global_status')} ({STATUS_FILE})")

    print(f"[platform-health-setup] errors={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
