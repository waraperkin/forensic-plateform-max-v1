#!/usr/bin/env python3
"""Cross-Pivot TS→OS — context links Timesketch + vues pivot OpenSearch."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crosspivot_engine import (  # noqa: E402
    PIVOT_BUILDERS,
    load_state,
    opensearch_discover_url,
    resolve_sketch_id,
    save_state,
    verify_pivot,
)
from timesketch_master_lib import login, ts_client  # noqa: E402
from timesketch_io import get_or_create_sketch, api_headers  # noqa: E402
from timesketch_zones_lib import create_saved_view, sketch_context  # noqa: E402

CONTEXT_PATH = ROOT / "config" / "timesketch" / "context_links.yaml"
WEB = __import__("os").environ.get("TIMESKETCH_WEB_CONTAINER", "forensic-timesketch-web")
TS_URL = __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")

TS_CONTEXT_LINKS = """
## Cross-Pivot — OpenSearch (FP)
  fp_opensearch_host:
    short_name: 'Open in OpenSearch (host)'
    match_fields: ['hostname', 'host', 'host.name', 'computer_name']
    context_link: 'http://localhost:5601/dashboards/app/discover#/?_a=(index:fp-events,query:(language:kuery,query:''hostname:<ATTR_VALUE>''))'
    redirect_warning: FALSE
  fp_opensearch_user:
    short_name: 'Open in OpenSearch (user)'
    match_fields: ['user', 'username', 'user.name']
    context_link: 'http://localhost:5601/dashboards/app/discover#/?_a=(index:fp-events,query:(language:kuery,query:''user.name:<ATTR_VALUE>''))'
    redirect_warning: FALSE
  fp_opensearch_ip:
    short_name: 'Open in OpenSearch (IP)'
    match_fields: ['ip', 'ip_address', 'source.ip', 'src_ip']
    context_link: 'http://localhost:5601/dashboards/app/discover#/?_a=(index:fp-events,query:(language:kuery,query:''source.ip:<ATTR_VALUE> OR destination.ip:<ATTR_VALUE>''))'
    redirect_warning: FALSE
  fp_opensearch_message:
    short_name: 'Open in OpenSearch (message)'
    match_fields: ['message']
    context_link: 'http://localhost:5601/dashboards/app/discover#/?_a=(index:fp-events,query:(language:kuery,query:''message:*<ATTR_VALUE>*''))'
    redirect_warning: FALSE
  fp_opensearch_tag:
    short_name: 'Open in OpenSearch (tag)'
    match_fields: ['tag', 'tags']
    context_link: 'http://localhost:5601/dashboards/app/discover#/?_a=(index:fp-events,query:(language:kuery,query:''message:*<ATTR_VALUE>* OR tag:<ATTR_VALUE>''))'
    redirect_warning: FALSE
  fp_opensearch_ioc:
    short_name: 'Open in OpenSearch (IOC)'
    match_fields: ['domain', 'domain_name', 'ioc']
    context_link: 'http://localhost:5601/dashboards/app/discover#/?_a=(index:fp-events,query:(language:kuery,query:''ti_match:true AND message:*<ATTR_VALUE>*''))'
    redirect_warning: FALSE
"""


def deploy_context_links() -> bool:
    text = CONTEXT_PATH.read_text(encoding="utf-8") if CONTEXT_PATH.is_file() else ""
    if "fp_opensearch_host" not in text:
        text = text.rstrip() + "\n" + TS_CONTEXT_LINKS
        CONTEXT_PATH.write_text(text, encoding="utf-8")
    try:
        subprocess.run(
            ["docker", "cp", str(CONTEXT_PATH), f"{WEB}:/etc/timesketch/context_links.yaml"],
            check=True,
            timeout=30,
        )
        subprocess.run(["docker", "restart", WEB], check=True, timeout=60, capture_output=True)
        print("[crosspivot-ts-os] OK context_links.yaml déployé")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"[crosspivot-ts-os] WARN deploy context_links: {exc}", file=sys.stderr)
        return False


def create_ts_views() -> int:
    s, h, sid, indices = sketch_context()
    fails = 0
    for kind in PIVOT_BUILDERS:
        pr = verify_pivot(kind)
        name = f"[FP] Open in OpenSearch — {kind}"
        desc = f"OPENSEARCH_URL={pr.os_url}\nECS={pr.os_query}"
        if not create_saved_view(s, h, sid, name, pr.os_query, indices, desc):
            print(f"[crosspivot-ts-os] KO view {name}", file=sys.stderr)
            fails += 1
        else:
            print(f"[crosspivot-ts-os] OK view {kind}")
    st = load_state()
    st["ts_views"] = len(PIVOT_BUILDERS) - fails
    st["context_links"] = True
    save_state([verify_pivot(k) for k in PIVOT_BUILDERS], st)
    return fails


def main() -> int:
    deploy_context_links()
    fails = create_ts_views()
    print(f"[crosspivot-ts-os] bilan fails={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
