#!/usr/bin/env python3
"""Timesketch Fusion Engine — Plaso + KAPE + Evtx + MFT + logs + IOC + CTI → timeline unique."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from timesketch_ecs_adapter import CONVERTERS, ensure_fp_ecs, sample_events  # noqa: E402
from ts_cti_fusion_lib import collect_cti_events, enrich_dfir_with_cti  # noqa: E402
from timesketch_master_lib import (  # noqa: E402
    LOG_DIR,
    MASTER_CASE,
    MASTER_SKETCH,
    os_search,
    ts_client,
    upload_events_timeline,
    wait_timeline_ready,
    write_sketch_url,
)

LOOKBACK = __import__("os").environ.get("TS_FUSION_LOOKBACK", "30d")
DATASET_FILTERS = {
    "plaso": ["dfir.plaso", "timeline.plaso"],
    "kape": ["dfir.kape"],
    "evtx": ["dfir.evtx", "windows.security"],
    "mfte": ["dfir.mft"],
    "fp_log": ["logs.", "web.", "system.auth"],
    "ioc": ["ti.ioc"],
    "cti": ["ti.enrichment", "ti.cti", "ti.opencti", "ti.misp", "ti.ioc", "ti.mitre", "ti.group", "ti.malware", "ti.campaign"],
}


def _query_dataset(datasets: list[str]) -> dict:
    should = [{"wildcard": {"event.dataset": f"{d}*"}} if d.endswith(".") else {"term": {"event.dataset": d}} for d in datasets]
    return {
        "bool": {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{LOOKBACK}"}}}],
            "should": should,
            "minimum_should_match": 1,
        }
    }


def fetch_source_events(source: str) -> list[dict[str, Any]]:
    datasets = DATASET_FILTERS.get(source, [])
    hits: list[dict] = []
    if datasets:
        hits = os_search("forensic-*", _query_dataset(datasets), 200)
    if not hits and source in ("ioc", "cti"):
        hits = os_search("forensic-*", {"term": {"ti_match": True}}, 100)
    conv = CONVERTERS.get(source)
    if not hits:
        return sample_events().get(source, [])
    out: list[dict] = []
    for h in hits[:500]:
        out.append(conv(h) if conv else ensure_fp_ecs(h, source, h.get("event.dataset", f"dfir.{source}")))
    return out


def merge_fusion(sources: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    merged: dict[str, dict] = {}

    def key(ev: dict) -> str:
        ts = (ev.get("@timestamp") or "")[:19]
        host = ev.get("host.name") or (ev.get("host") or {}).get("name", "")
        user = ev.get("user.name") or ""
        return f"{ts}|{host}|{user}"

    for src, events in sources.items():
        for ev in events:
            k = key(ev) or f"{src}-{id(ev)}"
            if k not in merged:
                merged[k] = dict(ev)
                merged[k]["fusion_sources"] = [src]
                merged[k]["tags"] = list(ev.get("tags", [])) + [f"fusion.{src}", "dfir.fusion"]
            else:
                merged[k]["fusion_sources"] = list(set(merged[k].get("fusion_sources", []) + [src]))
                for t in ev.get("tags", []):
                    if t not in merged[k].get("tags", []):
                        merged[k]["tags"].append(t)
                merged[k]["tag"] = ",".join(merged[k]["tags"][:32])
                if ev.get("message") and len(str(ev["message"])) > len(str(merged[k].get("message", ""))):
                    merged[k]["message"] = ev["message"]
    fused = list(merged.values())
    fused.sort(key=lambda x: x.get("@timestamp", ""))
    for ev in fused:
        ev["event.dataset"] = "dfir.fusion"
        if isinstance(ev.get("event"), dict):
            ev["event"]["dataset"] = "dfir.fusion"
        ensure_fp_ecs(ev, "fusion", "dfir.fusion")
    return fused


def main() -> int:
    print(f"[fusion] sketch={MASTER_SKETCH} lookback={LOOKBACK}")
    client = ts_client()
    if not client:
        print("[fusion] ERREUR login Timesketch", file=sys.stderr)
        return 1
    from timesketch_io import get_or_create_sketch  # noqa: E402

    sid = get_or_create_sketch(
        client,
        __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/"),
        MASTER_SKETCH,
        f"Fusion DFIR {MASTER_CASE}",
    )
    if not sid:
        return 1
    sid = int(sid)
    sources: dict[str, list[dict]] = {}
    for src in ("plaso", "kape", "evtx", "mfte", "fp_log", "ioc", "cti"):
        sources[src] = fetch_source_events(src)
        print(f"[fusion] {src}: {len(sources[src])} events")

    uploaded = 0
    for src, events in sources.items():
        if not events:
            continue
        ok, _ = upload_events_timeline(client, sid, f"FP-{src}", events)
        if ok:
            uploaded += 1
            print(f"[fusion] upload OK {src}")
        else:
            print(f"[fusion] upload KO {src}", file=sys.stderr)

    cti_pool = collect_cti_events()
    if cti_pool:
        sources["cti"] = list(sources.get("cti", [])) + cti_pool[:200]
        print(f"[fusion] CTI pool: {len(cti_pool)} events")

    fused = merge_fusion(sources)
    if cti_pool:
        fused = enrich_dfir_with_cti(fused, cti_pool)
        for ev in fused:
            tags = list(ev.get("tags") or [])
            for t in ("ti.fusion", "fp-cti-fusion"):
                if t not in tags:
                    tags.append(t)
            ev["tags"] = tags
            ev["tag"] = ",".join(tags[:32])
    if fused:
        ok, _ = upload_events_timeline(client, sid, "FP-fusion-timeline", fused)
        if ok:
            uploaded += 1
            print(f"[fusion] fusion timeline {len(fused)} events")

    session = client["session"]
    headers = __import__("timesketch_io").api_headers(client, __import__("os").environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/"), sid)
    wait_timeline_ready(session, headers, sid, timeout=int(__import__("os").environ.get("TS_FUSION_POLL", "240")))

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    state = {
        "sketch_id": sid,
        "sketch_name": MASTER_SKETCH,
        "case_id": MASTER_CASE,
        "uploaded_timelines": uploaded,
        "fusion_events": len(fused),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    (LOG_DIR / "timesketch_master_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    write_sketch_url(sid)
    print(f"[fusion] OK sketch={sid} timelines={uploaded} fusion={len(fused)}")
    return 0 if uploaded >= 1 else 1


if __name__ == "__main__":
    sys.exit(main())
