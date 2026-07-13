"""
Pipeline unifié ingest-worker → Timesketch (CSV strict + fallback Plaso).
"""
from __future__ import annotations

import logging
import os
from typing import Any

from parsers.timesketch_csv import build_timesketch_csv, validate_timesketch_csv
from timesketch_io import (
    api_headers,
    get_or_create_sketch,
    login_session,
    prune_failed_timelines,
    upload_csv_timeline,
    verify_sketch_explore,
    wait_timeline_ready,
)
from timesketch_plaso import evtx_to_plaso, log2timeline_available, upload_plaso_timeline

log = logging.getLogger("ingest-worker")

TS_URL = os.environ.get("TIMESKETCH_URL", "http://timesketch-web:5000")
TS_USER = os.environ.get("TIMESKETCH_USER", "admin")
TS_PASSWORD = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
OS_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch-node1:9200")
MIN_EVENTS_PLASO = int(os.environ.get("TIMESKETCH_PLASO_MIN_EVENTS", "50"))

_ts_client: dict | None = None
import time


def ts_client() -> dict | None:
    global _ts_client
    if _ts_client and (time.time() - _ts_client.get("ts", 0)) < 3500:
        return _ts_client
    client = login_session(TS_URL, TS_USER, TS_PASSWORD)
    if client:
        client["ts"] = time.time()
        _ts_client = client
    return _ts_client


def import_to_timesketch(
    events: list[dict],
    job: dict,
    raw_data: bytes | None = None,
    prune_broken: bool = False,
) -> dict[str, Any]:
    client = ts_client()
    if not client:
        return {"ok": False, "error": "login_failed"}

    filename = job.get("filename", "timeline.csv")
    case_id = job.get("case_id", "CASE-UNKNOWN")
    sketch_name = f"[FP] {case_id}"
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()

    try:
        sid = get_or_create_sketch(
            client, TS_URL, sketch_name, f"Forensic Platform — {case_id}"
        )
        if not sid:
            return {"ok": False, "error": "sketch_create_failed"}

        pruned = 0
        headers = api_headers(client, TS_URL, sid)
        if prune_broken:
            pruned = prune_failed_timelines(
                client["session"], TS_URL, sid, headers, OS_URL
            )
            if pruned:
                log.info("Sketch %s: %d timeline(s) cassée(s) supprimée(s)", sid, pruned)

        csv_data, csv_name = build_timesketch_csv(raw_data or b"", events, filename, job)
        ok_val, val_msg, row_count = validate_timesketch_csv(csv_data)
        method = "csv"
        upload_ok = False
        upload_meta: dict[str, Any] = {}

        if ok_val and row_count > 0:
            upload_ok, upload_meta = upload_csv_timeline(
                client, TS_URL, sid, csv_name, csv_data
            )
        else:
            log.warning("CSV Timesketch invalide: %s", val_msg)

        # Fallback Plaso pour EVTX si CSV vide/échec ou peu d'événements
        if (
            not upload_ok
            or not upload_meta.get("timeline_id")
            or row_count < MIN_EVENTS_PLASO
        ) and ext in ("evtx", "evt") and raw_data and log2timeline_available():
            log.info("Tentative fallback Plaso pour %s (%d events)", filename, len(events))
            plaso_path = evtx_to_plaso(raw_data, label=case_id.replace("/", "_")[:40])
            if plaso_path:
                plaso_name = csv_name.replace(".csv", ".plaso")
                upload_ok, upload_meta = upload_plaso_timeline(
                    client, TS_URL, sid, plaso_path, plaso_name, OS_URL
                )
                method = upload_meta.get("method", "plaso")
                try:
                    plaso_path.unlink(missing_ok=True)
                    plaso_path.parent.rmdir()
                except OSError:
                    pass

        timeline_id = upload_meta.get("timeline_id")
        ready = upload_meta.get("ready")
        ready_msg = upload_meta.get("detail", "")
        if timeline_id and not ready:
            ready, ready_msg = wait_timeline_ready(
                client["session"], TS_URL, OS_URL, sid, timeline_id, headers
            )

        explore_ok, explore_msg = verify_sketch_explore(
            client["session"], TS_URL, sid, headers, OS_URL
        )
        if not explore_ok:
            log.error("Explore verification failed sketch %s: %s", sid, explore_msg)

        ok = bool(upload_ok and ready and explore_ok)
        return {
            "ok": ok,
            "sketch_id": sid,
            "sketch_url": f"{TS_URL}/sketch/{sid}/explore",
            "timeline_id": timeline_id,
            "timeline_ready": ready,
            "timeline_detail": ready_msg,
            "explore_ok": explore_ok,
            "explore_detail": explore_msg,
            "method": method,
            "csv_rows": row_count,
            "csv_bytes": len(csv_data) if csv_data else 0,
            "events_parsed": len(events),
            "timelines_pruned": pruned,
        }
    except Exception as exc:
        log.exception("Timesketch pipeline error: %s", exc)
        return {"ok": False, "error": str(exc)}
