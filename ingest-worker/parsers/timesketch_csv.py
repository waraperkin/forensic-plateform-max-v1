"""
CSV Timesketch strict — 9 colonnes fixes, délégation à timesketch_normalizer.

Colonnes : datetime, message, timestamp_desc, source, event_type,
hostname, user, filename, tag.
"""
from __future__ import annotations

import csv
import io
import logging
import re
from typing import Any

from timesketch_normalizer import (
    TIMESKETCH_FIELDNAMES,
    DEFAULT_TIMESTAMP_DESC,
    events_to_strict_csv_bytes,
    normalize_csv_mapped_row,
    normalize_datetime_utc,
    normalize_event_to_ts_row,
    validate_strict_timesketch_csv,
    validate_ts_row,
)

log = logging.getLogger("ingest-worker")

COLUMN_ALIASES: dict[str, str] = {
    "timestamp": "datetime",
    "time": "datetime",
    "date": "datetime",
    "event_time": "datetime",
    "@timestamp": "datetime",
    "msg": "message",
    "Message": "message",
    "description": "message",
    "log": "message",
    "event_message": "message",
    "timeline": "timestamp_desc",
    "source_file": "timestamp_desc",
    "file": "filename",
    "host": "hostname",
    "computer": "hostname",
    "Computer": "hostname",
    "computer_name": "hostname",
    "username": "user",
    "account": "user",
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "event_id": "event_type",
    "EventID": "event_type",
    "provider": "source",
    "Provider": "source",
    "channel": "source",
    "tags": "tag",
}


def _normalize_header(h: str) -> str:
    h = h.strip().replace('"', "").replace("\ufeff", "")
    low = h.lower().replace(" ", "_")
    return COLUMN_ALIASES.get(h, COLUMN_ALIASES.get(low, low))


def event_to_row(ev: dict[str, Any], job: dict[str, Any]) -> dict[str, str]:
    """Ligne stricte à partir d'un événement parsé (API publique historique)."""
    return normalize_event_to_ts_row(ev, job)


def events_to_csv_bytes(events: list[dict[str, Any]], job: dict[str, Any]) -> bytes:
    """Génère le CSV UTF-8 (rétrocompat csv_validator)."""
    data, _, _ = events_to_strict_csv_bytes(events, job)
    return data


def rows_from_dict_reader(reader: csv.DictReader, job: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for i, raw in enumerate(reader):
        if i >= 500_000:
            break
        norm: dict[str, str] = {c: "" for c in TIMESKETCH_FIELDNAMES}
        for src, val in raw.items():
            if not src:
                continue
            key = _normalize_header(src)
            if key in TIMESKETCH_FIELDNAMES:
                norm[key] = (val or "").strip() if val is not None else ""
        if not norm.get("message"):
            norm["message"] = " | ".join(f"{k}={v}" for k, v in raw.items() if v)[:32000]
        row = normalize_csv_mapped_row(norm, job)
        ok, msg = validate_ts_row(row)
        if not ok:
            log.warning("CSV upload row %d skip: %s", i + 2, msg)
            continue
        rows.append(row)
    return rows


def normalize_uploaded_csv(data: bytes, job: dict[str, Any]) -> tuple[bytes, int]:
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = rows_from_dict_reader(reader, job)
    if not rows:
        return b"", 0
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(TIMESKETCH_FIELDNAMES), extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode("utf-8"), len(rows)


def validate_timesketch_csv(data: bytes) -> tuple[bool, str, int]:
    """Validation stricte avant upload Timesketch."""
    return validate_strict_timesketch_csv(data)


def build_timesketch_csv(
    raw_data: bytes, events: list[dict[str, Any]], filename: str, job: dict[str, Any]
) -> tuple[bytes, str]:
    """
    CSV Timesketch strict. Priorité : events parsés ; sinon CSV uploadé normalisé.
    """
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    base = re.sub(r"[^\w.\-]+", "_", filename.rsplit(".", 1)[0])[:120] + "_timeline.csv"

    # CSV structuré : normaliser d'abord (évite message « ligne brute » du text_parser).
    if ext == "csv" and raw_data:
        data, n = normalize_uploaded_csv(raw_data, job)
        ok, msg, _ = validate_timesketch_csv(data)
        if ok and n > 0:
            return data, base

    if events:
        data, written, skipped = events_to_strict_csv_bytes(events, job)
        ok, msg, n = validate_timesketch_csv(data)
        if ok and n > 0:
            if skipped:
                log.info("Timesketch CSV: %d rows written, %d skipped", written, skipped)
            return data, base
        log.warning("CSV depuis events invalide (%s), fallback normalize", msg)

    if ext == "csv" and raw_data:
        data, n = normalize_uploaded_csv(raw_data, job)
        ok, msg, _ = validate_timesketch_csv(data)
        if ok and n > 0:
            return data, base

    if events:
        data, _, _ = events_to_strict_csv_bytes(events, job)
        return data, base
    return b"", base
