"""Compatibilité — délègue au module Timesketch strict."""
from __future__ import annotations

from parsers.timesketch_csv import (
    build_timesketch_csv,
    normalize_uploaded_csv,
    validate_timesketch_csv,
)

# Alias historiques
validate_csv_bytes = validate_timesketch_csv


def build_csv_for_upload(data: bytes, events: list, filename: str) -> tuple[bytes, str, None]:
    job = {"filename": filename, "os_type": "unknown", "case_id": "CASE-UNKNOWN"}
    csv_data, name = build_timesketch_csv(data, events, filename, job)
    return csv_data, name, None


def events_to_csv_bytes(events: list, source_label: str = "upload") -> bytes:
    job = {"filename": source_label, "os_type": "forensic", "case_id": "CASE-UNKNOWN"}
    from parsers.timesketch_csv import events_to_csv_bytes as _ev

    return _ev(events, job)


def headers_mapping_for_rows(rows, original_headers=None):
    return None
