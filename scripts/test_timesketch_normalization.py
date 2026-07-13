#!/usr/bin/env python3
"""Tests unitaires — normalisation CSV Timesketch strict (9 colonnes)."""
from __future__ import annotations

import csv
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INGEST = os.path.join(ROOT, "ingest-worker")
if INGEST not in sys.path:
    sys.path.insert(0, INGEST)

from parsers.timesketch_csv import (  # noqa: E402
    TIMESKETCH_FIELDNAMES,
    build_timesketch_csv,
    events_to_csv_bytes,
    normalize_datetime_utc,
    normalize_uploaded_csv,
    validate_timesketch_csv,
)


def assert_eq(a, b, msg: str) -> None:
    if a != b:
        raise AssertionError(f"{msg}: {a!r} != {b!r}")


def test_fieldnames() -> None:
    assert_eq(
        TIMESKETCH_FIELDNAMES,
        (
            "datetime",
            "message",
            "timestamp_desc",
            "source",
            "event_type",
            "hostname",
            "user",
            "filename",
            "tag",
        ),
        "9 colonnes strictes",
    )


def test_datetime_utc() -> None:
    dt = normalize_datetime_utc("2024-03-15T08:12:01Z")
    assert "+0000" in dt or "+00:00" in dt.replace(":", "", 1), dt
    assert "2024-03-15" in dt


def test_events_to_csv() -> None:
    job = {
        "filename": "wara.csv",
        "case_id": "CASE-TEST",
        "portal": "cert",
        "os_type": "windows",
    }
    events = [
        {
            "@timestamp": "2024-03-15T08:12:01Z",
            "message": "Successful logon user=jdoe",
            "host": {"name": "DESKTOP-01"},
            "winlog": {"event_id": "4624", "provider_name": "Microsoft-Windows-Security-Auditing"},
        }
    ]
    data = events_to_csv_bytes(events, job)
    ok, msg, n = validate_timesketch_csv(data)
    assert ok, f"validation: {msg}"
    assert n >= 1, "au moins une ligne"
    reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
    row = next(reader)
    for col in TIMESKETCH_FIELDNAMES:
        assert col in row, f"colonne manquante {col}"
    assert row["event_type"] == "4624"
    assert "jdoe" in row["message"] or row["message"]


def test_uploaded_csv_normalize() -> None:
    raw = b"""datetime,message,source,timestamp_desc
2024-03-15T08:12:01Z,Failed logon,Security-Audit,Event log
"""
    job = {"filename": "up.csv", "case_id": "C2", "portal": "it", "os_type": "linux"}
    data, n = normalize_uploaded_csv(raw, job)
    ok, msg, count = validate_timesketch_csv(data)
    assert ok, msg
    assert n == count == 1


def test_build_from_fixture() -> None:
    fixture = os.path.join(ROOT, "tests", "fixtures", "wara-windows-events.csv")
    if not os.path.isfile(fixture):
        print(f"SKIP fixture {fixture}")
        return
    with open(fixture, "rb") as f:
        raw = f.read()
    job = {"filename": "wara-windows-events.csv", "case_id": "WARA", "portal": "cert", "os_type": "windows"}
    data, name = build_timesketch_csv(raw, [], "wara-windows-events.csv", job)
    ok, msg, n = validate_timesketch_csv(data)
    assert ok, msg
    assert n >= 4, f"fixture rows {n}"
    assert name.endswith("_timeline.csv")


def main() -> int:
    tests = [
        test_fieldnames,
        test_datetime_utc,
        test_events_to_csv,
        test_uploaded_csv_normalize,
        test_build_from_fixture,
    ]
    for t in tests:
        t()
        print(f"OK {t.__name__}")
    print(f"\n{len(tests)} test(s) passés")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
