"""
Normalisation stricte des événements → lignes CSV Timesketch (9 colonnes fixes).

Toutes les valeurs envoyées à Timesketch sont des chaînes UTF-8 « plates » :
pas de list/dict/bool/int dans les cellules CSV. Les structures imbriquées
sont sérialisées dans `message` ou ignorées.

Format datetime obligatoire : ISO8601 UTC avec microsecondes (6 chiffres) :
``YYYY-MM-DDTHH:MM:SS.ffffff+00:00``
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("ingest-worker")

TIMESKETCH_FIELDNAMES: tuple[str, ...] = (
    "datetime",
    "message",
    "timestamp_desc",
    "source",
    "event_type",
    "hostname",
    "user",
    "filename",
    "tag",
)

DEFAULT_TIMESTAMP_DESC = "Event Logged"

# Limites de taille (caractères) — alignées Timesketch / Elasticsearch
MAX_LEN = {
    "datetime": 40,
    "message": 32000,
    "timestamp_desc": 500,
    "source": 200,
    "event_type": 256,
    "hostname": 253,
    "user": 256,
    "filename": 500,
    "tag": 2000,
}

# En-tête CSV attendu (ordre exact)
EXPECTED_HEADER = ",".join(TIMESKETCH_FIELDNAMES)

_DATETIME_STRICT = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$"
)


def strip_control_chars(s: str, max_len: int) -> str:
    """NFKC, retire NUL et caractères de contrôle < 32 (sauf \\n \\t)."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", str(s))
    s = s.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    s = "".join(c for c in s if c in ("\n", "\t") or ord(c) >= 32)
    return s[:max_len] if max_len > 0 else ""


def safe_string(value: Any, max_len: int) -> str:
    """Convertit toute valeur en string sûre pour cellule CSV Timesketch."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return strip_control_chars(str(value), max_len)
    if isinstance(value, str):
        return strip_control_chars(value, max_len)
    if isinstance(value, (list, tuple)):
        parts = []
        for item in value[:64]:
            parts.append(safe_string(item, min(500, max_len)))
        joined = ";".join(p for p in parts if p)
        return strip_control_chars(joined, max_len)
    if isinstance(value, dict):
        try:
            flat = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            flat = str(value)
        return strip_control_chars(flat, max_len)
    return strip_control_chars(str(value), max_len)


def normalize_datetime_utc(value: Any) -> str:
    """
    Retourne une chaîne ISO8601 UTC avec microsecondes (6 chiffres) et +00:00.
    """
    now = datetime.now(timezone.utc)
    if value is None or value == "":
        dt = now
    else:
        s = str(value).strip()
        if not s:
            dt = now
        else:
            s = s.replace("Z", "+00:00")
            dt = None
            try:
                if re.match(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", s):
                    s_norm = s.replace(" ", "T", 1)
                    if "+" not in s_norm and s_norm.count("-") >= 3:
                        s_norm = s_norm[:19] + "+00:00"
                    dt = datetime.fromisoformat(s_norm.replace("Z", "+00:00"))
                else:
                    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                dt = None
            if dt is None:
                log.debug("datetime non parsé, fallback now: %r", s[:80])
                dt = now
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    # Toujours 6 décimales (microsecondes)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    frac = f"{dt.microsecond:06d}"
    return f"{base}.{frac}+00:00"


def _default_tag(job: dict[str, Any]) -> str:
    tags = job.get("tags") or []
    if isinstance(tags, list) and tags:
        raw = ",".join(safe_string(t, 200) for t in tags[:24] if t is not None)
        return strip_control_chars(raw.replace(";", ","), MAX_LEN["tag"])
    parts = ["forensic", safe_string(job.get("portal", "ingest"), 64), safe_string(job.get("os_type", "unknown"), 64)]
    if job.get("case_id"):
        parts.append(safe_string(job["case_id"], 80))
    return strip_control_chars(",".join(p for p in parts if p), MAX_LEN["tag"])


def _normalize_tag_string(tag: str) -> str:
    """Tags : une seule string ; séparateurs harmonisés en virgule."""
    t = strip_control_chars(tag.replace(";", ","), MAX_LEN["tag"])
    return t


def _flatten_event_data_for_message(ev: dict[str, Any], budget: int = 28000) -> str:
    """Condense champs utiles hors message standard en une ligne texte."""
    chunks: list[str] = []
    used = 0
    skip = {"message", "@timestamp", "datetime", "tags"}

    def add_piece(label: str, val: Any) -> None:
        nonlocal used
        piece = f"{label}={safe_string(val, 400)}"
        if used + len(piece) + 2 > budget:
            return
        chunks.append(piece)
        used += len(piece) + 2

    for key in sorted(ev.keys()):
        if key in skip or key.startswith("_"):
            continue
        val = ev[key]
        if isinstance(val, (dict, list)):
            add_piece(key, val)
        elif val not in (None, "", []):
            add_piece(key, val)
        if used >= budget:
            break
    return " | ".join(chunks)[:budget]


def normalize_event_to_ts_row(ev: dict[str, Any], job: dict[str, Any]) -> dict[str, str]:
    """
    Transforme un événement ECS-like / parser interne en ligne stricte (9 clés).
    Aucune valeur n'est laissée en type non-string (tout est str() côté dict).
    """
    winlog = ev.get("winlog") if isinstance(ev.get("winlog"), dict) else {}
    event_data = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}
    host = ev.get("host") if isinstance(ev.get("host"), dict) else {}
    user_obj = ev.get("user") if isinstance(ev.get("user"), dict) else {}

    hostname = (
        host.get("name")
        or winlog.get("computer_name")
        or event_data.get("Computer")
        or job.get("hostname")
        or ""
    )
    user = (
        (user_obj.get("name") if isinstance(user_obj, dict) else None)
        or event_data.get("TargetUserName")
        or event_data.get("SubjectUserName")
        or event_data.get("User")
        or ""
    )
    event_code = (ev.get("event") or {}).get("code") if isinstance(ev.get("event"), dict) else None
    event_type = (
        event_code
        or winlog.get("event_id")
        or event_data.get("EventID")
        or "log"
    )
    default_source = (
        "Windows-Security"
        if str(job.get("os_type", "")).lower() == "windows"
        else safe_string(job.get("os_type", "forensic"), MAX_LEN["source"])
    )
    log_obj = ev.get("log") if isinstance(ev.get("log"), dict) else {}
    source = (
        winlog.get("provider_name")
        or winlog.get("channel")
        or log_obj.get("logger")
        or default_source
    )
    filename = job.get("filename") or ev.get("source_file") or "upload"

    message = ev.get("message")
    if message is None or (isinstance(message, str) and not str(message).strip()):
        parts: list[str] = []
        et = safe_string(event_type, 64)
        if et:
            parts.append(f"EventID={et}")
        src = safe_string(source, 120)
        if src:
            parts.append(f"Provider={src}")
        for k, v in list(event_data.items())[:14]:
            if v is not None and v != "":
                parts.append(f"{k}={safe_string(v, 240)}")
        message = " | ".join(parts) if parts else _flatten_event_data_for_message(ev)
        if not message:
            message = "empty event"

    message = safe_string(message, MAX_LEN["message"])
    if not message.strip():
        message = "empty event"

    ts_desc = safe_string(ev.get("timestamp_desc") or ev.get("source_file") or filename, MAX_LEN["timestamp_desc"])
    if not ts_desc or ts_desc == "upload":
        ts_desc = DEFAULT_TIMESTAMP_DESC

    row = {
        "datetime": normalize_datetime_utc(ev.get("@timestamp") or ev.get("datetime")),
        "message": message,
        "timestamp_desc": ts_desc,
        "source": safe_string(source, MAX_LEN["source"]) or "forensic",
        "event_type": safe_string(event_type, MAX_LEN["event_type"]) or "log",
        "hostname": safe_string(hostname, MAX_LEN["hostname"]),
        "user": safe_string(user, MAX_LEN["user"]),
        "filename": safe_string(filename, MAX_LEN["filename"]),
        "tag": _normalize_tag_string(ev.get("tag") or _default_tag(job)),
    }
    # Troncature datetime si besoin (format fixe 35 chars typiquement)
    row["datetime"] = row["datetime"][: MAX_LEN["datetime"]]
    return row


def validate_ts_row(row: dict[str, Any]) -> tuple[bool, str]:
    """Valide une ligne logique avant écriture CSV."""
    if set(row.keys()) != set(TIMESKETCH_FIELDNAMES):
        return False, f"bad_keys:{sorted(row.keys())}"
    for k in TIMESKETCH_FIELDNAMES:
        v = row.get(k)
        if not isinstance(v, str):
            return False, f"not_str:{k}:{type(v).__name__}"
    if not _DATETIME_STRICT.match(row["datetime"]):
        return False, f"bad_datetime:{row['datetime'][:48]!r}"
    if not row["message"].strip():
        return False, "empty_message"
    if not row["event_type"].strip():
        return False, "empty_event_type"
    if not row["source"].strip():
        return False, "empty_source"
    if not row["timestamp_desc"].strip():
        return False, "empty_timestamp_desc"
    return True, "ok"


def normalize_csv_mapped_row(norm: dict[str, str], job: dict[str, Any]) -> dict[str, str]:
    """Finalise une ligne issue d'un CSV uploadé (colonnes déjà mappées)."""
    row = {c: strip_control_chars(norm.get(c, ""), MAX_LEN[c]) for c in TIMESKETCH_FIELDNAMES}
    row["datetime"] = normalize_datetime_utc(row.get("datetime"))
    row["datetime"] = row["datetime"][: MAX_LEN["datetime"]]
    if not row["timestamp_desc"].strip():
        row["timestamp_desc"] = DEFAULT_TIMESTAMP_DESC
    if not row["source"].strip():
        row["source"] = "forensic"
    if not row["event_type"].strip():
        row["event_type"] = "log"
    if not row["filename"].strip():
        row["filename"] = safe_string(job.get("filename", ""), MAX_LEN["filename"])
    if not row["tag"].strip():
        row["tag"] = _default_tag(job)
    if not row["message"].strip():
        row["message"] = "csv_row"
    return row


def validate_strict_timesketch_csv(data: bytes) -> tuple[bool, str, int]:
    """
    Valide un fichier CSV complet : en-tête exact (9 colonnes ordre fixe),
    chaque ligne a 9 champs, datetime au format strict, champs non vides requis.
    """
    if not data or len(data) < 20:
        return False, "empty", 0
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return False, f"encoding:{exc}", 0
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return False, "no_header", 0
    fnames = [h.strip().replace("\ufeff", "") for h in reader.fieldnames if h is not None]
    if fnames != list(TIMESKETCH_FIELDNAMES):
        return False, f"bad_header:{fnames}", 0
    count = 0
    for i, row in enumerate(reader):
        if i >= 500_000:
            break
        norm = {c: (row.get(c) or "").strip() if row.get(c) is not None else "" for c in TIMESKETCH_FIELDNAMES}
        ok, msg = validate_ts_row(norm)
        if not ok:
            return False, f"row_{i+2}:{msg}", count
        count += 1
    if count == 0:
        return False, "no_rows", 0
    return True, f"ok:{count}", count


def events_to_strict_csv_bytes(events: list[dict[str, Any]], job: dict[str, Any]) -> tuple[bytes, int, int]:
    """
    Génère CSV UTF-8 avec exactement les 9 colonnes.
    Retourne (csv_bytes, rows_written, rows_skipped).
    """
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(TIMESKETCH_FIELDNAMES),
        extrasaction="ignore",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    written = 0
    skipped = 0
    for ev in events[:500_000]:
        try:
            row = normalize_event_to_ts_row(ev, job)
            ok, msg = validate_ts_row(row)
            if not ok:
                log.warning("Timesketch row skip: %s", msg)
                skipped += 1
                continue
            writer.writerow(row)
            written += 1
        except Exception as exc:
            log.warning("Timesketch row exception: %s", exc)
            skipped += 1
    data = buf.getvalue().encode("utf-8")
    return data, written, skipped
