"""
Fallback EVTX → log2timeline → upload Plaso vers Timesketch.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger("ingest-worker")

from timesketch_io import api_headers, wait_timeline_ready


def log2timeline_available() -> bool:
    return bool(shutil.which("log2timeline.py") or shutil.which("psteal.py"))


def _log2timeline_bin() -> str | None:
    return shutil.which("log2timeline.py") or shutil.which("psteal.py")


def evtx_to_plaso(evtx_bytes: bytes, label: str = "evidence") -> Path | None:
    """Convertit des bytes EVTX en fichier .plaso via log2timeline."""
    bin_path = _log2timeline_bin()
    if not bin_path:
        log.info("log2timeline absent — fallback Plaso ignoré")
        return None
    work = Path(tempfile.mkdtemp(prefix="fp-plaso-"))
    evtx_path = work / f"{label}.evtx"
    plaso_path = work / f"{label}.plaso"
    evtx_path.write_bytes(evtx_bytes)
    cmd = [
        bin_path,
        "--storage_file",
        str(plaso_path),
        "--status_view",
        "none",
        str(evtx_path),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("PLASO_TIMEOUT_SEC", "900")),
        )
        if proc.returncode != 0:
            log.warning("log2timeline exit %s: %s", proc.returncode, proc.stderr[-500:])
            return None
        if plaso_path.is_file() and plaso_path.stat().st_size > 0:
            return plaso_path
    except subprocess.TimeoutExpired:
        log.error("log2timeline timeout")
    except Exception as exc:
        log.error("log2timeline failed: %s", exc)
    finally:
        try:
            evtx_path.unlink(missing_ok=True)
        except OSError:
            pass
    return None


def upload_plaso_timeline(
    client: dict[str, Any],
    ts_url: str,
    sketch_id: int,
    plaso_path: Path,
    timeline_name: str,
    os_url: str,
) -> tuple[bool, dict[str, Any]]:
    session = client["session"]
    h = api_headers(client, ts_url, sketch_id)
    size = plaso_path.stat().st_size
    with plaso_path.open("rb") as fh:
        files = {"file": (timeline_name, fh, "application/octet-stream")}
        data = {
            "name": timeline_name,
            "sketch_id": str(sketch_id),
            "total_file_size": str(size),
        }
        tr = session.post(
            f"{ts_url}/api/v1/upload/",
            files=files,
            data=data,
            headers=h,
            timeout=3600,
        )
    body: dict[str, Any] = {}
    try:
        body = tr.json()
    except Exception:
        pass
    timeline_id = None
    objs = body.get("objects") or []
    if objs:
        timeline_id = objs[0].get("id")
    ready, ready_msg = wait_timeline_ready(
        session, ts_url, os_url, sketch_id, timeline_id, h, timeout_sec=600
    )
    return tr.status_code < 300 and ready, {
        "status_code": tr.status_code,
        "timeline_id": timeline_id,
        "ready": ready,
        "detail": ready_msg,
        "method": "plaso",
        "plaso_bytes": size,
    }
