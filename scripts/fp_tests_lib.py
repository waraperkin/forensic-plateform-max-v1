#!/usr/bin/env python3
"""Bibliothèque partagée — tests E2E / UI FP."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import urllib3

import requests
from fp_runtime_env import (
    CERT_PORTAL_URL,
    CORTEX_URL,
    GRAFANA_URL,
    IT_PORTAL_URL,
    MINIO_CONSOLE_URL,
    MISP_URL,
    OPENSEARCH_URL,
    OPENCTI_UI_URL,
    OSD_NGINX_URL,
    OSD_URL,
    THEHIVE_URL,
    TIMESKETCH_NGINX_URL,
    TIMESKETCH_URL,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FORENSIC_SH = ROOT / "forensic.sh"

OS_URL = OPENSEARCH_URL
OSD = OSD_URL
OSD_NGINX = OSD_NGINX_URL
TS_URL = TIMESKETCH_URL
TS_NGINX = TIMESKETCH_NGINX_URL
GRAFANA = GRAFANA_URL
CERT_URL = CERT_PORTAL_URL
IT_URL = IT_PORTAL_URL
CTI_UI = OPENCTI_UI_URL
MINIO_UI = MINIO_CONSOLE_URL

E2E_STATUS = Path(os.environ.get("FP_E2E_STATUS", "/tmp/fp-e2e-tests-status.json"))
UI_STATUS = Path(os.environ.get("FP_UI_STATUS", "/tmp/fp-ui-tests-status.json"))

UI_BAD_PHRASES = (
    "server side error",
    "could not locate field",
    "could not locate that index-pattern",
    "saved field",
    "something went wrong",
    "application error",
    "internal server error",
    "query error",
    "fatal error",
    "page not found",
    "database error",
)

BLANK_PAGE_MARKERS = ('id="root"></div>', '<div id="root"></div>', "<body></body>")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(prefix: str, msg: str) -> None:
    line = f"[{prefix}] {msg}"
    try:
        print(line, flush=True)
    except OSError:
        safe = line.encode("ascii", errors="replace").decode("ascii")
        print(safe, flush=True)


def step_result(name: str, ok: bool, detail: str = "", extra: dict | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "ok": ok,
        "detail": detail,
        "at": utc_now(),
        **(extra or {}),
    }


def write_status(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def run_py(script: str, timeout: int = 600) -> tuple[bool, str]:
    p = SCRIPTS / script
    if not p.is_file():
        return False, f"script absent: {script}"
    r = subprocess.run([sys.executable, str(p)], cwd=str(ROOT), capture_output=True, text=True, timeout=timeout)
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode == 0, out[-2000:]


def run_forensic(cmd: str, timeout: int = 900) -> tuple[bool, str]:
    if not FORENSIC_SH.is_file():
        return False, "forensic.sh absent"
    r = subprocess.run(
        ["bash", str(FORENSIC_SH), cmd],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode == 0, out[-2000:]


def os_search(index: str, body: dict) -> dict:
    r = requests.post(f"{OS_URL}/{index}/_search", json=body, timeout=30, verify=False)
    r.raise_for_status()
    return r.json()


def os_count(index: str, query: dict | None = None) -> int:
    body: dict[str, Any] = {"query": query or {"match_all": {}}}
    r = requests.post(f"{OS_URL}/{index}/_count", json=body, timeout=20, verify=False)
    if r.status_code != 200:
        return -1
    return int(r.json().get("count", 0))


def check_http_ui(url: str, *, must_contain: tuple[str, ...] = (), label: str = "") -> tuple[bool, str]:
    try:
        r = requests.get(url, timeout=45, verify=False, allow_redirects=True)
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}"
        text = (r.text or "").lower()
        if len(text.strip()) < 80:
            return False, "page blanche / vide"
        for m in BLANK_PAGE_MARKERS:
            if m.lower() in text and len(text) < 500:
                return False, "page blanche (SPA non rendue)"
        for bad in UI_BAD_PHRASES:
            if bad in text:
                return False, bad
        for need in must_contain:
            if need.lower() not in text:
                return False, f"manque `{need}`"
        return True, "OK"
    except Exception as e:
        return False, str(e)


def summarize_steps(steps: list[dict[str, Any]]) -> dict[str, Any]:
    fails = sum(1 for s in steps if not s.get("ok"))
    return {
        "updated_at": utc_now(),
        "global_status": "OK" if fails == 0 else "FAIL",
        "error_count": fails,
        "total_steps": len(steps),
        "steps": steps,
    }


def verify_status_file(path: Path, label: str) -> int:
    if not path.is_file():
        log(label, f"KO status absent: {path}")
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("global_status") != "OK":
        log(label, f"KO global={data.get('global_status')} errors={data.get('error_count')}")
        for s in data.get("steps", []):
            if not s.get("ok"):
                print(f"  - {s.get('name')}: {s.get('detail', '')[:120]}", file=sys.stderr)
        return 1
    log(label, f"OK — 0 erreur ({data.get('total_steps')} étapes)")
    return 0
