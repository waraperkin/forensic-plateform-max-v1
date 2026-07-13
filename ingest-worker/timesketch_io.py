"""Timesketch API — auth, upload, explore, validation, réparation."""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable

import requests

from timesketch_normalizer import validate_strict_timesketch_csv

log = logging.getLogger("ingest-worker")

UPLOAD_RETRIES = int(__import__("os").environ.get("TIMESKETCH_UPLOAD_RETRIES", "3"))
UPLOAD_RETRY_DELAY = float(__import__("os").environ.get("TIMESKETCH_UPLOAD_RETRY_DELAY", "5"))


def _retry_request(
    fn: Callable[[], requests.Response],
    label: str,
    max_retries: int = UPLOAD_RETRIES,
) -> requests.Response:
    last: requests.Response | None = None
    for attempt in range(1, max_retries + 1):
        try:
            last = fn()
            if last.status_code < 500:
                return last
            log.warning(
                "Timesketch %s HTTP %s (tentative %s/%s): %s",
                label,
                last.status_code,
                attempt,
                max_retries,
                (last.text or "")[:200],
            )
        except requests.RequestException as exc:
            log.warning(
                "Timesketch %s erreur réseau (%s/%s): %s",
                label,
                attempt,
                max_retries,
                exc,
            )
        if attempt < max_retries:
            time.sleep(UPLOAD_RETRY_DELAY * attempt)
    if last is None:
        raise RuntimeError(f"Timesketch {label}: aucune réponse")
    return last


def login_session(ts_url: str, user: str, password: str) -> dict[str, Any] | None:
    try:
        session = requests.Session()
        r = session.get(f"{ts_url}/login/", timeout=20)
        m = re.search(r'csrf-token" content="([^"]+)"', r.text) or re.search(
            r'name="csrf_token"[^>]*value="([^"]+)"', r.text
        )
        if not m:
            log.warning("Timesketch: CSRF introuvable sur /login/")
            return None
        csrf = m.group(1)
        session.post(
            f"{ts_url}/login/",
            data={"username": user, "password": password},
            headers={"Referer": f"{ts_url}/login/"},
            timeout=25,
            allow_redirects=True,
        )
        home = session.get(f"{ts_url}/", timeout=15)
        m2 = re.search(r'csrf-token" content="([^"]+)"', home.text) or re.search(
            r'name="csrf_token"[^>]*value="([^"]+)"', home.text
        )
        if m2:
            csrf = m2.group(1)
        return {"session": session, "csrf": csrf}
    except Exception as exc:
        log.warning("Timesketch login failed: %s", exc)
        return None


def api_headers(client: dict[str, Any], ts_url: str, sketch_id: int | None = None) -> dict[str, str]:
    referer = f"{ts_url}/sketch/{sketch_id}/explore/" if sketch_id else f"{ts_url}/"
    return {
        "X-CSRFToken": client["csrf"],
        "Referer": referer,
    }


def _fetch_all_sketch_objects(
    session: requests.Session, ts_url: str, headers: dict[str, str]
) -> list[dict[str, Any]]:
    """Parcourt toutes les pages `/api/v1/sketches/` (défaut ~10 sketchs par page)."""
    sketches: list[dict[str, Any]] = []
    page = 1
    while True:
        r = session.get(
            f"{ts_url}/api/v1/sketches/",
            params={"page": page},
            headers=headers,
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        sketches.extend(data.get("objects", []))
        meta = data.get("meta") or {}
        if not meta.get("has_next"):
            break
        page = int(meta.get("next_page") or page + 1)
    return sketches


def get_or_create_sketch(
    client: dict[str, Any], ts_url: str, sketch_name: str, description: str = ""
) -> int | None:
    session = client["session"]
    h = api_headers(client, ts_url)
    all_sketches = _fetch_all_sketch_objects(session, ts_url, h)
    sid = next(
        (s["id"] for s in all_sketches if s.get("name") == sketch_name),
        None,
    )
    if sid:
        return sid
    cr = session.post(
        f"{ts_url}/api/v1/sketches/",
        json={"name": sketch_name, "description": description or sketch_name},
        headers={**h, "Content-Type": "application/json"},
        timeout=25,
    )
    cr.raise_for_status()
    body = cr.json()
    return body.get("objects", [{}])[0].get("id") or body.get("id")


def upload_csv_timeline(
    client: dict[str, Any],
    ts_url: str,
    sketch_id: int,
    csv_name: str,
    csv_data: bytes,
) -> tuple[bool, dict[str, Any]]:
    session = client["session"]
    h = api_headers(client, ts_url, sketch_id)
    ok_csv, val_msg, row_n = validate_strict_timesketch_csv(csv_data)
    if not ok_csv:
        log.error(
            "Timesketch upload refusé — CSV invalide sketch=%s (%s) rows=%s",
            sketch_id,
            val_msg,
            row_n,
        )
        return False, {
            "status_code": 400,
            "timeline_id": None,
            "body": {"error": val_msg},
            "method": "csv",
            "validation": val_msg,
        }
    log.info("Timesketch CSV validé sketch=%s lignes=%d", sketch_id, row_n)
    data = {
        "name": csv_name,
        "sketch_id": str(sketch_id),
        "total_file_size": str(len(csv_data)),
        "delimiter": ",",
    }

    def _post():
        files = {"file": (csv_name, csv_data, "text/csv; charset=utf-8")}
        return session.post(
            f"{ts_url}/api/v1/upload/",
            files=files,
            data=data,
            headers=h,
            timeout=600,
        )

    tr = _retry_request(_post, f"upload_csv sketch={sketch_id}")
    body: dict[str, Any] = {}
    try:
        body = tr.json()
    except Exception as exc:
        log.error("Timesketch upload JSON invalide: %s body=%s", exc, (tr.text or "")[:300])
    if tr.status_code >= 300:
        log.error(
            "Timesketch upload_csv échec HTTP %s sketch=%s: %s",
            tr.status_code,
            sketch_id,
            (tr.text or "")[:400],
        )
    timeline_id = None
    objs = body.get("objects") or []
    if objs:
        timeline_id = objs[0].get("id")
    return tr.status_code < 300, {
        "status_code": tr.status_code,
        "timeline_id": timeline_id,
        "task_id": body.get("meta", {}).get("task_id"),
        "body": body,
        "method": "csv",
    }


def delete_timeline(
    session: requests.Session,
    ts_url: str,
    sketch_id: int,
    timeline_id: int,
    headers: dict[str, str],
) -> bool:
    """Supprime une timeline cassée avant réimport."""
    try:
        r = session.delete(
            f"{ts_url}/api/v1/sketches/{sketch_id}/timelines/{timeline_id}/",
            headers=headers,
            timeout=30,
        )
        if r.status_code in (200, 204, 404):
            log.info("Timeline %s supprimée (sketch %s)", timeline_id, sketch_id)
            return True
        log.warning("delete timeline %s: HTTP %s", timeline_id, r.status_code)
    except Exception as exc:
        log.warning("delete timeline %s: %s", timeline_id, exc)
    return False


def prune_failed_timelines(
    session: requests.Session,
    ts_url: str,
    sketch_id: int,
    headers: dict[str, str],
    os_url: str,
    prune_empty_index: bool = False,
) -> int:
    """Supprime les timelines en échec (status ``fail``).

    Si ``prune_empty_index`` est True (mode réparation), supprime aussi les
    timelines dont l'index OpenSearch existe mais est vide — sinon on ne retire
    que les ``fail`` pour éviter de supprimer une timeline encore en cours
    d'indexation.
    """
    removed = 0
    detail = session.get(
        f"{ts_url}/api/v1/sketches/{sketch_id}/", headers=headers, timeout=20
    ).json().get("objects", [{}])[0]
    for tl in detail.get("timelines", []):
        st = (tl.get("status") or [{}])[-1].get("status", "")
        idx = (tl.get("searchindex") or {}).get("index_name", "")
        cnt = 0
        if idx:
            try:
                cnt = requests.get(f"{os_url}/{idx}/_count", timeout=10).json().get("count", 0)
            except Exception:
                cnt = 0
        remove = st == "fail" or (prune_empty_index and idx and cnt == 0)
        if remove:
            if delete_timeline(session, ts_url, sketch_id, tl["id"], headers):
                removed += 1
    return removed


def wait_timeline_ready(
    session: requests.Session,
    ts_url: str,
    os_url: str,
    sketch_id: int,
    timeline_id: int | None,
    headers: dict[str, str],
    timeout_sec: int = 300,
) -> tuple[bool, str]:
    if not timeline_id:
        return False, "no_timeline_id"
    deadline = time.time() + timeout_sec
    last_status = "unknown"
    while time.time() < deadline:
        try:
            r = session.get(
                f"{ts_url}/api/v1/sketches/{sketch_id}/",
                headers=headers,
                timeout=20,
            )
            r.raise_for_status()
            for tl in r.json().get("objects", [{}])[0].get("timelines", []):
                if tl.get("id") != timeline_id:
                    continue
                last_status = (tl.get("status") or [{}])[-1].get("status", "unknown")
                idx = (tl.get("searchindex") or {}).get("index_name", "")
                if last_status == "fail":
                    err = ""
                    for ds in tl.get("datasources", []):
                        err = ds.get("error_message", "") or err
                    return False, f"fail:{err[:200]}"
                if last_status == "ready" and idx:
                    cnt = requests.get(f"{os_url}/{idx}/_count", timeout=15).json().get("count", 0)
                    if cnt > 0:
                        return True, f"ready:{cnt}"
        except Exception as exc:
            last_status = str(exc)
        time.sleep(5)
    return False, f"timeout:{last_status}"


def verify_sketch_explore(
    session: requests.Session,
    ts_url: str,
    sketch_id: int,
    headers: dict[str, str],
    os_url: str,
) -> tuple[bool, str]:
    """
    Reproduit les appels UI (explore + chronology) et vérifie index + page HTML.
    """
    ar = session.get(
        f"{ts_url}/api/v1/sketches/{sketch_id}/analyzer/", headers=headers, timeout=30
    )
    if ar.status_code != 200:
        return False, f"analyzer_http_{ar.status_code}:{(ar.text or '')[:80]}"
    detail = session.get(
        f"{ts_url}/api/v1/sketches/{sketch_id}/", headers=headers, timeout=20
    ).json().get("objects", [{}])[0]
    timelines = detail.get("timelines", [])
    if not timelines:
        return False, "no_timelines"
    for tl in timelines:
        st = (tl.get("status") or [{}])[-1].get("status", "")
        idx = (tl.get("searchindex") or {}).get("index_name", "")
        if st == "fail":
            return False, f"timeline_fail:{tl.get('name')}"
        if idx:
            try:
                cnt = requests.get(f"{os_url}/{idx}/_count", timeout=15).json().get("count", 0)
                if cnt == 0:
                    return False, f"index_empty:{idx}"
            except Exception as exc:
                return False, f"index_check:{exc}"

    payloads = [
        {"query_string": "*", "filter": {}},
        {
            "query_string": "*",
            "filter": {},
            "fields": [{"field": "datetime", "type": "datetime"}],
            "chronology": True,
            "order": "asc",
        },
        {
            "query_string": "*",
            "filter": {
                "indices": ["_all"],
                "fields": [
                    {"field": "datetime", "type": "datetime"},
                    {"field": "message", "type": "text"},
                ],
            },
            "chronology": True,
        },
    ]
    h = {**headers, "Content-Type": "application/json", "Referer": f"{ts_url}/sketch/{sketch_id}/explore/"}
    for i, payload in enumerate(payloads):
        er = session.post(
            f"{ts_url}/api/v1/sketches/{sketch_id}/explore/",
            json=payload,
            headers=h,
            timeout=90,
        )
        if er.status_code != 200:
            return False, f"explore_{i}_http_{er.status_code}:{er.text[:120]}"
        total = er.json().get("meta", {}).get("es_total_count", 0)
        if total < 1:
            return False, f"explore_{i}_zero_events"

    ui = session.get(f"{ts_url}/sketch/{sketch_id}/explore/", timeout=30)
    if "Server side error" in ui.text:
        return False, "ui_server_side_error"
    return True, f"ok_events={total}"
