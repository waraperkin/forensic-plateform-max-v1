#!/usr/bin/env python3
"""
5 use cases forensic E2E — validation livraison CERT.

Exécute des scénarios analyste complets (incident → collecte → analyse → reporting)
et produit un inventaire des erreurs dans reports/cert-use-cases-e2e.json
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_tests_lib import (  # noqa: E402
    CERT_URL,
    OS_URL,
    log,
    os_count,
    os_search,
    step_result,
    summarize_steps,
    write_status,
)
from opensearch_ioc_common import (  # noqa: E402
    bulk_index_ti,
    dedupe_docs,
    ensure_ti_aliases,
    ensure_ti_index_ready,
    ioc_doc,
    os_session,
    ti_index_for_source,
)


def load_env_defaults() -> None:
    """Load .env/local-ports values without overriding the caller shell."""
    for path in (ROOT / ".env", ROOT / "config" / "local-ports.env"):
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_defaults()

FIXTURES = ROOT / "tests" / "fixtures" / "use-cases"
REPORT_PATH = ROOT / "reports" / "cert-use-cases-e2e.json"
BASE = os.environ.get("CERT_PORTAL_URL", os.environ.get("BASE_URL", "https://localhost:8443")).rstrip("/")
ADMIN_USER = os.environ.get("PORTAL_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("PORTAL_ADMIN_PASSWORD", "F0r3ns1c_Portal_2024!")
INGEST_TIMEOUT = int(os.environ.get("UC_INGEST_TIMEOUT", "120"))
HELK_ES_URL = os.environ.get("HELK_ELASTICSEARCH_URL", "http://localhost:19201").rstrip("/")
OPENCTI_GRAPHQL_URL = os.environ.get("OPENCTI_GRAPHQL_URL", f"{BASE}/cti/graphql")
OPENCTI_ADMIN_TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "")
MISP_URL = (os.environ.get("MISP_URL") or os.environ.get("MISP_PUBLIC_BASE_URL") or f"{BASE}/misp").rstrip("/")
MISP_ADMIN_EMAIL = os.environ.get("MISP_ADMIN_EMAIL", "admin@admin.test")
MISP_ADMIN_API_KEY = os.environ.get("MISP_ADMIN_API_KEY", "")


@dataclass
class UseCase:
    id: str
    title: str
    case_id: str
    host: str
    os_type: str
    fixtures: list[str]
    playbook: str
    expected_indices: list[str] = field(default_factory=list)
    iocs: list[dict[str, str]] = field(default_factory=list)
    helk_datasets: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CertClient:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False

    def login(self) -> tuple[bool, str]:
        try:
            r = self.session.post(
                f"{self.base}/api/auth/login",
                json={"username": ADMIN_USER, "password": ADMIN_PASS},
                timeout=30,
            )
            if r.status_code != 200:
                return False, f"HTTP {r.status_code} {r.text[:200]}"
            body = r.json()
            if body.get("mfaRequired"):
                return False, "MFA requis — désactiver MFA pour les tests E2E ou fournir TOTP"
            return True, f"session={body.get('username', ADMIN_USER)}"
        except Exception as exc:
            return False, str(exc)

    def get(self, path: str, timeout: int = 60) -> tuple[int, Any]:
        r = self.session.get(f"{self.base}{path}", timeout=timeout)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text[:500]

    def post_json(self, path: str, body: dict | None = None, timeout: int = 120) -> tuple[int, Any]:
        r = self.session.post(
            f"{self.base}{path}",
            json=body or {},
            timeout=timeout,
        )
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text[:500]

    def generate_it_token(self, case_id: str, os_type: str, max_uses: int = 2) -> tuple[bool, str, str]:
        code, body = self.post_json("/api/tokens/generate", {
            "case_id": case_id,
            "description": f"E2E IT upload {case_id}",
            "expires_in_hours": 24,
            "max_uses": max_uses,
            "analyst": "cert-e2e",
            "os_type": os_type,
        })
        token = body.get("token") if isinstance(body, dict) else None
        url = body.get("it_portal_url") if isinstance(body, dict) else ""
        return code == 200 and bool(token), token or "", url or ""

    def it_upload(self, token: str, files: list[tuple[str, Path]], helk: bool = True) -> tuple[bool, str]:
        multipart = []
        handles = []
        try:
            for name, path in files:
                fh = path.open("rb")
                handles.append(fh)
                multipart.append(("files", (name, fh, "application/octet-stream")))
            data = {
                "submitter_name": "Local IT E2E",
                "submitter_email": "local-it@example.test",
                "notes": "E2E compromised asset logs for CERT analysis",
            }
            if helk:
                data["helk_sync"] = "true"
            r = self.session.post(
                f"{self.base}/it/api/upload",
                headers={"x-it-token": token},
                files=multipart,
                data=data,
                timeout=180,
            )
            if r.status_code not in (200, 201):
                return False, f"HTTP {r.status_code} {r.text[:300]}"
            body = r.json()
            ok = any(x.get("ok") for x in (body.get("results") or []))
            return ok, json.dumps(body)[:500]
        except Exception as exc:
            return False, str(exc)
        finally:
            for fh in handles:
                fh.close()

    def upload(self, case_id: str, files: list[tuple[str, Path]], os_type: str, helk: bool = False) -> tuple[bool, str]:
        multipart = []
        handles = []
        try:
            for name, path in files:
                fh = path.open("rb")
                handles.append(fh)
                multipart.append(("files", (name, fh, "application/octet-stream")))
            data = {
                "case_id": case_id,
                "analyst": "cert-e2e",
                "priority": "high",
                "os_type": os_type,
            }
            if helk:
                data["helk_send"] = "true"
                data["helk_hunt"] = "true"
            r = self.session.post(f"{self.base}/api/upload", files=multipart, data=data, timeout=180)
            if r.status_code not in (200, 201):
                return False, f"HTTP {r.status_code} {r.text[:300]}"
            body = r.json()
            ok = any(x.get("ok") for x in (body.get("results") or []))
            return ok, json.dumps(body)[:400]
        except Exception as exc:
            return False, str(exc)
        finally:
            for fh in handles:
                fh.close()


def wait_case_docs(case_id: str, min_docs: int = 1, timeout_s: int = INGEST_TIMEOUT) -> tuple[bool, int]:
    q = case_query(case_id)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        total = 0
        for idx in ("forensic-uploads*", "forensic-windows*", "forensic-linux*", "forensic-web*", "fp-events*", "forensic-*"):
            try:
                total += os_count(idx, q)
            except Exception:
                pass
        if total >= min_docs:
            return True, total
        time.sleep(5)
    return False, total


def case_query(case_id: str) -> dict:
    return {
        "bool": {
            "should": [
                {"term": {"case_id.keyword": case_id}},
                {"term": {"case_id": case_id}},
                {"match_phrase": {"case_id": case_id}},
            ],
            "minimum_should_match": 1,
        }
    }


def wait_index_docs(index: str, case_id: str, min_docs: int = 1, timeout_s: int = INGEST_TIMEOUT) -> tuple[bool, int]:
    q = case_query(case_id)
    deadline = time.time() + timeout_s
    count = 0
    while time.time() < deadline:
        try:
            count = os_count(index, q)
        except Exception:
            count = -1
        if count >= min_docs:
            return True, count
        time.sleep(5)
    return False, count


def helk_count(case_id: str, dataset: str | None = None) -> int:
    must: list[dict] = [{"bool": {
        "should": [
            {"term": {"case_id.keyword": case_id}},
            {"term": {"case_id": case_id}},
            {"match_phrase": {"case_id": case_id}},
        ],
        "minimum_should_match": 1,
    }}]
    if dataset:
        must.append({"term": {"event.dataset.keyword": dataset}})
    r = requests.post(
        f"{HELK_ES_URL}/helk-*/_count",
        json={"query": {"bool": {"must": must}}},
        timeout=30,
        verify=False,
    )
    if r.status_code == 404:
        return 0
    r.raise_for_status()
    return int(r.json().get("count", 0))


def verify_observability(uc: UseCase) -> None:
    for idx in uc.expected_indices:
        found, cnt = wait_index_docs(idx, uc.case_id, 1)
        record(uc, f"verify_index_{idx}", found, f"docs={cnt}")
    for item in uc.iocs:
        for source in ("opencti", "misp"):
            try:
                cnt = os_count(f"forensic-ti-{source}*", {"term": {"ioc_value": item["value"]}})
            except Exception:
                cnt = -1
            record(uc, f"verify_ioc_{source}_{item['value']}", cnt > 0, f"docs={cnt}")
    if uc.iocs:
        deadline = time.time() + INGEST_TIMEOUT
        ti_matches = 0
        while time.time() < deadline:
            try:
                ti_matches = os_count("forensic-*", {"bool": {"must": [case_query(uc.case_id), {"term": {"ti_match": True}}]}})
            except Exception:
                ti_matches = -1
            if ti_matches > 0:
                break
            time.sleep(5)
        record(uc, "verify_ti_correlation_on_events", ti_matches > 0, f"docs={ti_matches}")
    for dataset in uc.helk_datasets:
        deadline = time.time() + INGEST_TIMEOUT
        cnt = 0
        while time.time() < deadline:
            try:
                cnt = helk_count(uc.case_id, dataset)
            except Exception:
                cnt = 0
            if cnt > 0:
                break
            time.sleep(5)
        record(uc, f"verify_helk_{dataset}", cnt > 0, f"docs={cnt}")


def record(uc: UseCase, name: str, ok: bool, detail: str = "") -> None:
    step = step_result(name, ok, detail)
    uc.steps.append(step)
    if not ok:
        uc.errors.append(f"{name}: {detail}")
    status = "OK" if ok else "FAIL"
    log(uc.id, f"  [{status}] {name} - {detail}")


def seed_ti_indices(iocs: list[dict[str, str]]) -> tuple[bool, str]:
    docs_by_source: dict[str, list[dict[str, Any]]] = {"opencti": [], "misp": []}
    for item in iocs:
        for source in ("opencti", "misp"):
            docs_by_source[source].append(
                ioc_doc(
                    item["type"],
                    item["value"],
                    source,
                    tags=["fp-e2e", item.get("case_id", ""), item.get("scenario", "")],
                    feed="fp-e2e-use-cases",
                    extra={"case_id": item.get("case_id"), "scenario": item.get("scenario")},
                )
            )
    try:
        session = os_session()
        ensure_ti_aliases(session)
        total = 0
        for source, docs in docs_by_source.items():
            docs = dedupe_docs(docs)
            index = ti_index_for_source(source)
            ensure_ti_index_ready(session, index)
            total += bulk_index_ti(session, index, docs)
            bulk_index_ti(session, index.replace(source, "unified"), docs)
        return True, f"docs={total}"
    except Exception as exc:
        return False, str(exc)


def stix_pattern(ioc_type: str, value: str) -> str:
    if ioc_type == "ip":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc_type == "url":
        return f"[url:value = '{value}']"
    if ioc_type == "hash":
        return f"[file:hashes.'SHA-256' = '{value}']"
    return f"[artifact:payload_bin = '{value}']"


def seed_opencti_api(iocs: list[dict[str, str]]) -> tuple[bool, str]:
    if not OPENCTI_ADMIN_TOKEN:
        return False, "OPENCTI_ADMIN_TOKEN absent"
    mutation = """
    mutation IndicatorAdd($input: IndicatorAddInput!) {
      indicatorAdd(input: $input) { id standard_id name pattern }
    }
    """
    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": f"Bearer {OPENCTI_ADMIN_TOKEN}", "Content-Type": "application/json"})
    ok = 0
    errors: list[str] = []
    for item in iocs:
        payload = {
            "query": mutation,
            "variables": {"input": {
                "name": f"FP E2E {item.get('case_id')} {item['value']}",
                "description": f"Forensic platform E2E IOC for {item.get('scenario')}",
                "pattern_type": "stix",
                "pattern": stix_pattern(item["type"], item["value"]),
                "x_opencti_score": 80,
                "valid_from": datetime.now(timezone.utc).isoformat(),
            }},
        }
        try:
            r = session.post(OPENCTI_GRAPHQL_URL, json=payload, timeout=60)
            body = r.json() if r.text else {}
            if r.status_code < 300 and not body.get("errors"):
                ok += 1
            else:
                errors.append(f"{item['value']}: HTTP {r.status_code} {str(body.get('errors') or body)[:160]}")
        except Exception as exc:
            errors.append(f"{item['value']}: {exc}")
    return ok > 0 and not errors, f"created={ok}/{len(iocs)} errors={errors[:2]}"


def misp_type(ioc_type: str) -> tuple[str, str]:
    if ioc_type == "ip":
        return "Network activity", "ip-dst"
    if ioc_type == "domain":
        return "Network activity", "domain"
    if ioc_type == "url":
        return "Network activity", "url"
    if ioc_type == "hash":
        return "Payload delivery", "sha256"
    return "Other", "text"


def resolve_misp_key() -> tuple[str, str]:
    if MISP_ADMIN_API_KEY:
        return MISP_ADMIN_API_KEY, "env"
    key = secrets.token_hex(20)
    candidates: list[str] = []
    for item in (MISP_ADMIN_EMAIL, "admin@admin.test", "admin@forensic.local"):
        if item and item not in candidates:
            candidates.append(item)
    for email in candidates:
        try:
            proc = subprocess.run(
                [
                    "docker", "exec", "forensic-misp", "sudo", "-u", "www-data",
                    "/var/www/MISP/app/Console/cake", "user", "change_authkey", email, key,
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode == 0:
                return key, f"cake:{email}"
        except Exception:
            continue
    return "", "unavailable"


def seed_misp_api(iocs: list[dict[str, str]]) -> tuple[bool, str]:
    key, key_source = resolve_misp_key()
    if not key:
        return False, f"api_key {key_source}"
    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"})
    attrs = []
    for item in iocs:
        category, typ = misp_type(item["type"])
        attrs.append({
            "category": category,
            "type": typ,
            "value": item["value"],
            "to_ids": True,
            "comment": f"FP E2E {item.get('case_id')} {item.get('scenario')}",
        })
    event = {"Event": {
        "info": f"FP E2E forensic use cases {datetime.now(timezone.utc).isoformat()}",
        "distribution": "0",
        "threat_level_id": "2",
        "analysis": "1",
        "published": True,
        "Attribute": attrs,
    }}
    try:
        r = session.post(f"{MISP_URL}/events/add", json=event, timeout=120)
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code} {r.text[:180]}"
        verified = 0
        for item in iocs[:10]:
            sr = session.post(
                f"{MISP_URL}/attributes/restSearch",
                json={"returnFormat": "json", "value": item["value"], "limit": 1},
                timeout=60,
            )
            if sr.status_code < 300 and item["value"] in sr.text:
                verified += 1
        return verified > 0, f"event_http={r.status_code} verified={verified}/{min(len(iocs), 10)} key={key_source}"
    except Exception as exc:
        return False, str(exc)


def all_iocs(cases: list[UseCase]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for uc in cases:
        for item in uc.iocs:
            out.append({**item, "case_id": uc.case_id, "scenario": uc.title})
    return out


def planned_iocs() -> list[dict[str, str]]:
    raw = [
        ("CASE-UC01-RANSOM", "Ransomware Windows", "ip", "203.0.113.50"),
        ("CASE-UC02-WEB", "Compromission web Linux", "ip", "198.51.100.77"),
        ("CASE-UC02-WEB", "Compromission web Linux", "url", "http://lab-linux01/upload.php"),
        ("CASE-UC03-C2", "Correlation C2", "ip", "203.0.113.50"),
        ("CASE-UC03-C2", "Correlation C2", "domain", "c2-panel.evil.test"),
        ("CASE-UC04-LATMOVE", "Mouvement lateral", "ip", "192.0.2.21"),
        ("CASE-UC05-EXFIL", "Exfiltration", "ip", "93.184.216.34"),
        ("CASE-UC05-EXFIL", "Exfiltration", "domain", "sensitive.example.test"),
        ("CASE-UC06-CLOUD", "CloudTrail AWS", "ip", "198.51.100.201"),
        ("CASE-UC06-CLOUD", "CloudTrail AWS", "domain", "cloud-exfil.evil.test"),
        ("CASE-UC07-NETWORK", "Zeek DNS C2", "ip", "10.10.10.10"),
        ("CASE-UC07-NETWORK", "Zeek DNS C2", "domain", "malicious.example.com"),
    ]
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, str]] = []
    for case_id, scenario, typ, value in raw:
        key = (case_id, typ, value)
        if key in seen:
            continue
        seen.add(key)
        out.append({"case_id": case_id, "scenario": scenario, "type": typ, "value": value})
    return out


def run_uc1_ransomware(client: CertClient) -> UseCase:
    """UC1 — Ransomware Windows endpoint (lab-win01)."""
    uc = UseCase(
        id="UC1",
        title="Ransomware Windows — lab-win01",
        case_id="CASE-UC01-RANSOM",
        host="lab-win01",
        os_type="windows",
        fixtures=["uc01-ransomware-sysmon.jsonl", "uc01-ransomware-security.jsonl"],
        playbook="windows-triage-full",
        expected_indices=["forensic-windows*"],
        iocs=[{"type": "ip", "value": "203.0.113.50"}],
        helk_datasets=["windows.sysmon", "windows.events"],
    )
    log(uc.id, f"=== {uc.title} ===")

    code, body = client.post_json("/api/master/incidents", {
        "id": uc.case_id,
        "title": f"[CERT-E2E] {uc.title}",
        "severity": "critical",
        "status": "investigating",
        "case_id": uc.case_id,
        "assignee": "cert-analyst",
    })
    record(uc, "create_incident", code == 200 and body.get("ok"), f"HTTP {code}")

    files = [(f, FIXTURES / f) for f in uc.fixtures]
    ok, detail = client.upload(uc.case_id, files, uc.os_type, helk=True)
    record(uc, "upload_evidence", ok, detail)

    found, cnt = wait_case_docs(uc.case_id, 1)
    record(uc, "ingest_opensearch", found, f"docs={cnt}")
    verify_observability(uc)

    code, body = client.post_json("/api/helk/lab/ingest", timeout=180)
    record(uc, "helk_lab_ingest", code == 200 and body.get("ok", True), f"HTTP {code} {str(body)[:150]}")

    code, body = client.post_json("/api/helk/sync", timeout=180)
    record(uc, "helk_sync_findings", code == 200, f"HTTP {code} synced={body.get('synced', body.get('ok', '?'))}")

    code, body = client.post_json("/api/velociraptor/lab/collect-full", {
        "case_id": uc.case_id,
        "playbook": uc.playbook,
        "hostname": uc.host,
        "auto_export": True,
    }, timeout=300)
    record(uc, "vr_collect_full", code == 200 and body.get("ok", True), f"HTTP {code} events={body.get('events_count', '?')}")

    code, body = client.post_json("/api/velociraptor/export/timesketch", {"case_id": uc.case_id}, timeout=180)
    record(uc, "vr_export_timesketch", code == 200, f"HTTP {code} {str(body)[:120]}")

    try:
        hits = os_search("forensic-*", {"size": 0, "query": {"term": {"case_id.keyword": uc.case_id}}})
        cnt = hits.get("hits", {}).get("total", {})
        n = cnt.get("value", cnt) if isinstance(cnt, dict) else cnt
        record(uc, "verify_forensic_index", n >= 1, f"docs={n}")
    except Exception as exc:
        record(uc, "verify_forensic_index", False, str(exc))

    code, _ = client.session.put(
        f"{client.base}/api/master/incidents/{uc.case_id}",
        json={"status": "contained", "resolution": "Ransomware isolé — UC1 E2E"},
        timeout=30,
    ).status_code, {}
    record(uc, "update_incident_status", code in (200, 201), f"HTTP {code}")

    return uc


def run_uc2_linux_web(client: CertClient) -> UseCase:
    """UC2 — Compromission serveur web Linux (lab-linux01)."""
    uc = UseCase(
        id="UC2",
        title="Compromission web Linux — lab-linux01",
        case_id="CASE-UC02-WEB",
        host="lab-linux01",
        os_type="linux",
        fixtures=["uc02-linux-web.jsonl"],
        playbook="linux-triage-full",
        expected_indices=["forensic-linux*"],
        iocs=[{"type": "ip", "value": "198.51.100.77"}, {"type": "url", "value": "http://lab-linux01/upload.php"}],
        helk_datasets=["linux.syslog"],
    )
    log(uc.id, f"=== {uc.title} ===")

    code, body = client.post_json("/api/master/incidents", {
        "id": uc.case_id,
        "title": f"[CERT-E2E] {uc.title}",
        "severity": "high",
        "status": "investigating",
        "case_id": uc.case_id,
    })
    record(uc, "create_incident", code == 200 and body.get("ok"), f"HTTP {code}")

    ok, detail = client.upload(uc.case_id, [("uc02-linux-web.jsonl", FIXTURES / "uc02-linux-web.jsonl")], "linux", helk=True)
    record(uc, "upload_evidence", ok, detail)

    found, cnt = wait_case_docs(uc.case_id, 1)
    record(uc, "ingest_opensearch", found, f"docs={cnt}")
    verify_observability(uc)

    code, body = client.post_json("/api/helk/lab/ingest", timeout=180)
    record(uc, "helk_lab_ingest", code == 200, f"HTTP {code}")

    code, body = client.post_json("/api/helk/sync", timeout=180)
    record(uc, "helk_sync_findings", code == 200, f"HTTP {code}")

    code, body = client.post_json("/api/velociraptor/lab/collect-full", {
        "case_id": uc.case_id,
        "playbook": uc.playbook,
        "hostname": uc.host,
    }, timeout=300)
    record(uc, "vr_linux_collect", code == 200 and body.get("ok", True), f"HTTP {code}")

    code, _ = client.get(f"/api/helk/hunt-url?hostname={uc.host}&case_id={uc.case_id}")
    record(uc, "helk_hunt_pivot", code == 200, f"HTTP {code}")

    code, _ = client.session.put(
        f"{client.base}/api/master/incidents/{uc.case_id}",
        json={"status": "closed", "resolution": "Webshell supprimé — UC2 E2E"},
        timeout=30,
    ).status_code, {}
    record(uc, "close_incident", code in (200, 201), f"HTTP {code}")

    return uc


def run_uc3_c2_threat(client: CertClient) -> UseCase:
    """UC3 — Corrélation menace / IOC C2 (203.0.113.50)."""
    uc = UseCase(
        id="UC3",
        title="Threat Intel — corrélation C2 203.0.113.50",
        case_id="CASE-UC03-C2",
        host="lab-win01",
        os_type="windows",
        fixtures=["uc03-c2-threat.jsonl"],
        playbook="windows-triage-full",
        expected_indices=["forensic-windows*"],
        iocs=[{"type": "ip", "value": "203.0.113.50"}, {"type": "domain", "value": "c2-panel.evil.test"}],
        helk_datasets=["windows.events"],
    )
    log(uc.id, f"=== {uc.title} ===")

    code, body = client.post_json("/api/master/incidents", {
        "id": uc.case_id,
        "title": f"[CERT-E2E] {uc.title}",
        "severity": "high",
        "status": "open",
        "case_id": uc.case_id,
    })
    record(uc, "create_incident", code == 200 and body.get("ok"), f"HTTP {code}")

    ok, detail = client.upload(uc.case_id, [("uc03-c2-threat.jsonl", FIXTURES / "uc03-c2-threat.jsonl")], "windows", helk=True)
    record(uc, "upload_ioc_logs", ok, detail)

    found, cnt = wait_case_docs(uc.case_id, 1)
    record(uc, "ingest_opensearch", found, f"docs={cnt}")
    verify_observability(uc)

    code, _ = client.get("/api/helk/hunt-url?ioc=203.0.113.50&case_id=" + uc.case_id)
    record(uc, "helk_ioc_pivot", code == 200, f"HTTP {code}")

    code, body = client.post_json("/api/helk/export-cti", {"case_id": uc.case_id, "ioc": "203.0.113.50"}, timeout=120)
    record(uc, "export_ioc_cti", code == 200, f"HTTP {code} {str(body)[:120]}")

    ti_oc = os_count("forensic-ti-opencti*")
    ti_m = os_count("forensic-ti-misp*")
    record(uc, "ti_indices_present", ti_oc >= 0, f"opencti={ti_oc} misp={ti_m}")

    code, body = client.post_json("/api/helk/sync", timeout=180)
    record(uc, "helk_sync", code == 200, f"HTTP {code}")

    det = os_count("helk-detections*")
    record(uc, "helk_detections_index", det >= 0, f"count={det}")

    return uc


def run_uc4_lateral_movement(client: CertClient) -> UseCase:
    """UC4 — Mouvement latéral inter-hôtes."""
    uc = UseCase(
        id="UC4",
        title="Mouvement lateral lab-win01 -> lab-linux01",
        case_id="CASE-UC04-LATMOVE",
        host="lab-win01",
        os_type="windows",
        fixtures=["uc04-lateral-movement.jsonl"],
        playbook="windows-triage-full",
        expected_indices=["forensic-windows*"],
        iocs=[{"type": "ip", "value": "192.0.2.21"}],
        helk_datasets=["windows.events"],
    )
    log(uc.id, f"=== {uc.title} ===")

    code, body = client.post_json("/api/master/incidents", {
        "id": uc.case_id,
        "title": f"[CERT-E2E] {uc.title}",
        "severity": "critical",
        "status": "investigating",
        "case_id": uc.case_id,
    })
    record(uc, "create_incident", code == 200 and body.get("ok"), f"HTTP {code}")

    ok, detail = client.upload(uc.case_id, [("uc04-lateral-movement.jsonl", FIXTURES / "uc04-lateral-movement.jsonl")], "windows", helk=True)
    record(uc, "upload_evidence", ok, detail)

    found, cnt = wait_case_docs(uc.case_id, 1)
    record(uc, "ingest_opensearch", found, f"docs={cnt}")
    verify_observability(uc)

    code, body = client.post_json("/api/helk/sync", timeout=180)
    record(uc, "helk_sync", code == 200, f"HTTP {code}")

    code, body = client.post_json("/api/velociraptor/lab/collect-full", {
        "case_id": uc.case_id,
        "playbook": uc.playbook,
        "hostname": uc.host,
    }, timeout=300)
    record(uc, "vr_collect", code == 200, f"HTTP {code}")

    code, body = client.post_json("/api/helk/export-timesketch", {}, timeout=180)
    record(uc, "helk_export_timesketch", code == 200 and body.get("ok", True), f"HTTP {code} {str(body)[:120]}")

    code, body = client.post_json("/api/master/kb", {
        "title": "[KB] Procédure mouvement latéral PsExec",
        "category": "incident-response",
        "content": "Détection PsExec + corrélation SMB + auth SSH cross-host",
        "case_id": uc.case_id,
    })
    record(uc, "create_kb_article", code == 200 and body.get("ok"), f"HTTP {code}")

    return uc


def run_uc5_full_incident_360(client: CertClient) -> UseCase:
    """UC5 — Incident 360° complet (workflow analyste bout en bout)."""
    uc = UseCase(
        id="UC5",
        title="Incident 360° — workflow DFIR complet",
        case_id="CASE-UC05-EXFIL",
        host="lab-win01",
        os_type="windows",
        fixtures=["uc05-exfiltration.jsonl"],
        playbook="memory-forensics",
        expected_indices=["forensic-windows*"],
        iocs=[{"type": "ip", "value": "93.184.216.34"}, {"type": "domain", "value": "sensitive.example.test"}],
        helk_datasets=["windows.events"],
    )
    log(uc.id, f"=== {uc.title} ===")

    code, body = client.post_json("/api/master/seed", timeout=60)
    record(uc, "seed_master_data", code == 200 and body.get("ok"), f"seeded={body.get('seeded', '?')}")

    code, body = client.post_json("/api/master/incidents", {
        "id": uc.case_id,
        "title": f"[CERT-E2E] Exfiltration données — incident 360°",
        "severity": "critical",
        "status": "investigating",
        "case_id": uc.case_id,
        "assignee": "ir-lead",
    })
    record(uc, "create_incident", code == 200 and body.get("ok"), f"HTTP {code}")

    ok, detail = client.upload(uc.case_id, [("uc05-exfiltration.jsonl", FIXTURES / "uc05-exfiltration.jsonl")], "windows", helk=True)
    record(uc, "upload_evidence", ok, detail)

    found, cnt = wait_case_docs(uc.case_id, 1)
    record(uc, "ingest_opensearch", found, f"docs={cnt}")
    verify_observability(uc)

    for api_path, payload, label in [
        ("/api/helk/lab/ingest", {}, "helk_ingest"),
        ("/api/helk/sync", {}, "helk_sync"),
        ("/api/velociraptor/lab/collect-full", {"case_id": uc.case_id, "playbook": uc.playbook, "hostname": uc.host}, "vr_memory"),
        ("/api/velociraptor/export/full", {"case_id": uc.case_id, "os_type": "windows"}, "vr_export_full"),
        ("/api/velociraptor/export/timesketch", {"case_id": uc.case_id}, "vr_timesketch"),
        ("/api/helk/export-cti", {"case_id": uc.case_id}, "helk_cti"),
    ]:
        code, body = client.post_json(api_path, payload, timeout=300)
        record(uc, label, code == 200, f"HTTP {code} {str(body)[:100]}")

    code, body = client.get(f"/api/master/incidents/{uc.case_id}/events")
    record(uc, "incident_events_api", code == 200, f"events={len(body.get('events', [])) if isinstance(body, dict) else '?'}")

    code, body = client.get("/api/health/global")
    if isinstance(body, dict):
        summary = body.get("summary", {})
        record(uc, "platform_health", summary.get("down", 1) == 0, f"ok={summary.get('ok')}/{summary.get('total')}")
    else:
        record(uc, "platform_health", code == 200, f"HTTP {code}")

    code, _ = client.session.put(
        f"{client.base}/api/master/incidents/{uc.case_id}",
        json={"status": "closed", "resolution": "Exfiltration contenue — UC5 E2E complet"},
        timeout=30,
    ).status_code, {}
    record(uc, "close_incident", code in (200, 201), f"HTTP {code}")

    return uc


def run_uc6_cloud_compromise_it_upload(client: CertClient) -> UseCase:
    """UC6 - CloudTrail AWS compromis transmis par une equipe IT locale."""
    uc = UseCase(
        id="UC6",
        title="CloudTrail AWS - cle IAM compromise",
        case_id="CASE-UC06-CLOUD",
        host="aws-prod-account",
        os_type="cloud",
        fixtures=["uc06-cloudtrail-aws.jsonl"],
        playbook="cloud-triage-full",
        expected_indices=["forensic-cloud*"],
        iocs=[{"type": "ip", "value": "198.51.100.201"}, {"type": "domain", "value": "cloud-exfil.evil.test"}],
        helk_datasets=["cloud.aws.cloudtrail"],
    )
    log(uc.id, f"=== {uc.title} ===")

    code, body = client.post_json("/api/master/incidents", {
        "id": uc.case_id,
        "title": f"[CERT-E2E] {uc.title}",
        "severity": "critical",
        "status": "investigating",
        "case_id": uc.case_id,
        "assignee": "cloud-ir",
    })
    record(uc, "create_incident", code == 200 and body.get("ok"), f"HTTP {code}")

    ok_token, token, token_url = client.generate_it_token(uc.case_id, uc.os_type, max_uses=2)
    record(uc, "generate_it_token", ok_token, token_url)

    if ok_token:
        ok, detail = client.it_upload(token, [("uc06-cloudtrail-aws.jsonl", FIXTURES / "uc06-cloudtrail-aws.jsonl")], helk=True)
        record(uc, "it_upload_cloudtrail", ok, detail)
    else:
        record(uc, "it_upload_cloudtrail", False, "token absent")

    found, cnt = wait_case_docs(uc.case_id, 1)
    record(uc, "ingest_opensearch", found, f"docs={cnt}")
    verify_observability(uc)

    code, body = client.post_json("/api/helk/sync", timeout=180)
    record(uc, "helk_sync", code == 200, f"HTTP {code} {str(body)[:120]}")

    code, _ = client.session.put(
        f"{client.base}/api/master/incidents/{uc.case_id}",
        json={"status": "contained", "resolution": "Cle IAM desactivee - UC6 E2E"},
        timeout=30,
    ).status_code, {}
    record(uc, "update_incident_status", code in (200, 201), f"HTTP {code}")

    return uc


def run_uc7_network_c2_it_upload(client: CertClient) -> UseCase:
    """UC7 - Logs reseau Zeek/DNS compromis transmis par l'IT local."""
    uc = UseCase(
        id="UC7",
        title="Reseau - C2 DNS/HTTP detecte par Zeek",
        case_id="CASE-UC07-NETWORK",
        host="edge-fw01",
        os_type="network",
        fixtures=["uc07-zeek-dns-network.log"],
        playbook="network-triage-full",
        expected_indices=["forensic-network*"],
        iocs=[{"type": "ip", "value": "10.10.10.10"}, {"type": "domain", "value": "malicious.example.com"}],
        helk_datasets=["network.zeek"],
    )
    log(uc.id, f"=== {uc.title} ===")

    code, body = client.post_json("/api/master/incidents", {
        "id": uc.case_id,
        "title": f"[CERT-E2E] {uc.title}",
        "severity": "high",
        "status": "investigating",
        "case_id": uc.case_id,
        "assignee": "network-ir",
    })
    record(uc, "create_incident", code == 200 and body.get("ok"), f"HTTP {code}")

    ok_token, token, token_url = client.generate_it_token(uc.case_id, uc.os_type, max_uses=2)
    record(uc, "generate_it_token", ok_token, token_url)

    if ok_token:
        ok, detail = client.it_upload(token, [("uc07-zeek-dns-network.log", FIXTURES / "uc07-zeek-dns-network.log")], helk=True)
        record(uc, "it_upload_zeek", ok, detail)
    else:
        record(uc, "it_upload_zeek", False, "token absent")

    found, cnt = wait_case_docs(uc.case_id, 1)
    record(uc, "ingest_opensearch", found, f"docs={cnt}")
    verify_observability(uc)

    code, _ = client.get(f"/api/helk/hunt-url?hostname={uc.host}&ioc=malicious.example.com&case_id={uc.case_id}")
    record(uc, "helk_ioc_pivot", code == 200, f"HTTP {code}")

    code, _ = client.session.put(
        f"{client.base}/api/master/incidents/{uc.case_id}",
        json={"status": "contained", "resolution": "Blocage C2 DNS/HTTP - UC7 E2E"},
        timeout=30,
    ).status_code, {}
    record(uc, "update_incident_status", code in (200, 201), f"HTTP {code}")

    return uc


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="7 use cases forensic E2E CERT")
    parser.add_argument("--bootstrap-only", action="store_true", help="Seed IOCs OpenSearch/OpenCTI/MISP only")
    args = parser.parse_args()

    if args.bootstrap_only or os.environ.get("UC_BOOTSTRAP_ONLY") == "1":
        log("cert-uc", "=== Bootstrap IOC 7 UC (OpenSearch TI + OpenCTI + MISP) ===")
        preflight_steps: list[dict[str, Any]] = []
        for name, func in [
            ("seed_ioc_opensearch_ti", seed_ti_indices),
            ("seed_ioc_opencti_api", seed_opencti_api),
            ("seed_ioc_misp_api", seed_misp_api),
        ]:
            ok, detail = func(planned_iocs())
            preflight_steps.append(step_result(name, ok, detail))
            log("cert-uc", f"  [{'OK' if ok else 'FAIL'}] {name} - {detail}")
        all_ok = all(s.get("ok") for s in preflight_steps)
        write_status(REPORT_PATH, {"ok": all_ok, "mode": "bootstrap-only", "preflight_steps": preflight_steps, "at": utc_now()})
        return 0 if all_ok else 1

    log("cert-uc", f"=== 7 Use Cases Forensic E2E @ {BASE} ===")
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    client = CertClient(BASE)
    ok_login, login_detail = client.login()
    if not ok_login:
        log("cert-uc", f"ECHEC login: {login_detail}")
        write_status(REPORT_PATH, {"ok": False, "error": login_detail, "at": utc_now()})
        return 1
    log("cert-uc", f"Login OK - {login_detail}")

    preflight_steps: list[dict[str, Any]] = []
    for name, func in [
        ("seed_ioc_opensearch_ti", seed_ti_indices),
        ("seed_ioc_opencti_api", seed_opencti_api),
        ("seed_ioc_misp_api", seed_misp_api),
    ]:
        ok, detail = func(planned_iocs())
        preflight_steps.append(step_result(name, ok, detail))
        log("cert-uc", f"  [{'OK' if ok else 'FAIL'}] {name} - {detail}")

    use_cases = [
        run_uc1_ransomware(client),
        run_uc2_linux_web(client),
        run_uc3_c2_threat(client),
        run_uc4_lateral_movement(client),
        run_uc5_full_incident_360(client),
        run_uc6_cloud_compromise_it_upload(client),
        run_uc7_network_c2_it_upload(client),
    ]

    all_errors: list[dict] = []
    for s in preflight_steps:
        if not s.get("ok"):
            all_errors.append({"use_case": "PREFLIGHT", "case_id": "-", "error": f"{s.get('name')}: {s.get('detail')}"})
    summary_rows = []
    for uc in use_cases:
        passed = sum(1 for s in uc.steps if s.get("ok"))
        total = len(uc.steps)
        summary_rows.append({
            "id": uc.id,
            "title": uc.title,
            "case_id": uc.case_id,
            "passed": passed,
            "total": total,
            "ok": passed == total and not uc.errors,
            "errors": uc.errors,
        })
        for err in uc.errors:
            all_errors.append({"use_case": uc.id, "case_id": uc.case_id, "error": err})

    report = {
        "ok": all(s.get("ok") for s in preflight_steps) and all(not uc.errors for uc in use_cases),
        "at": utc_now(),
        "base_url": BASE,
        "preflight_steps": preflight_steps,
        "use_cases": summary_rows,
        "steps_detail": {uc.id: uc.steps for uc in use_cases},
        "errors_inventory": all_errors,
        "totals": summarize_steps(preflight_steps + [s for uc in use_cases for s in uc.steps]),
    }
    write_status(REPORT_PATH, report)

    log("cert-uc", f"Rapport: {REPORT_PATH}")
    for row in summary_rows:
        status = "PASS" if row["ok"] else "FAIL"
        log("cert-uc", f"  [{status}] {row['id']} {row['case_id']} - {row['passed']}/{row['total']}")

    if all_errors:
        log("cert-uc", f"=== Inventaire erreurs ({len(all_errors)}) ===")
        for e in all_errors:
            log("cert-uc", f"  • [{e['use_case']}] {e['error']}")

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
