#!/usr/bin/env python3
"""Bibliothèque QA navigateur — mode pessimiste (doute = FAIL)."""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
EXPECTATIONS_PATH = ROOT / "config" / "qa_expectations.yaml"
LOG_DIR = ROOT / "logs" / "fp-browser-qa"
BROWSER_RESULTS = Path(os.environ.get("FP_BROWSER_QA_RESULTS", "/tmp/fp-ui-browser-qa-results.json"))

# Ne pas matcher le mot « error » isolé (trop de faux positifs dans les UIs)
UI_ERROR_PATTERNS = re.compile(
    r"server\s+error|could not locate field|could not locate that index-pattern|"
    r"panel error|request failed|internal error|application error|"
    r"database error|fatal error|something went wrong|query error|failed to load|"
    r"an error occurred|query failed|unable to load",
    re.I,
)

BLANK_MARKERS = (
    '<div id="root"></div>',
    "<body></body>",
    "please upgrade your browser",
)


@dataclass
class BrowserStep:
    name: str
    url: str
    expectation_key: str = ""
    critical: bool = False
    must_contain: tuple[str, ...] = ()
    login: dict[str, str] | None = None
    scroll_passes: int = 4
    reload: bool = True
    extra_clicks: list[str] = field(default_factory=list)
    assert_fn: str = ""  # page_metrics | osd_dashboard | ts_explore | ts_overview | ts_stories | grafana


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_qa(prefix: str, msg: str) -> None:
    print(f"[{prefix}] {msg}", flush=True)


def load_env() -> None:
    env = ROOT / ".env"
    if not env.is_file():
        return
    for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def load_qa_expectations() -> dict[str, Any]:
    if not EXPECTATIONS_PATH.is_file():
        return {"meta": {"pessimistic": True}, "critical_views": []}
    if yaml:
        return yaml.safe_load(EXPECTATIONS_PATH.read_text(encoding="utf-8")) or {}
    return json.loads(json.dumps({"meta": {"pessimistic": True}}))


def is_critical_view(key: str) -> bool:
    exp = load_qa_expectations()
    return key in (exp.get("critical_views") or [])


def get_expectation_rules(key: str) -> dict[str, Any]:
    """Clé dotted: timesketch.explore -> exp['timesketch']['explore']"""
    exp = load_qa_expectations()
    parts = key.split(".")
    node: Any = exp
    for p in parts:
        if not isinstance(node, dict):
            return {}
        node = node.get(p, {})
    return node if isinstance(node, dict) else {}


def service_urls() -> dict[str, str]:
    load_env()
    return {
        "osd": env("OSD_URL", "http://localhost:5601/dashboards").rstrip("/"),
        "ts": env("TIMESKETCH_URL", "http://localhost:5000").rstrip("/"),
        "grafana": env("GRAFANA_URL", "http://localhost:3001").rstrip("/"),
        "opencti": env("OPENCTI_UI_URL", "http://localhost:8080").rstrip("/"),
        "misp": env("MISP_URL", "http://localhost:8090").rstrip("/"),
        "thehive": env("THEHIVE_URL", "http://localhost:9000").rstrip("/"),
        "cortex": env("CORTEX_URL", "http://localhost:9003").rstrip("/"),
        "minio": env("MINIO_CONSOLE_URL", "http://localhost:9001").rstrip("/"),
        "cert": env("CERT_PORTAL_URL", "https://localhost").rstrip("/"),
        "it": env("IT_PORTAL_URL", "https://localhost/it").rstrip("/"),
    }


def strict_check_page_text(text: str, rules: dict, label: str) -> tuple[bool, str]:
    """Pessimiste : toute anomalie → FAIL."""
    low = (text or "").lower()
    meta = load_qa_expectations().get("meta", {})
    min_len = int(rules.get("min_body_text", meta.get("min_body_text_length", 500)))

    if len(low.strip()) < min_len:
        return False, f"{label}: page blanche/vide (len={len(low.strip())} < {min_len})"

    for marker in BLANK_MARKERS:
        if marker in low and len(low) < 1500:
            return False, f"{label}: page blanche ({marker})"

    m = UI_ERROR_PATTERNS.search(text)
    if m:
        return False, f"{label}: {m.group(0)}"

    for bad in rules.get("forbid_phrases", []) or []:
        if bad.lower() in low:
            return False, f"{label}: interdit `{bad}`"

    for need in rules.get("must_contain", []) or []:
        if need.lower() not in low:
            return False, f"{label}: manque `{need}`"

    return True, "OK"


def record_step(steps: list[dict[str, Any]], name: str, ok: bool, detail: str, **extra: Any) -> None:
    if not ok and load_qa_expectations().get("meta", {}).get("pessimistic"):
        detail = f"FAIL(pessimiste): {detail}"
    steps.append(
        {
            "name": name,
            "ok": ok,
            "detail": detail,
            "at": utc_now(),
            **extra,
        }
    )


def write_browser_results(steps: list[dict[str, Any]], engine: str) -> dict[str, Any]:
    fails = sum(1 for s in steps if not s.get("ok"))
    data = {
        "updated_at": utc_now(),
        "engine": engine,
        "global_status": "FAIL" if fails else "OK",
        "error_count": fails,
        "total_steps": len(steps),
        "human_validation_required": True,
        "human_validation_note": (
            "Ne pas conclure « tout est bon » sans revue humaine : pages blanches, "
            "incohérences de chiffres et bugs visuels ne sont pas tous détectables automatiquement."
        ),
        "steps": steps,
    }
    BROWSER_RESULTS.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return data


# Rétrocompat
def check_page_text(text: str, must_contain: tuple[str, ...]) -> tuple[bool, str]:
    rules = {"min_body_text": 200, "must_contain": list(must_contain)}
    return strict_check_page_text(text, rules, "legacy")


def all_browser_journeys() -> list[BrowserStep]:
    u = service_urls()
    exp = load_qa_expectations()
    steps: list[BrowserStep] = []

    osd_map = [
        ("fp-opensearch-security", "osd:Security Operations — Overview", "osd.fp_security_events_ti"),
        ("fp-ti-overview", "osd:Threat Intelligence — Overview", "osd.fp_ti_overview"),
        ("fp-incident-commander-playbook", "osd:Incident Response — Commander", "osd.fp_incident_commander"),
        ("fp-purple-team-playbook", "osd:Purple Teaming — Operations", "osd.fp_purple_team"),
        ("fp-platform-health", "osd:Platform Health — System Metrics", "osd.fp_platform_health"),
    ]
    for did, label, ekey in osd_map:
        steps.append(
            BrowserStep(
                name=label,
                url=f"{u['osd']}/app/dashboards#/view/{did}",
                expectation_key=ekey,
                critical=is_critical_view(ekey),
                must_contain=("opensearch",),
                assert_fn="osd_dashboard",
                scroll_passes=5,
                reload=True,
            )
        )
    steps.append(
        BrowserStep(
            name="osd:Discover",
            url=f"{u['osd']}/app/discover#/",
            expectation_key="osd.discover",
            critical=is_critical_view("osd.discover"),
            must_contain=("discover",),
            assert_fn="page_metrics",
            scroll_passes=4,
        )
    )

    steps += [
        BrowserStep(
            name="ts:Login",
            url=f"{u['ts']}/login/",
            expectation_key="timesketch.login",
            must_contain=("timesketch", "username"),
            scroll_passes=2,
        ),
        BrowserStep(
            name="ts:Home",
            url=f"{u['ts']}/",
            expectation_key="timesketch.home",
            must_contain=("timesketch",),
            scroll_passes=2,
            reload=True,
        ),
    ]

    grafana_uid = exp.get("grafana", {}).get("platform_health", {}).get("dashboard_uid", "fp-platform-health")
    steps.append(
        BrowserStep(
            name="grafana:Platform Health",
            url=f"{u['grafana']}/d/{grafana_uid}",
            expectation_key="grafana.platform_health",
            critical=True,
            must_contain=("grafana",),
            login={"user": env("GRAFANA_ADMIN_USER", "admin"), "pass": env("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")},
            assert_fn="grafana",
            scroll_passes=5,
            reload=True,
        )
    )

    for path, gname in [("/login", "Login"), ("/", "Home"), ("/explore", "Explore")]:
        steps.append(
            BrowserStep(
                name=f"grafana:{gname}",
                url=f"{u['grafana']}{path}",
                must_contain=("grafana",),
                login={"user": env("GRAFANA_ADMIN_USER", "admin"), "pass": env("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")},
                scroll_passes=3,
            )
        )

    for path, mname in [("/events/index", "Events"), ("/attributes/index", "Attributes")]:
        steps.append(
            BrowserStep(name=f"misp:{mname}", url=f"{u['misp']}{path}", must_contain=("misp",), scroll_passes=3)
        )

    steps += [
        BrowserStep(
            name="portal:home",
            url=f"{u['cert']}/",
            expectation_key="portal_cert.home",
            critical=True,
            must_contain=("forensic", "portail"),
            scroll_passes=4,
            reload=True,
        ),
        BrowserStep(
            name="portal:tab-dashboard-cert",
            url=f"{u['cert']}/",
            expectation_key="portal_cert.dashboard_cert",
            critical=True,
            scroll_passes=2,
            extra_clicks=["dashboard-cert"],
            assert_fn="portal_api",
        ),
        BrowserStep(
            name="portal:tab-dashboard-it",
            url=f"{u['cert']}/",
            expectation_key="portal_cert.dashboard_it",
            critical=True,
            scroll_passes=2,
            extra_clicks=["dashboard-it"],
            assert_fn="portal_api",
        ),
        BrowserStep(
            name="portal_it:home",
            url=f"{u['it']}/",
            expectation_key="portal_it.home",
            must_contain=("portail it",),
            scroll_passes=3,
        ),
    ]

    return steps
