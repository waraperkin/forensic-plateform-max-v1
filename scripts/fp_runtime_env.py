#!/usr/bin/env python3
"""Host-side runtime URLs for local validation scripts.

Docker containers use internal service names, but scripts launched from the
Windows host must respect config/local-ports.env when Docker Desktop ports are
remapped to avoid conflicts with other projects.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_env_file(env_file: Path) -> None:
    if not env_file.exists():
        return
    for raw in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_runtime_env() -> None:
    # Load local port overrides first; then load secrets from .env without
    # overwriting host-side URLs that were already resolved.
    _load_env_file(ROOT / "config" / "local-ports.env")
    _load_env_file(ROOT / ".env")


def _url(url_keys: tuple[str, ...], port_keys: tuple[str, ...], default_port: str, scheme: str, suffix: str = "") -> str:
    for key in url_keys:
        value = os.environ.get(key)
        if value:
            return value.rstrip("/")
    port = default_port
    for key in port_keys:
        value = os.environ.get(key)
        if value:
            port = value
            break
    if (scheme, port) in (("https", "443"), ("http", "80")):
        return f"{scheme}://localhost{suffix}".rstrip("/")
    return f"{scheme}://localhost:{port}{suffix}".rstrip("/")


load_runtime_env()

OPENSEARCH_URL = _url(("OPENSEARCH_URL", "OS_URL"), ("FP_OS_PORT",), "9200", "http")
OSD_URL = _url(("OSD_URL",), ("FP_OSD_PORT",), "5601", "http", "/dashboards")
OSD_NGINX_URL = _url(("OSD_NGINX_URL",), ("FP_HTTPS_PORT",), "443", "https", "/dashboards")
TIMESKETCH_URL = _url(("TIMESKETCH_URL",), ("FP_TIMESKETCH_PORT",), "5000", "http")
TIMESKETCH_NGINX_URL = _url(("TIMESKETCH_NGINX_URL",), ("FP_HTTPS_PORT",), "443", "https", "/timesketch")
GRAFANA_URL = _url(("GRAFANA_URL",), ("FP_HTTPS_PORT",), "443", "https", "/grafana")
CERT_PORTAL_URL = _url(("CERT_PORTAL_URL", "BASE_URL"), ("FP_HTTPS_PORT",), "443", "https")
IT_PORTAL_URL = _url(("IT_PORTAL_URL",), ("FP_HTTPS_PORT",), "443", "https", "/it")
OPENCTI_UI_URL = _url(("OPENCTI_UI_URL",), ("FP_HTTPS_PORT",), "443", "https", "/cti")
THEHIVE_URL = _url(("THEHIVE_URL",), ("FP_HTTPS_PORT",), "443", "https", "/thehive")
CORTEX_URL = _url(("CORTEX_URL",), ("FP_HTTPS_PORT",), "443", "https", "/cortex")
MISP_URL = _url(("MISP_URL",), ("FP_HTTPS_PORT", "FP_MISP_PORT"), "443", "https", "/misp")
MINIO_CONSOLE_URL = _url(("MINIO_CONSOLE_URL",), ("FP_HTTPS_PORT",), "443", "https", "/minio")
