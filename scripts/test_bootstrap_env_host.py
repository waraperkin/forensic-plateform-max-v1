#!/usr/bin/env python3
"""Tests — patch IP hôte dans .env bootstrap (placeholder 192.0.2.9)."""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

PLACEHOLDER = "192.0.2.9"
HOST_KEYS = (
    "PUBLIC_HOST",
    "TIMESKETCH_EXTERNAL_URL",
    "MISP_PUBLIC_BASE_URL",
    "GRAFANA_ROOT_URL",
    "GRAFANA_DOMAIN",
    "GRAFANA_ALLOWED_ORIGINS",
    "GRAFANA_CSRF_ORIGINS",
    "GRAFANA_CORS_ORIGIN",
)


def should_patch_host_value(key: str, current: str, ip: str) -> str | None:
    if key not in HOST_KEYS:
        return None
    if current == "" or PLACEHOLDER in current or current == PLACEHOLDER:
        defaults = {
            "PUBLIC_HOST": ip,
            "TIMESKETCH_EXTERNAL_URL": f"https://{ip}/timesketch",
            "MISP_PUBLIC_BASE_URL": f"https://{ip}/misp",
            "GRAFANA_ROOT_URL": f"https://{ip}/grafana/",
            "GRAFANA_DOMAIN": ip,
            "GRAFANA_ALLOWED_ORIGINS": f"https://{ip},http://{ip},https://localhost,http://localhost",
            "GRAFANA_CSRF_ORIGINS": f"https://{ip},http://{ip},https://localhost,http://localhost",
            "GRAFANA_CORS_ORIGIN": f"https://{ip},http://{ip},https://localhost,http://localhost",
        }
        return defaults[key]
    return None


def patch_env_text(text: str, ip: str) -> str:
    out: list[str] = []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            out.append(line)
            continue
        key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
        patched = should_patch_host_value(key, val, ip)
        if patched is not None:
            out.append(f"{key}={patched}")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def main() -> int:
    sample = """PUBLIC_HOST=192.0.2.9
GRAFANA_DOMAIN=192.0.2.9
POSTGRES_USER=forensic
CUSTOM_HOST=192.0.2.9
"""
    patched = patch_env_text(sample, "203.0.113.10")
    assert "PUBLIC_HOST=203.0.113.10" in patched
    assert "GRAFANA_DOMAIN=203.0.113.10" in patched
    assert "POSTGRES_USER=forensic" in patched
    assert "CUSTOM_HOST=192.0.2.9" in patched
    print("PASS: bootstrap env host patch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
