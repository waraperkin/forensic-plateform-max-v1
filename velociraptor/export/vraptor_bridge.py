#!/usr/bin/env python3
"""Velociraptor bridge — API HTTP + export pipeline."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import requests

from common import CERT_URL, export_collection, now_iso
from lab_simulator import list_artifacts, simulate_collect, simulate_playbook

log = logging.getLogger("velociraptor-bridge")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

VR_API = os.environ.get("VELOCIRAPTOR_API_URL", "https://velociraptor-server:8002").rstrip("/")
VR_CONFIG = os.environ.get("VELOCIRAPTOR_API_CONFIG", "/config/api.config.yaml")
VR_SERVER_CONFIG = os.environ.get("VELOCIRAPTOR_SERVER_CONFIG", "/config/server.config.yaml")
BRIDGE_PORT = int(os.environ.get("VR_BRIDGE_PORT", "8097"))
POLL_INTERVAL = int(os.environ.get("VR_POLL_INTERVAL_SEC", "180"))


def vr_health() -> dict[str, Any]:
    """Vérifie le GUI VR (HTTP plain, 401 = service up). L'API mTLS 8002 n'est pas sonde en GET."""
    gui_url = os.environ.get("VELOCIRAPTOR_GUI_URL", "http://velociraptor-server:8000/velociraptor/app/index.html")
    try:
        r = requests.get(gui_url, timeout=5)
        if r.status_code in (200, 401, 302, 307):
            return {"ok": True, "status": r.status_code, "via": "gui"}
        return {"ok": r.status_code < 500, "status": r.status_code, "via": "gui"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def query_clients() -> list[dict[str, Any]]:
    cfg = VR_CONFIG if os.path.isfile(VR_CONFIG) and os.path.getsize(VR_CONFIG) > 32 else VR_SERVER_CONFIG
    cmd = ["velociraptor", "--config", cfg]
    if cfg == VR_CONFIG:
        cmd.extend(["--api_server_url", VR_API])
    cmd.extend(["query", "--format", "json", "SELECT client_id, os_info.system AS OS FROM clients()"])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if proc.returncode != 0:
            log.debug("query clients stderr: %s", proc.stderr[:500])
            return []
        raw = proc.stdout.strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "rows" in data:
            return data["rows"]
        return [{"raw": raw[:2000]}]
    except Exception as exc:
        log.debug("query clients: %s", exc)
    return []


def collect_artifact(body: dict[str, Any]) -> dict[str, Any]:
    client_id = str(body.get("client_id") or "").strip()
    artifact = str(body.get("artifact") or "Custom.Windows.Sysmon.ForensicMinimal").strip()
    case_id = str(body.get("case_id") or "VR-COLLECT").strip()
    auto_export = bool(body.get("auto_export", True))
    # Lab offline: sans agent live, bascule automatique vers simulation + export
    if not client_id:
        log.info("collect sans client_id → fallback lab offline (%s)", artifact)
        return simulate_collect(
            artifact=artifact,
            case_id=case_id,
            client_id="LAB-OFFLINE",
            auto_export=auto_export,
        )

    cfg = VR_CONFIG if os.path.isfile(VR_CONFIG) and os.path.getsize(VR_CONFIG) > 32 else VR_SERVER_CONFIG
    cmd = ["velociraptor", "--config", cfg]
    if cfg == VR_CONFIG:
        cmd.extend(["--api_server_url", VR_API])
    cmd.extend(["artifacts", "collect", artifact, "--client", client_id, "--format", "json"])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        result: dict[str, Any] = {
            "ok": proc.returncode == 0,
            "client_id": client_id,
            "artifact": artifact,
            "case_id": case_id,
        }
        if proc.stdout.strip():
            try:
                result["collection"] = json.loads(proc.stdout)
            except json.JSONDecodeError:
                result["stdout"] = proc.stdout[:4000]
        if proc.stderr.strip():
            result["stderr"] = proc.stderr[:2000]
        if auto_export:
            export_body = {
                **body,
                "case_id": case_id,
                "artifact": artifact,
                "client_id": client_id,
                "os_type": body.get("os_type") or "unknown",
            }
            result["export"] = export_collection(export_body)
        return result
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "collect timeout", "client_id": client_id, "artifact": artifact}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "client_id": client_id, "artifact": artifact}


class BridgeHandler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"ok": True, "velociraptor": vr_health(), "ts": now_iso()})
        elif self.path == "/clients":
            self._json(200, {"clients": query_clients()})
        elif self.path == "/lab/artifacts":
            self._json(200, list_artifacts())
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            body = {}

        if self.path == "/export/collection":
            self._json(200, export_collection(body))
        elif self.path == "/export/cert":
            from export_to_cert import export_to_cert
            self._json(200, export_to_cert(body))
        elif self.path == "/export/opensearch":
            from export_to_opensearch import export_to_opensearch
            self._json(200, export_to_opensearch(body))
        elif self.path == "/export/timesketch":
            from export_to_timesketch import export_to_timesketch
            self._json(200, export_to_timesketch(body))
        elif self.path == "/export/full":
            self._json(200, export_collection(body))
        elif self.path == "/collect":
            self._json(200, collect_artifact(body))
        elif self.path == "/lab/collect":
            artifact = str(body.get("artifact") or "Custom.Windows.Sysmon.ForensicFull")
            self._json(200, simulate_collect(
                artifact=artifact,
                case_id=str(body.get("case_id") or "LAB-OFFLINE"),
                client_id=str(body.get("client_id") or "LAB-OFFLINE"),
                auto_export=bool(body.get("auto_export", True)),
            ))
        elif self.path == "/lab/collect-full":
            playbook = str(body.get("playbook") or "windows-triage-full")
            self._json(200, simulate_playbook(
                playbook=playbook,
                case_id=str(body.get("case_id") or "LAB-DFIR-FULL"),
                auto_export=bool(body.get("auto_export", True)),
            ))
        else:
            self._json(404, {"error": "not_found"})

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s - %s", self.address_string(), fmt % args)


def poll_loop() -> None:
    while True:
        try:
            clients = query_clients()
            if clients:
                log.info("Velociraptor poll: %s client(s) actif(s)", len(clients))
        except Exception as exc:
            log.warning("poll error: %s", exc)
        time.sleep(POLL_INTERVAL)


def main() -> None:
    t = threading.Thread(target=poll_loop, daemon=True)
    t.start()
    server = HTTPServer(("0.0.0.0", BRIDGE_PORT), BridgeHandler)
    log.info("Velociraptor bridge listening on :%s", BRIDGE_PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
