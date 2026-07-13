"""Simulateur collecte offline Velociraptor — pas d'agent live requis."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from common import export_collection, now_iso

log = logging.getLogger("velociraptor-lab")

LAB_ROOT = Path(os.environ.get("VR_LAB_DATA", "/lab-data"))
if not LAB_ROOT.is_dir():
    _fallback = Path(__file__).resolve().parent.parent / "lab-data"
    if _fallback.is_dir():
        LAB_ROOT = _fallback
COLLECTIONS_DIR = Path(os.environ.get("VR_LAB_COLLECTIONS", "/lab-collections"))
_fallback_coll = Path(__file__).resolve().parent.parent / "lab-collections"
if not COLLECTIONS_DIR.is_dir() and _fallback_coll.is_dir():
    COLLECTIONS_DIR = _fallback_coll

FORENSIC_FULL_ARTIFACTS = [
    "Custom.Windows.Sysmon.ForensicFull",
    "Custom.Windows.Registry.ForensicFull",
    "Custom.Windows.Memory.Volatility",
    "Custom.Linux.Auth.ForensicFull",
    "Custom.Linux.Network.ForensicFull",
    "Custom.Network.PCAP.ForensicFull",
]

MINIMAL_ARTIFACTS = [
    "Custom.Windows.Sysmon.ForensicMinimal",
    "Custom.Windows.EventLogs.ForensicMinimal",
    "Custom.Linux.Logs.ForensicMinimal",
    "Custom.Network.PCAP.ForensicMinimal",
]

ARTIFACT_FILES: dict[str, tuple[str, str, str]] = {
    "Custom.Windows.Sysmon.ForensicFull": ("windows", "sysmon-full.jsonl", "windows"),
    "Custom.Windows.Registry.ForensicFull": ("windows", "registry-full.jsonl", "windows"),
    "Custom.Windows.Memory.Volatility": ("windows", "memory-volatility.json", "windows"),
    "Custom.Linux.Auth.ForensicFull": ("linux", "auth-full.jsonl", "linux"),
    "Custom.Linux.Network.ForensicFull": ("linux", "network-full.jsonl", "linux"),
    "Custom.Network.PCAP.ForensicFull": ("network", "pcap-summary.json", "network"),
}

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "windows-triage-full": {
        "label": "Windows triage complet",
        "os_type": "windows",
        "client_id": "LAB-WIN-OFFLINE",
        "artifacts": [
            "Custom.Windows.Sysmon.ForensicFull",
            "Custom.Windows.Registry.ForensicFull",
            "Custom.Windows.Memory.Volatility",
        ],
    },
    "linux-triage-full": {
        "label": "Linux triage complet",
        "os_type": "linux",
        "client_id": "LAB-LINUX-OFFLINE",
        "artifacts": [
            "Custom.Linux.Auth.ForensicFull",
            "Custom.Linux.Network.ForensicFull",
        ],
    },
    "memory-forensics": {
        "label": "Memory forensics",
        "os_type": "windows",
        "client_id": "LAB-MEM-OFFLINE",
        "artifacts": ["Custom.Windows.Memory.Volatility"],
    },
    "ioc-sweeping": {
        "label": "IOC sweeping",
        "os_type": "endpoint",
        "client_id": "LAB-IOC-OFFLINE",
        "artifacts": [
            "Custom.Windows.Sysmon.ForensicFull",
            "Custom.Linux.Auth.ForensicFull",
            "Custom.Network.PCAP.ForensicFull",
        ],
    },
    "network-forensics": {
        "label": "Network forensics",
        "os_type": "network",
        "client_id": "LAB-NET-OFFLINE",
        "artifacts": [
            "Custom.Network.PCAP.ForensicFull",
            "Custom.Linux.Network.ForensicFull",
        ],
    },
    "persistence-hunting": {
        "label": "Persistence hunting",
        "os_type": "windows",
        "client_id": "LAB-PERSIST-OFFLINE",
        "artifacts": [
            "Custom.Windows.Registry.ForensicFull",
            "Custom.Windows.Sysmon.ForensicFull",
        ],
    },
}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def load_artifact_events(artifact: str) -> list[dict[str, Any]]:
    spec = ARTIFACT_FILES.get(artifact)
    if not spec:
        return [{
            "@timestamp": now_iso(),
            "message": f"Lab stub — {artifact}",
            "artifact": artifact,
            "source": "velociraptor-lab",
        }]
    subdir, filename, _os = spec
    path = LAB_ROOT / subdir / filename
    if not path.is_file():
        log.warning("lab data missing: %s", path)
        return [{
            "@timestamp": now_iso(),
            "message": f"Missing lab data for {artifact}",
            "artifact": artifact,
            "lab_path": str(path),
        }]
    if filename.endswith(".jsonl"):
        rows = _read_jsonl(path)
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "plugins" in data:
            rows = []
            for plugin in data.get("plugins", []):
                for row in plugin.get("rows", []):
                    rows.append({"plugin": plugin.get("name"), **row, "image": data.get("image")})
        elif isinstance(data, dict) and "flows" in data:
            rows = []
            for flow in data.get("flows", []):
                rows.append({"type": "flow", **flow, "pcap_file": data.get("pcap_file")})
            for alert in data.get("alerts", []):
                rows.append({"type": "alert", **alert, "pcap_file": data.get("pcap_file")})
        elif isinstance(data, list):
            rows = data
        else:
            rows = [data]
    for row in rows:
        row.setdefault("@timestamp", row.get("EventTime") or row.get("timestamp") or now_iso())
        row["artifact"] = artifact
        row["collection_mode"] = "offline-lab"
    return rows


def artifact_os_type(artifact: str) -> str:
    spec = ARTIFACT_FILES.get(artifact)
    return spec[2] if spec else "endpoint"


def list_artifacts() -> dict[str, Any]:
    official_dir = Path(os.environ.get("VR_OFFICIAL_ARTIFACTS", "/artifacts/official"))
    custom_dir = Path(os.environ.get("VR_CUSTOM_ARTIFACTS", "/artifacts/custom"))
    official = sorted(p.stem for p in official_dir.glob("*.yaml")) if official_dir.is_dir() else []
    custom = sorted(p.stem for p in custom_dir.glob("*.yaml")) if custom_dir.is_dir() else []
    return {
        "mode": "offline-lab",
        "forensic_full": FORENSIC_FULL_ARTIFACTS,
        "forensic_minimal": MINIMAL_ARTIFACTS,
        "playbooks": {k: {"label": v["label"], "artifacts": v["artifacts"]} for k, v in PLAYBOOKS.items()},
        "official_count": len(official),
        "custom_count": len(custom),
        "official_sample": official[:20],
        "custom": [a.replace(".yaml", "") for a in custom],
    }


def persist_collection(case_id: str, artifact: str, events: list[dict[str, Any]]) -> str | None:
    try:
        COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)
        safe = artifact.replace(".", "_").replace("/", "_")
        out = COLLECTIONS_DIR / f"{case_id}_{safe}_{now_iso().replace(':', '-')}.json"
        out.write_text(json.dumps({"case_id": case_id, "artifact": artifact, "events": events}, indent=2), encoding="utf-8")
        return str(out)
    except OSError as exc:
        log.warning("persist collection: %s", exc)
        return None


def simulate_collect(
    artifact: str,
    case_id: str = "LAB-OFFLINE",
    client_id: str = "LAB-OFFLINE",
    auto_export: bool = True,
) -> dict[str, Any]:
    events = load_artifact_events(artifact)
    os_type = artifact_os_type(artifact)
    payload = {
        "case_id": case_id,
        "artifact": artifact,
        "client_id": client_id,
        "os_type": os_type,
        "events": events,
        "offline": True,
        "collected_at": now_iso(),
    }
    stored = persist_collection(case_id, artifact, events)
    result: dict[str, Any] = {
        "ok": True,
        "mode": "offline-lab",
        "artifact": artifact,
        "case_id": case_id,
        "client_id": client_id,
        "events_count": len(events),
        "datastore_path": stored,
    }
    if auto_export:
        result["export"] = export_collection(payload)
    return result


def simulate_playbook(
    playbook: str,
    case_id: str = "LAB-DFIR-FULL",
    auto_export: bool = True,
) -> dict[str, Any]:
    spec = PLAYBOOKS.get(playbook)
    if not spec:
        return {"ok": False, "error": f"playbook inconnu: {playbook}", "available": list(PLAYBOOKS)}
    collections = []
    exports: dict[str, Any] = {}
    for artifact in spec["artifacts"]:
        r = simulate_collect(
            artifact=artifact,
            case_id=case_id,
            client_id=spec.get("client_id", "LAB-OFFLINE"),
            auto_export=auto_export,
        )
        collections.append(r)
        if auto_export and r.get("export"):
            exports[artifact] = r["export"]
    return {
        "ok": True,
        "mode": "offline-lab",
        "playbook": playbook,
        "label": spec["label"],
        "case_id": case_id,
        "collections": collections,
        "exports": exports,
        "artifacts_run": len(collections),
    }
