#!/usr/bin/env python3
"""Cross-Pivot Engine — pivots ECS OpenSearch ↔ Timesketch."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import requests

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
OS_URL = os.environ.get("OPENSEARCH_URL", os.environ.get("OS_URL", "http://localhost:9200")).rstrip("/")
OSD = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
TS_USER = os.environ.get("TIMESKETCH_USER", "admin")
TS_PASS = os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!")
MASTER_SKETCH = os.environ.get("TS_MASTER_SKETCH_NAME", "[FP] Timesketch Master")
LOG_DIR = ROOT / "logs"
STATE_PATH = LOG_DIR / "crosspivot_state.json"

DEFAULT_SAMPLES = {
    "host": "WIN-MASTER01",
    "user": "analyst",
    "ip": "203.0.113.44",
    "process": "explorer.exe",
    "file_path": r"C:\Windows\Prefetch\CMD.EXE",
    "file_hash": "deadbeef",
    "ioc": "malicious.example.com",
    "alert_dataset": "security.detection",
}


@dataclass
class PivotResult:
    kind: str
    value: str
    os_query: str
    ts_query: str
    os_index: str
    os_url: str
    ts_url: str
    fields: dict[str, str] = field(default_factory=dict)
    os_hits: int = -1
    ts_ok: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "os_query": self.os_query,
            "ts_query": self.ts_query,
            "os_index": self.os_index,
            "os_url": self.os_url,
            "ts_url": self.ts_url,
            "fields": self.fields,
            "os_hits": self.os_hits,
            "ts_ok": self.ts_ok,
        }


def ecs_to_ts_query(query: str) -> str:
    if not query or query.strip() == "*":
        return "*"
    q = query.strip()
    repl = [
        (r"\bevent\.dataset:([^\s\)]+)", r"message:*event.dataset=\1*"),
        (r"\bhost\.name:([^\s\)]+)", r"hostname:\1"),
        (r"\buser\.name:([^\s\)]+)", r"user:\1"),
        (r"\bsource\.ip:([^\s\)]+)", r"message:*source.ip=\1*"),
        (r"\bdestination\.ip:([^\s\)]+)", r"message:*destination.ip=\1*"),
        (r"\bti_match:true\b", r"tag:ti OR message:*ti.ioc*"),
        (r"\bti\.ioc_value:([^\s\)]+)", r"message:*\1*"),
        (r"\bti\.([^:\s]+):([^\s\)]+)", r"message:*ti.\1=\2*"),
        (r"\bprocess\.name:([^\s\)]+)", r"message:*process.name=\1*"),
        (r"\bprocess\.command_line:([^\s\)]+)", r"message:*\1*"),
        (r"\bfile\.path:([^\s\)]+)", r"message:*\1*"),
        (r"\bfile\.hash\.sha256:([^\s\)]+)", r"message:*\1*"),
    ]
    for pat, rep in repl:
        q = re.sub(pat, rep, q)
    return q[:900] if len(q) > 900 else q


def opensearch_discover_url(query: str, index_id: str = "fp-events") -> str:
    q = query.replace("'", "\\'")
    return (
        f"{OSD}/app/discover#/"
        f"?_a=(columns:!(),filters:!(),index:'{index_id}',interval:auto,"
        f"query:(language:kuery,query:'{q}'),sort:!())"
    )


def timesketch_explore_url(query: str, sketch_id: int | None = None) -> str:
    sid = sketch_id or resolve_sketch_id()
    q = quote(query, safe="")
    return f"{TS_URL}/sketch/{sid}/explore/?q={q}"


def resolve_sketch_id() -> int:
    if os.environ.get("TS_CROSSPIVOT_SKETCH_ID", "").isdigit():
        return int(os.environ["TS_CROSSPIVOT_SKETCH_ID"])
    url_file = LOG_DIR / "timesketch_master_sketch.url"
    if url_file.is_file():
        m = re.search(r"/sketch/(\d+)/", url_file.read_text(encoding="utf-8"))
        if m:
            return int(m.group(1))
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from timesketch_master_lib import get_master_sketch_id, ts_client  # noqa: E402

    return get_master_sketch_id(ts_client())


def _finish(kind: str, value: str, os_query: str, ts_query: str, os_index: str, fields: dict) -> PivotResult:
    sid = resolve_sketch_id()
    return PivotResult(
        kind=kind,
        value=value,
        os_query=os_query,
        ts_query=ts_query,
        os_index=os_index,
        os_url=opensearch_discover_url(os_query, os_index),
        ts_url=timesketch_explore_url(ts_query, sid),
        fields=fields,
    )


def pivot_host(host: str | None = None) -> PivotResult:
    v = host or DEFAULT_SAMPLES["host"]
    os_q = f"host.name:{v}"
    ts_q = f"hostname:{v}"
    return _finish("host", v, os_q, ts_q, "fp-events", {"host.name": v, "hostname": v})


def pivot_user(user: str | None = None) -> PivotResult:
    v = user or DEFAULT_SAMPLES["user"]
    os_q = f"user.name:{v}"
    ts_q = f"user:{v}"
    return _finish("user", v, os_q, ts_q, "fp-events", {"user.name": v, "user": v})


def pivot_ip(ip: str | None = None, field: str = "source.ip") -> PivotResult:
    v = ip or DEFAULT_SAMPLES["ip"]
    os_q = f"source.ip:{v} OR destination.ip:{v}"
    ts_q = f"message:*{v}*"
    return _finish("ip", v, os_q, ts_q, "fp-events", {field: v, "source.ip": v})


def pivot_process(command: str | None = None) -> PivotResult:
    v = command or DEFAULT_SAMPLES["process"]
    os_q = f"process.name:{v} OR process.command_line:*{v}*"
    ts_q = f"message:*process.name={v}* OR message:*{v}*"
    return _finish("process", v, os_q, ts_q, "fp-events", {"process.name": v})


def pivot_file(path: str | None = None, sha256: str | None = None) -> PivotResult:
    p = (path or DEFAULT_SAMPLES["file_path"]).replace("\\", "/")
    h = sha256 or ""
    if h:
        os_q = f"file.path:*Prefetch* OR file.hash.sha256:{h} OR message:*{h}*"
        ts_q = f"message:*{h}* OR message:*Prefetch*"
    else:
        os_q = f"file.path:*Prefetch* OR message:*{p.split('/')[-1]}*"
        ts_q = f"message:*Prefetch* OR message:*dfir.mft*"
    return _finish("file", p, os_q, ts_q, "fp-events", {"file.path": p, "file.hash.sha256": h})


def pivot_ioc(ioc_value: str | None = None, ioc_type: str = "domain") -> PivotResult:
    v = ioc_value or DEFAULT_SAMPLES["ioc"]
    os_q = f"ti_match:true AND (ti.ioc_value:{v} OR ti_ioc_value:{v} OR message:*{v}*)"
    ts_q = f"message:*{v}* OR tag:ti"
    return _finish("ioc", v, os_q, ts_q, "fp-events", {"ti.ioc_value": v, "ti.ioc_type": ioc_type})


def pivot_cti(ioc_value: str | None = None) -> PivotResult:
    v = ioc_value or DEFAULT_SAMPLES["ioc"]
    os_q = f"ti.ioc_value:{v} OR ti_match:true"
    ts_q = f"tag:APT OR tag:C2 OR message:*{v}*"
    return _finish("cti", v, os_q, ts_q, "fp-ti-opencti", {"ti.ioc_value": v})


def pivot_alert(dataset: str | None = None) -> PivotResult:
    ds = dataset or DEFAULT_SAMPLES["alert_dataset"]
    os_q = f'event.dataset:"{ds}" OR _index:forensic-alerts*'
    ts_q = f"message:*event.dataset={ds}* OR tag:alert"
    return _finish("alert", ds, os_q, ts_q, "fp-events", {"event.dataset": ds})


PIVOT_BUILDERS = {
    "host": pivot_host,
    "user": pivot_user,
    "ip": pivot_ip,
    "process": pivot_process,
    "file": pivot_file,
    "ioc": pivot_ioc,
    "cti": pivot_cti,
    "alert": pivot_alert,
}


def verify_opensearch(pivot: PivotResult) -> int:
    s = requests.Session()
    s.verify = False
    indices = {
        "fp-events": "forensic-*",
        "fp-ti-opencti": "forensic-ti-opencti*",
        "fp-logs": "forensic-*",
    }.get(pivot.os_index, "forensic-*")
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"query_string": {"query": pivot.os_query, "default_field": "*"}},
    }
    r = s.post(f"{OS_URL}/{indices}/_search", json=body, timeout=45)
    if r.status_code != 200:
        return -1
    total = r.json().get("hits", {}).get("total", {})
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total)


def verify_timesketch(pivot: PivotResult) -> bool:
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from timesketch_master_lib import explore, login  # noqa: E402

    s, h = login()
    sid = resolve_sketch_id()
    ex = explore(s, h, sid, {"query_string": pivot.ts_query, "size": 5})
    return bool(ex.get("ok"))


def verify_pivot(kind: str) -> PivotResult:
    fn = PIVOT_BUILDERS[kind]
    pr = fn()
    pr.os_hits = verify_opensearch(pr)
    pr.ts_ok = verify_timesketch(pr)
    return pr


def save_state(results: list[PivotResult], extra: dict | None = None) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "sketch_id": resolve_sketch_id(),
        "pivots": [p.to_dict() for p in results],
        **(extra or {}),
    }
    STATE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_PATH.is_file():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {}


def pivot_from_ecs_fields(fields: dict[str, Any]) -> PivotResult | None:
    """Choisit le pivot le plus pertinent depuis un document ECS-like."""
    if fields.get("ti.ioc_value") or fields.get("ti_ioc_value"):
        return pivot_ioc(str(fields.get("ti.ioc_value") or fields.get("ti_ioc_value")))
    if fields.get("source.ip") or fields.get("destination.ip"):
        return pivot_ip(str(fields.get("source.ip") or fields.get("destination.ip")))
    if fields.get("host.name") or fields.get("hostname"):
        return pivot_host(str(fields.get("host.name") or fields.get("hostname")))
    if fields.get("user.name") or fields.get("user"):
        return pivot_user(str(fields.get("user.name") or fields.get("user")))
    if fields.get("process.command_line"):
        return pivot_process(str(fields["process.command_line"]))
    if fields.get("file.path"):
        return pivot_file(str(fields["file.path"]), str(fields.get("file.hash.sha256", "")))
    if fields.get("event.dataset"):
        return pivot_alert(str(fields["event.dataset"]))
    return pivot_host()


if __name__ == "__main__":
    import sys

    fails = 0
    for k in PIVOT_BUILDERS:
        pr = verify_pivot(k)
        ok = pr.ts_ok and pr.os_hits >= 0
        print(f"[crosspivot] {k}: os_hits={pr.os_hits} ts_ok={pr.ts_ok}")
        if not ok:
            fails += 1
    sys.exit(0 if fails == 0 else 1)
