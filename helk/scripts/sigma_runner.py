#!/usr/bin/env python3
"""
Sigma runner HELK safe — compile règles Sigma → DSL Elasticsearch → helk-detections-*.
Charge helk/sigma/rules si présent, sinon règles lab intégrées.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

log = logging.getLogger("sigma-runner")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

HELK_ES = os.environ.get("HELK_ES_URL", "http://helk-elasticsearch:9200").rstrip("/")
INTERVAL = int(os.environ.get("SIGMA_INTERVAL_SEC", "300"))
SIGMA_DIR = Path(os.environ.get("SIGMA_DIR", Path(__file__).resolve().parent.parent / "sigma"))
MITRE_PATH = Path(os.environ.get("MITRE_PATH", Path(__file__).resolve().parent.parent / "mitre" / "enterprise-attack.json"))
MAX_RULES = int(os.environ.get("SIGMA_MAX_RULES", "200"))

BUILTIN_RULES = [
    {"id": "sigma-powershell-encoded", "title": "PowerShell Encoded Command", "mitre": ["T1059.001"],
     "index": "helk-sysmon-*", "query": {"query_string": {"query": 'process.command_line:*powershell* AND process.command_line:*-enc*'}}},
    {"id": "sigma-mimikatz", "title": "Mimikatz Execution", "mitre": ["T1003.001"],
     "index": "helk-sysmon-*", "query": {"query_string": {"query": "message:*mimikatz* OR process.command_line:*mimikatz*"}}},
    {"id": "sigma-ssh-bruteforce", "title": "SSH Authentication Failure", "mitre": ["T1110.001"],
     "index": "helk-linux-*", "query": {"query_string": {"query": 'message:*Failed password* OR message:*authentication failure*'}}},
    {"id": "sigma-certutil", "title": "Certutil Download", "mitre": ["T1059.001"],
     "index": "helk-sysmon-*", "query": {"query_string": {"query": "message:*certutil* OR process.command_line:*certutil*"}}},
    {"id": "sigma-zeek-nonstd-port", "title": "Zeek Non-Standard Port", "mitre": ["T1571"],
     "index": "helk-zeek-*", "query": {"query_string": {"query": "destination.port:4444"}}},
    {"id": "sigma-dns-suspicious", "title": "Suspicious DNS Query", "mitre": ["T1071.004"],
     "index": "helk-linux-*", "query": {"query_string": {"query": "message:*evil.test* OR message:*malware*"}}},
]


def load_mitre() -> dict[str, dict]:
    lookup: dict[str, dict] = {}
    if not MITRE_PATH.exists():
        return lookup
    try:
        data = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
        for t in data.get("techniques", []):
            lookup[t["id"]] = t
    except Exception as exc:
        log.warning("MITRE load failed: %s", exc)
    return lookup


def sigma_detection_to_query(detection: dict) -> str | None:
    """Conversion Sigma simplifiée (selection → query_string)."""
    parts: list[str] = []
    for key, val in detection.items():
        if key.startswith("condition") or key == "timeframe":
            continue
        if not isinstance(val, dict):
            continue
        for field, pattern in val.items():
            if isinstance(pattern, list):
                sub = " OR ".join(f"{field}:{p}" if not str(p).startswith("*") else f"{field}:{p}" for p in pattern)
                parts.append(f"({sub})")
            elif isinstance(pattern, str):
                parts.append(f"{field}:{pattern}")
    return " AND ".join(parts) if parts else None


def load_sigma_rules() -> list[dict]:
    rules_dir = SIGMA_DIR / "rules"
    if not rules_dir.exists():
        log.info("Sigma repo absent — règles builtin (%s)", len(BUILTIN_RULES))
        return BUILTIN_RULES

    try:
        import yaml  # type: ignore
    except ImportError:
        log.warning("PyYAML absent — règles builtin")
        return BUILTIN_RULES

    loaded: list[dict] = []
    for yml in sorted(rules_dir.rglob("*.yml"))[:MAX_RULES]:
        try:
            doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
            if not doc or doc.get("status") == "unsupported":
                continue
            det = doc.get("detection") or {}
            q = sigma_detection_to_query(det)
            if not q:
                continue
            logsource = doc.get("logsource") or {}
            idx = "helk-sysmon-*"
            if logsource.get("product") == "linux":
                idx = "helk-linux-*"
            elif logsource.get("product") == "zeek":
                idx = "helk-zeek-*"
            elif logsource.get("product") == "windows":
                idx = "helk-sysmon-*"
            tags = doc.get("tags") or []
            mitre = [t.replace("attack.", "").upper().replace("T", "T") for t in tags if t.startswith("attack.t")]
            mitre = [re.sub(r"^attack\.", "", t, flags=re.I).upper() for t in tags if "attack.t" in t.lower()]
            mitre_ids = []
            for t in mitre:
                m = re.search(r"T\d{4}(?:\.\d{3})?", t, re.I)
                if m:
                    mitre_ids.append(m.group(0).upper())
            loaded.append({
                "id": doc.get("id") or yml.stem,
                "title": doc.get("title") or yml.stem,
                "mitre": mitre_ids or [],
                "index": idx,
                "query": {"query_string": {"query": q}},
                "level": doc.get("level", "medium"),
            })
        except Exception as exc:
            log.debug("skip %s: %s", yml, exc)
    if not loaded:
        return BUILTIN_RULES
    log.info("Sigma rules loaded: %s", len(loaded))
    return loaded


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_rule(rule: dict, mitre: dict[str, dict]) -> list[dict]:
    body = {
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [rule["query"], {"range": {"@timestamp": {"gte": "now-24h"}}}]}},
    }
    try:
        r = requests.post(f"{HELK_ES}/{rule['index']}/_search", json=body, timeout=30)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
    except Exception as exc:
        log.warning("rule %s failed: %s", rule["id"], exc)
        return []

    alerts = []
    for h in hits:
        src = h.get("_source", {})
        tid = (rule.get("mitre") or [None])[0]
        m = mitre.get(tid or "", {})
        alerts.append({
            "@timestamp": now_iso(),
            "event.kind": "alert",
            "event.module": "sigma",
            "rule.id": rule["id"],
            "rule.name": rule["title"],
            "rule.level": rule.get("level", "medium"),
            "rule.mitre": rule.get("mitre", []),
            "threat.technique.id": tid,
            "threat.technique.name": m.get("name"),
            "threat.tactic.name": m.get("tactic"),
            "threat.severity": m.get("severity", rule.get("level")),
            "host.name": src.get("host", {}).get("name") if isinstance(src.get("host"), dict) else src.get("host.name"),
            "message": (src.get("message") or "")[:2000],
            "source_index": h.get("_index"),
            "source_id": h.get("_id"),
            "tags": ["sigma", "helk-detection", "safe-lab"],
        })
    return alerts


def bulk_alerts(alerts: list[dict]) -> int:
    if not alerts:
        return 0
    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index = f"helk-detections-{day}"
    lines = []
    for doc in alerts:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    r = requests.post(f"{HELK_ES}/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}, timeout=60)
    r.raise_for_status()
    items = r.json().get("items", [])
    return sum(1 for it in items if it.get("index", {}).get("status", 500) < 300)


def cycle(rules: list[dict], mitre: dict[str, dict]) -> None:
    total = 0
    for rule in rules:
        alerts = run_rule(rule, mitre)
        n = bulk_alerts(alerts)
        if n:
            log.info("Sigma %s → %s alert(s)", rule["id"], n)
        total += n
    log.info("Sigma cycle — %s detection(s) indexed", total)


def main() -> None:
    import sys
    once = "--once" in sys.argv
    rules = load_sigma_rules()
    mitre = load_mitre()
    log.info("Sigma runner safe mode — %s rules, interval=%ss, once=%s", len(rules), INTERVAL, once)
    if once:
        cycle(rules, mitre)
        return
    while True:
        try:
            cycle(rules, mitre)
        except Exception as exc:
            log.error("sigma cycle error: %s", exc)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
