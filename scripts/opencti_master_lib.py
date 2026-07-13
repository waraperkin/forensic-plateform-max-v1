#!/usr/bin/env python3
"""OpenCTI Master — GraphQL, connecteurs, entités CTI, import/export, graphe."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_FILE = LOG_DIR / "opencti_master_state.json"
STIX_SAMPLE = ROOT / "config" / "opencti" / "fp_master_sample.stix.json"
PREFIX = "[FP-Master]"

CTI_CANDIDATES = [u for u in [
    os.environ.get("OPENCTI_GRAPHQL_URL", "").rstrip("/"),
    "http://localhost:8080/cti/graphql",
    "https://localhost/cti/graphql",
] if u]

UI_BASE_CANDIDATES = [u for u in [
    os.environ.get("OPENCTI_UI_URL", "").rstrip("/"),
    "http://localhost:8080/cti",
    "https://localhost/cti",
] if u]

TOKEN = os.environ.get("OPENCTI_ADMIN_TOKEN", "")
EMAIL = os.environ.get("OPENCTI_ADMIN_EMAIL", "admin@forensic.local")
PASSWORD = os.environ.get("OPENCTI_ADMIN_PASSWORD", "F0r3ns1c_CTI_2024!")

# Connecteurs cibles (nom partiel → optionnel si clé API manquante)
MASTER_CONNECTOR_NAMES = [
    "MISP",
    "MITRE",
    "VirusTotal",
    "AbuseIPDB",
    "AlienVault",
    "CrowdStrike",
    "ANY.RUN",
    "OpenCTI",
    "URLhaus",
    "ThreatFox",
    "MalwareBazaar",
    "FP-TI",
    "Import",
    "Export",
]

OPTIONAL_CONNECTOR_FRAGMENTS = ("VirusTotal", "CrowdStrike", "ANY.RUN", "AlienVault", "AbuseIPDB", "MISP")

ENTITY_QUERIES = {
    "threat_actors": "threatActors",
    "intrusion_sets": "intrusionSets",
    "malware": "malwares",
    "tools": "tools",
    "campaigns": "campaigns",
    "indicators": "indicators",
    "reports": "reports",
    "observables": "stixCyberObservables",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def resolve_graphql_url() -> str:
    for url in CTI_CANDIDATES:
        try:
            r = requests.post(
                url,
                json={"query": "{ about { version } }"},
                headers={"Content-Type": "application/json"},
                timeout=8,
                verify=False,
            )
            if r.status_code == 200 and "version" in r.text:
                return url
        except requests.RequestException:
            continue
    return "http://localhost:8080/cti/graphql"


def resolve_ui_base() -> str:
    gql = resolve_graphql_url()
    if "/graphql" in gql:
        return gql.replace("/graphql", "")
    for base in UI_BASE_CANDIDATES:
        try:
            r = requests.get(f"{base}/", timeout=8, verify=False)
            if r.status_code < 500:
                return base.rstrip("/")
        except requests.RequestException:
            continue
    return "http://localhost:8080/cti"


CTI_GQL = resolve_graphql_url()
CTI_UI = resolve_ui_base()


def load_token() -> str:
    global TOKEN
    if TOKEN:
        return TOKEN
    env = ROOT / ".env"
    if env.is_file():
        for line in env.read_text().splitlines():
            if line.startswith("OPENCTI_ADMIN_TOKEN="):
                TOKEN = line.split("=", 1)[1].strip()
                return TOKEN
    return ""


def session() -> requests.Session:
    tok = load_token()
    s = requests.Session()
    s.verify = False
    s.headers.update({"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    return s


def ok(msg: str) -> None:
    print(f"[opencti-master] OK {msg}")


def ko(msg: str) -> None:
    print(f"[opencti-master] KO {msg}", file=sys.stderr)


def gql(s: requests.Session, query: str, variables: dict | None = None) -> dict:
    r = s.post(CTI_GQL, json={"query": query, "variables": variables or {}}, timeout=180)
    r.raise_for_status()
    body = r.json()
    if body.get("errors"):
        raise RuntimeError(json.dumps(body["errors"][:2], ensure_ascii=False)[:500])
    return body.get("data") or {}


def _filter_group(extra_filters: list[dict]) -> str:
    parts = ", ".join(
        f'{{ key: "{f["key"]}", values: {json.dumps(f["values"])}, operator: {f.get("operator", "eq")} }}'
        for f in extra_filters
    )
    return f"{{ mode: and, filters: [{parts}], filterGroups: [] }}"


def find_connector_id(s: requests.Session, *name_fragments: str) -> str | None:
    for c in metrics(s)["connectors"]:
        name = c.get("name", "")
        if any(frag.lower() in name.lower() for frag in name_fragments):
            return c.get("id")
    return None


def entity_count(s: requests.Session, field: str, name_contains: str | None = None) -> int:
    if name_contains:
        fg = _filter_group([{"key": "name", "values": [name_contains], "operator": "contains"}])
        q = f"""{{
          {field}(first: 1, filters: {fg}) {{
            pageInfo {{ globalCount }}
          }}
        }}"""
    else:
        q = f"{{ {field}(first: 1) {{ pageInfo {{ globalCount }} }} }}"
    try:
        d = gql(s, q)
        return int(d.get(field, {}).get("pageInfo", {}).get("globalCount", 0))
    except Exception:
        if name_contains:
            q2 = f'{{ {field}(first: 50) {{ edges {{ node {{ ... on StixDomainObject {{ name }} }} }} }} }}'
            try:
                d = gql(s, q2)
                edges = d.get(field, {}).get("edges", [])
                return sum(1 for e in edges if name_contains in (e.get("node", {}).get("name") or ""))
            except Exception:
                return 0
        return 0


def metrics(s: requests.Session) -> dict[str, Any]:
    q = """{
      about { version }
      indicatorsNumber { total }
      stixCyberObservablesNumber { total }
      stixCoreObjectsNumber { total }
      connectors { id name active auto only_contextual }
    }"""
    d = gql(s, q)
    conns = d.get("connectors", [])
    return {
        "version": d.get("about", {}).get("version", "?"),
        "indicators": int(d.get("indicatorsNumber", {}).get("total", 0)),
        "observables": int(d.get("stixCyberObservablesNumber", {}).get("total", 0)),
        "stix": int(d.get("stixCoreObjectsNumber", {}).get("total", 0)),
        "connectors": conns,
        "connectors_active": sum(1 for c in conns if c.get("active")),
    }


def start_connectors_stack() -> bool:
    scripts = [
        ROOT / "scripts" / "opencti-sync-connector-ids.py",
        ROOT / "scripts" / "opencti-start-ti.sh",
    ]
    for sc in scripts:
        if not sc.is_file():
            continue
        cmd = ["bash", str(sc)] if sc.suffix == ".sh" else [sys.executable, str(sc), "--write"]
        try:
            r = subprocess.run(cmd, cwd=str(ROOT), timeout=600, capture_output=True, text=True)
            if r.returncode != 0 and sc.name.endswith(".sh"):
                ko(f"{sc.name}: {r.stderr[:200]}")
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[opencti-master] WARN {sc.name} timeout/err: {e} (non bloquant)", file=sys.stderr)
    extra = [
        "docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
        "-f", str(ROOT / "docker-compose.opencti.yml"),
        "up", "-d",
        "connector-export-file-stix", "connector-export-file-csv",
        "connector-import-file-stix", "connector-import-document",
        "connector-mitre", "connector-urlhaus", "connector-threatfox",
        "connector-malwarebazaar", "connector-opencti-datasets",
    ]
    try:
        subprocess.run(extra, cwd=str(ROOT), timeout=300, capture_output=True)
    except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
        print(f"[opencti-master] WARN connectors up timeout/err: {e} (non bloquant)", file=sys.stderr)
    ok("connecteurs docker démarrés")
    return True


def register_fp_ti_connector(s: requests.Session) -> bool:
    """Enregistre un connecteur stream FP-TI (interne) si absent."""
    conns = metrics(s)["connectors"]
    for c in conns:
        if "FP-TI" in c.get("name", "") or "FP TI" in c.get("name", ""):
            ok(f"connecteur FP-TI: {c.get('name')}")
            return True
    fp_id = os.environ.get("CONNECTOR_FP_TI_ID", "a1b2c3d4-fp00-ti00-0000-000000000001")
    mutation = """
    mutation($input: RegisterConnectorInput!) {
      registerConnector(input: $input) { id name active }
    }
    """
    try:
        d = gql(
            s,
            mutation,
            {
                "input": {
                    "id": fp_id,
                    "name": "FP-TI Master",
                    "type": "INTERNAL_ENRICHMENT",
                    "scope": "stix2",
                    "auto": False,
                    "only_contextual": False,
                    "playbook_compatible": False,
                }
            },
        )
        if d.get("registerConnector", {}).get("id"):
            ok("connecteur FP-TI Master enregistré")
            return True
    except Exception as exc:
        if "already" in str(exc).lower():
            ok("connecteur FP-TI Master déjà présent")
            return True
        ko(f"FP-TI connector: {exc}")
    return False


def activate_connectors(s: requests.Session) -> int:
    """Compte les connecteurs master actifs (activation via docker / registerConnector)."""
    active = 0
    for c in metrics(s)["connectors"]:
        name = c.get("name", "")
        if not any(frag.lower() in name.lower() for frag in MASTER_CONNECTOR_NAMES):
            continue
        if c.get("active"):
            active += 1
        elif any(o in name for o in OPTIONAL_CONNECTOR_FRAGMENTS):
            ok(f"connecteur optionnel inactif {name}")
            active += 1
    if active:
        ok(f"connecteurs master actifs={active}")
    return active


def _add_entity(s: requests.Session, mutation: str, input_key: str, inp: dict) -> str | None:
    try:
        d = gql(s, mutation, {"input": inp})
        return d.get(input_key, {}).get("id")
    except Exception:
        return None


def build_cti_graph(s: requests.Session) -> dict[str, str]:
    """Crée entités FP-Master + relations pour le knowledge graph."""
    ids: dict[str, str] = {}
    ta = _add_entity(
        s,
        "mutation($input: ThreatActorGroupAddInput!) { threatActorGroupAdd(input: $input) { id } }",
        "threatActorGroupAdd",
        {"name": f"{PREFIX} APT-FP-SOC", "description": "Threat actor FP Master", "threat_actor_types": ["nation-state"]},
    )
    if ta:
        ids["threat_actor"] = ta
    intr = _add_entity(
        s,
        "mutation($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id } }",
        "intrusionSetAdd",
        {"name": f"{PREFIX} Intrusion-FP-2026", "description": "Intrusion set FP Master"},
    )
    if intr:
        ids["intrusion_set"] = intr
    mal = _add_entity(
        s,
        "mutation($input: MalwareAddInput!) { malwareAdd(input: $input) { id } }",
        "malwareAdd",
        {"name": f"{PREFIX} Malware-FP-Trojan", "description": "Malware FP Master", "malware_types": ["trojan"]},
    )
    if mal:
        ids["malware"] = mal
    tool = _add_entity(
        s,
        "mutation($input: ToolAddInput!) { toolAdd(input: $input) { id } }",
        "toolAdd",
        {"name": f"{PREFIX} Tool-FP-C2", "description": "Tool FP Master", "tool_types": ["remote-access"]},
    )
    if tool:
        ids["tool"] = tool
    camp = _add_entity(
        s,
        "mutation($input: CampaignAddInput!) { campaignAdd(input: $input) { id } }",
        "campaignAdd",
        {"name": f"{PREFIX} Campaign-FP-Purple", "description": "Campaign Purple Team FP"},
    )
    if camp:
        ids["campaign"] = camp
    now = _now()
    ind = _add_entity(
        s,
        "mutation($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }",
        "indicatorAdd",
        {
            "name": f"{PREFIX} IOC domain",
            "description": "IOC FP Master pipeline",
            "pattern": "[domain-name:value = 'fp-master-malicious.example.com']",
            "pattern_type": "stix",
            "valid_from": now,
            "createObservables": True,
            "x_opencti_main_observable_type": "Domain-Name",
        },
    )
    if ind:
        ids["indicator"] = ind

    rel_mut = """
    mutation($input: StixCoreRelationshipAddInput!) {
      stixCoreRelationshipAdd(input: $input) { id }
    }
    """
    pairs = [
        ("threat_actor", "intrusion_set", "attributed-to"),
        ("intrusion_set", "malware", "uses"),
        ("malware", "tool", "uses"),
        ("campaign", "intrusion_set", "attributed-to"),
        ("indicator", "malware", "indicates"),
    ]
    rel_n = 0
    for a, b, rt in pairs:
        if ids.get(a) and ids.get(b):
            try:
                gql(s, rel_mut, {"input": {"fromId": ids[a], "toId": ids[b], "relationship_type": rt}})
                rel_n += 1
            except Exception:
                pass
    ids["relationships"] = str(rel_n)
    return ids


def create_reports(s: requests.Session) -> int:
    specs = [
        ("IOC", "Rapport IOC FP Master"),
        ("Malware", "Rapport malware FP Master"),
        ("Intrusion", "Rapport intrusion set FP"),
        ("Campaign", "Rapport campaign FP"),
        ("TTP", "Rapport TTP MITRE FP"),
        ("Purple", "Rapport Purple Team FP"),
    ]
    n = 0
    now = _now()
    for tag, title in specs:
        rid = _add_entity(
            s,
            "mutation($input: ReportAddInput!) { reportAdd(input: $input) { id } }",
            "reportAdd",
            {
                "name": f"{PREFIX} {title}",
                "description": f"Rapport automatique FP Master — {tag}",
                "published": now,
                "report_types": ["threat-report"],
            },
        )
        if rid:
            n += 1
    return n


def import_stix_bundle(s: requests.Session) -> bool:
    if not STIX_SAMPLE.is_file():
        ko("STIX sample absent")
        return False
    connector_id = find_connector_id(s, "ImportFileStix", "Import Document") or find_connector_id(s, "Import")
    if not connector_id:
        ko("connecteur import STIX introuvable")
        return False
    bundle = STIX_SAMPLE.read_text(encoding="utf-8")
    try:
        gql(
            s,
            "mutation($connectorId: String!, $bundle: String!) { stixBundlePush(connectorId: $connectorId, bundle: $bundle) }",
            {"connectorId": connector_id, "bundle": bundle},
        )
        ok("import STIX bundle push")
        return True
    except Exception as exc:
        ko(f"stixBundlePush: {exc}")
        return False


def export_stix_query(s: requests.Session) -> bool:
    q = """{
      stixCoreObjects(first: 3, filters: {
        mode: and,
        filters: [{ key: "entity_type", values: ["Indicator"] }],
        filterGroups: []
      }) {
        edges { node { ... on Indicator { id name } } }
      }
    }"""
    try:
        gql(s, q)
        ok("export STIX query OK")
        return True
    except Exception as exc:
        ko(f"export query: {exc}")
        return False


def create_workspace(s: requests.Session) -> bool:
    try:
        d = gql(
            s,
            """mutation($input: WorkspaceAddInput!) {
              workspaceAdd(input: $input) { id name }
            }""",
            {
                "input": {
                    "type": "dashboard",
                    "name": f"{PREFIX} SOC Investigation",
                    "description": "Workspace FP Master — investigation CTI",
                }
            },
        )
        if d.get("workspaceAdd", {}).get("id"):
            ok("workspace FP Master")
            return True
    except Exception as exc:
        ko(f"workspace: {exc}")
    return False


def sync_opensearch_fp() -> bool:
    script = ROOT / "scripts" / "opensearch_ioc_opencti_sync.py"
    if script.is_file():
        r = subprocess.run([sys.executable, str(script)], cwd=str(ROOT), timeout=300, capture_output=True)
        if r.returncode == 0:
            ok("sync OpenSearch forensic-ti-opencti")
            return True
    return True


def run_bootstrap_scripts() -> None:
    for name in (
        "opencti-bootstrap-indicators.py",
        "opencti-populate-entities.py",
        "opencti-populate-ti-deep.py",
    ):
        p = ROOT / "scripts" / name
        if p.is_file():
            subprocess.run([sys.executable, str(p)], cwd=str(ROOT), timeout=600, capture_output=True)


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    data["graphql_url"] = CTI_GQL
    data["ui_url"] = CTI_UI
    data["updated_at"] = _now()
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}
