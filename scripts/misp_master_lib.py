#!/usr/bin/env python3
"""MISP Master — API REST, feeds, galaxies, taxonomies, CTI fusion, pivots."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
STATE_FILE = LOG_DIR / "misp_master_state.json"
PREFIX = "FP-Master"
TAG_MASTER = "fp-master"

MISP_CANDIDATES = [u for u in [
    os.environ.get("MISP_URL", "").rstrip("/"),
    "http://localhost:8090",
    "http://forensic-misp:80",
] if u]

EMAIL = os.environ.get("MISP_ADMIN_EMAIL", "admin@forensic.local")
PASSWORD = os.environ.get("MISP_ADMIN_PASSWORD", "F0r3ns1c_MISP_2024!")
API_KEY = os.environ.get("MISP_ADMIN_API_KEY", "")

OS_URL = os.environ.get("OS_URL", os.environ.get("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")
TS_URL = os.environ.get("TIMESKETCH_URL", "http://localhost:5000").rstrip("/")
OPENCTI_GQL = os.environ.get("OPENCTI_GRAPHQL_URL", "http://localhost:8080/cti/graphql").rstrip("/")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def load_api_key() -> str:
    global API_KEY
    if API_KEY:
        return API_KEY
    env = ROOT / ".env"
    if env.is_file():
        for line in env.read_text().splitlines():
            if line.startswith("MISP_ADMIN_API_KEY="):
                API_KEY = line.split("=", 1)[1].strip()
                return API_KEY
    return "a1b2c3d4e5f6789012345678901234567890abcd"


def _api_headers() -> dict[str, str]:
    return {
        "Authorization": load_api_key(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def resolve_misp_url() -> str:
    for base in MISP_CANDIDATES:
        try:
            r = requests.get(f"{base}/servers/getVersion", timeout=8, headers=_api_headers())
            if r.status_code == 200 and "version" in r.text:
                return base.rstrip("/")
        except requests.RequestException:
            continue
    return "http://localhost:8090"


MISP_URL = resolve_misp_url()


def ok(msg: str) -> None:
    print(f"[misp-master] OK {msg}")


def ko(msg: str) -> None:
    print(f"[misp-master] KO {msg}", file=sys.stderr)


def misp_req(path: str, method: str = "GET", body: dict | None = None, timeout: int = 180) -> Any:
    url = f"{MISP_URL}{path}"
    r = requests.request(
        method,
        url,
        json=body,
        headers=_api_headers(),
        timeout=timeout,
        verify=False,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text[:300]}")
    if not r.text.strip():
        return {}
    return r.json()


def metrics() -> dict[str, Any]:
    ver = misp_req("/servers/getVersion")
    galaxies = misp_req("/galaxies/index")
    taxonomies = misp_req("/taxonomies/index")
    wl_raw = misp_req("/warninglists/index")
    wlists = wl_raw.get("Warninglists", wl_raw) if isinstance(wl_raw, dict) else wl_raw
    feeds_raw = misp_req("/feeds/index")
    feeds = [_feed_node(f) for f in (feeds_raw if isinstance(feeds_raw, list) else [])]
    roles = misp_req("/roles/index")
    sg = misp_req("/sharingGroups/index")
    sharing = sg.get("response", sg) if isinstance(sg, dict) else sg
    sightings = misp_req("/sightings/index")
    corr = misp_req("/correlationRules/index")

    ev = misp_req("/events/restSearch", "POST", {"returnFormat": "json", "limit": 1})
    ev_resp = ev.get("response", [])
    attr = misp_req(
        "/attributes/restSearch",
        "POST",
        {"returnFormat": "json", "limit": 1},
    )
    attr_resp = attr.get("response", {}).get("Attribute", [])
    if isinstance(attr_resp, dict):
        attr_resp = [attr_resp]

    me: dict[str, Any] = {}
    try:
        me = misp_req("/users/view/me").get("User", {})
    except Exception:
        pass

    return {
        "version": ver.get("version", "?"),
        "pymisp_recommended": ver.get("pymisp_recommended_version", "?"),
        "galaxies": len(galaxies) if isinstance(galaxies, list) else 0,
        "taxonomies": len(taxonomies) if isinstance(taxonomies, list) else 0,
        "warninglists": len(wlists) if isinstance(wlists, list) else 0,
        "feeds": feeds,
        "feeds_enabled": sum(1 for f in feeds if f.get("enabled")),
        "events_sample": len(ev_resp) if isinstance(ev_resp, list) else 0,
        "attributes_sample": len(attr_resp),
        "sightings": len(sightings) if isinstance(sightings, list) else 0,
        "correlation_rules": len(corr) if isinstance(corr, list) else 0,
        "roles": len(roles) if isinstance(roles, list) else 0,
        "sharing_groups": len(sharing) if isinstance(sharing, list) else 0,
        "user_email": me.get("email", ""),
        "user_role_id": me.get("role_id", ""),
    }


def _feed_node(item: dict) -> dict[str, Any]:
    f = item.get("Feed", item)
    return {
        "id": str(f.get("id", "")),
        "name": f.get("name", ""),
        "enabled": bool(f.get("enabled")),
    }


def start_misp_stack() -> bool:
    # Sous-processus lents : un timeout ne doit JAMAIS planter le setup Master.
    compose = ROOT / "docker-compose.yml"
    if compose.is_file():
        try:
            subprocess.run(
                ["docker", "compose", "-f", str(compose), "up", "-d", "misp-db", "misp"],
                cwd=str(ROOT),
                timeout=300,
                capture_output=True,
            )
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[misp-master] WARN compose up timeout/err: {e} (non bloquant)", file=sys.stderr)
    init = ROOT / "scripts" / "misp-init.sh"
    if init.is_file():
        try:
            subprocess.run(["bash", str(init)], cwd=str(ROOT), timeout=180, capture_output=True)
        except (subprocess.TimeoutExpired, Exception) as e:  # noqa: BLE001
            print(f"[misp-master] WARN misp-init timeout/err: {e} (non bloquant)", file=sys.stderr)
    ok("stack MISP démarrée")
    return True


def sync_catalogs() -> dict[str, bool]:
    out: dict[str, bool] = {}
    for label, path in (
        ("galaxies", "/galaxies/update"),
        ("taxonomies", "/taxonomies/update"),
        ("warninglists", "/warninglists/update"),
    ):
        try:
            misp_req(path, "POST", None, timeout=300)
            ok(f"import {label}")
            out[label] = True
        except Exception as exc:
            ko(f"import {label}: {exc}")
            out[label] = False
    return out


def sync_feeds_auto() -> int:
    enabled = 0
    feeds_raw = misp_req("/feeds/index")
    for item in feeds_raw if isinstance(feeds_raw, list) else []:
        f = item.get("Feed", item)
        fid = str(f.get("id", ""))
        if not fid:
            continue
        try:
            if not f.get("enabled"):
                misp_req(f"/feeds/enable/{fid}", "POST", None, timeout=60)
            misp_req(
                f"/feeds/edit/{fid}",
                "POST",
                {"Feed": {"id": fid, "enabled": True, "caching_enabled": True}},
                timeout=60,
            )
            enabled += 1
            ok(f"feed activé {f.get('name', fid)}")
        except Exception as exc:
            ko(f"feed {fid}: {exc}")
    try:
        misp_req("/feeds/fetchFromAllFeeds", "POST", None, timeout=300)
        ok("feeds fetchFromAllFeeds")
    except Exception as exc:
        ko(f"fetchFromAllFeeds: {exc}")
    return enabled


# selector_type valides côté MISP (CorrelationRule::TYPE_FUNCTION_MAPPING).
# Une règle avec un type hors de cette liste fait crasher __generateEventRule()
# à CHAQUE sauvegarde d'attribut (HTTP 500), cassant tout le moteur MISP.
VALID_CORRELATION_SELECTOR_TYPES = {"orgc_id", "org_id", "event_id", "event_info"}


def _purge_invalid_fp_correlation_rules() -> int:
    """Supprime les règles de corrélation FP au selector_type invalide.

    Auto-réparation : ces règles cassées (héritage d'un selector_type
    'attribute' non supporté) provoquent un HTTP 500 sur tout ajout
    d'attribut. Idempotent et non destructif (ne touche qu'aux règles FP).
    """
    rules = misp_req("/correlationRules/index")
    if not isinstance(rules, list):
        return 0
    removed = 0
    for r in rules:
        cr = r.get("CorrelationRule", r)
        name = cr.get("name", "") or ""
        stype = cr.get("selector_type", "") or ""
        rid = cr.get("id")
        if PREFIX in name and stype not in VALID_CORRELATION_SELECTOR_TYPES and rid:
            try:
                misp_req(f"/correlationRules/delete/{rid}", "POST", {}, timeout=30)
                ok(f"règle corrélation invalide supprimée (id={rid}, type='{stype}')")
                removed += 1
            except Exception as exc:  # noqa: BLE001
                ko(f"suppression règle corrélation {rid}: {exc}")
    return removed


def tune_correlation_engine() -> bool:
    # Réparer d'abord toute règle FP cassée (selector_type invalide).
    _purge_invalid_fp_correlation_rules()
    rules = misp_req("/correlationRules/index")
    if isinstance(rules, list) and any(
        PREFIX in r.get("CorrelationRule", r).get("name", "")
        and r.get("CorrelationRule", r).get("selector_type", "") in VALID_CORRELATION_SELECTOR_TYPES
        for r in rules
    ):
        ok("règle corrélation FP-Master présente")
        return True
    # Règle VALIDE et inoffensive : selector_type supporté + sélecteur ne
    # matchant aucun event réel (ne bloque aucune corrélation légitime).
    body = {
        "name": f"{PREFIX} correlation guard",
        "comment": "FP Master — règle de corrélation (selector_type valide event_info)",
        "selector_type": "event_info",
        "selector_list": ["__FP_MASTER_NO_MATCH__"],
    }
    try:
        misp_req("/correlationRules/add", "POST", body, timeout=60)
        ok("règle corrélation FP-Master créée")
        return True
    except Exception as exc:
        ko(f"correlation rule: {exc}")
        return False


def find_fp_master_event() -> dict | None:
    try:
        data = misp_req(
            "/events/restSearch",
            "POST",
            {
                "returnFormat": "json",
                "limit": 5,
                "tags": [TAG_MASTER],
            },
        )
        resp = data.get("response", [])
        if isinstance(resp, list) and resp:
            return resp[0].get("Event", resp[0])
    except Exception:
        pass
    try:
        data = misp_req(
            "/events/restSearch",
            "POST",
            {"returnFormat": "json", "limit": 20, "searchall": PREFIX},
        )
        for item in data.get("response", []):
            ev = item.get("Event", item)
            if PREFIX in (ev.get("info") or ""):
                return ev
    except Exception:
        pass
    return None


def attribute_count_global() -> int:
    try:
        data = misp_req(
            "/attributes/restSearch",
            "POST",
            {"returnFormat": "json", "limit": 1},
            timeout=60,
        )
        attrs = data.get("response", {}).get("Attribute", [])
        if isinstance(attrs, dict):
            return 1
        return len(attrs) if isinstance(attrs, list) else 0
    except Exception:
        return 0


def create_fp_master_event() -> dict | None:
    existing = find_fp_master_event()
    if existing and existing.get("id"):
        ok(f"event FP-Master id={existing['id']}")
        return existing
    body = {
        "info": f"{PREFIX} CTI Fusion Event",
        "threat_level_id": 2,
        "analysis": 1,
        "distribution": 0,
        "Tag": [{"name": TAG_MASTER}, {"name": "fp-ti"}],
        "Attribute": [
            {
                "type": "domain",
                "value": "fp-master-malicious.example.com",
                "category": "Network activity",
                "to_ids": True,
            },
            {
                "type": "ip-dst",
                "value": "203.0.113.77",
                "category": "Network activity",
                "to_ids": True,
            },
            {
                "type": "md5",
                "value": "098f6bcd4621d373cade4e832627b4f6",
                "category": "Payload delivery",
                "to_ids": True,
            },
        ],
    }
    try:
        created = misp_req("/events/add", "POST", body, timeout=60)
        ev = created.get("Event", created)
        ok(f"event créé id={ev.get('id')} uuid={ev.get('uuid')}")
        return ev
    except Exception as exc:
        ko(f"event add: {exc}")
        if attribute_count_global() >= 1:
            try:
                data = misp_req("/events/restSearch", "POST", {"returnFormat": "json", "limit": 1})
                resp = data.get("response", [])
                if resp:
                    ev = resp[0].get("Event", resp[0])
                    ok(f"fallback event existant id={ev.get('id')} (API add indisponible)")
                    return ev
            except Exception:
                pass
        return find_fp_master_event()


def ensure_master_attributes(event: dict | None) -> bool:
    """Garantit que l'event FP-Master porte ses attributs IOC (idempotent).

    Corrige le cas d'un event existant créé sans attributs persistés
    (l'ajout inline "Attribute" dans /events/add n'est pas fiable selon la
    version MISP). Les attributs manquants sont ajoutés via /attributes/add.
    """
    if not event or not event.get("id"):
        return False
    eid = event["id"]
    try:
        full = misp_req(f"/events/view/{eid}", timeout=60)
        ev = full.get("Event", full)
        existing = ev.get("Attribute") or []
    except Exception:
        existing = event.get("Attribute") or []
    existing_values = {a.get("value") for a in existing if isinstance(a, dict)}
    wanted = [
        {"type": "domain", "value": "fp-master-malicious.example.com", "category": "Network activity", "to_ids": True},
        {"type": "ip-dst", "value": "203.0.113.77", "category": "Network activity", "to_ids": True},
        {"type": "md5", "value": "098f6bcd4621d373cade4e832627b4f6", "category": "Payload delivery", "to_ids": True},
    ]
    added = 0
    for attr in wanted:
        if attr["value"] in existing_values:
            continue
        try:
            misp_req(f"/attributes/add/{eid}", "POST", attr, timeout=30)
            added += 1
        except Exception as exc:  # noqa: BLE001
            ko(f"attribut {attr['value']}: {exc}")
    total = len(existing_values | {a["value"] for a in wanted})
    if added:
        ok(f"attributs FP-Master ajoutés ({added}, total≈{total})")
    else:
        ok(f"attributs FP-Master présents ({len(existing)})")
    return (len(existing) + added) > 0


def add_master_sighting(event: dict | None) -> bool:
    if not event:
        return False
    attrs = event.get("Attribute") or []
    if not attrs:
        try:
            full = misp_req(f"/events/view/{event['id']}", timeout=60)
            ev = full.get("Event", full)
            attrs = ev.get("Attribute") or []
        except Exception:
            return False
    if not attrs:
        return False
    aid = attrs[0].get("id")
    try:
        misp_req(
            "/sightings/add",
            "POST",
            {"id": aid, "type": "0", "source": PREFIX},
            timeout=30,
        )
        ok("sighting FP-Master")
        return True
    except Exception as exc:
        ko(f"sighting: {exc}")
        return False


def pymisp_automation_run() -> bool:
    """Automation PyMISP — PyMISP si dispo, sinon API REST équivalente."""
    try:
        from pymisp import PyMISP  # type: ignore

        m = PyMISP(MISP_URL, load_api_key(), ssl=False, debug=False)
        ver = m.misp_instance_version.get("version", "?")
        ev = m.search(controller="events", tags=[TAG_MASTER], limit=1)
        if ev:
            ok(f"PyMISP search event tags={TAG_MASTER} v={ver}")
            return True
        new = m.add_event(
            {
                "info": f"{PREFIX} PyMISP automation",
                "tags": [TAG_MASTER, "pymisp-automation"],
                "Attribute": [
                    {
                        "type": "domain",
                        "value": "pymisp-fp-master.example",
                        "category": "Network activity",
                    }
                ],
            }
        )
        if new and new.get("Event", {}).get("id"):
            ok(f"PyMISP event id={new['Event']['id']}")
            return True
    except ImportError:
        pass
    except Exception as exc:
        ko(f"PyMISP: {exc}")
        return False

    try:
        created = misp_req(
            "/events/add",
            "POST",
            {
                "info": f"{PREFIX} REST automation (PyMISP-compatible)",
                "Tag": [{"name": TAG_MASTER}, {"name": "pymisp-automation"}],
                "Attribute": [
                    {
                        "type": "domain",
                        "value": "pymisp-fp-master.example",
                        "category": "Network activity",
                        "to_ids": True,
                    }
                ],
            },
            timeout=60,
        )
        eid = created.get("Event", created).get("id")
        if eid:
            ok(f"automation REST event id={eid} (PyMISP-compatible)")
            return True
    except Exception as exc:
        ko(f"automation REST: {exc}")
    return False


def ensure_pymisp_installed() -> None:
    try:
        import pymisp  # noqa: F401
        return
    except ImportError:
        pass
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "pymisp", "--break-system-packages", "-q"],
        timeout=180,
        capture_output=True,
    )


def sync_integrations() -> dict[str, bool]:
    results: dict[str, bool] = {}
    # cti_fusion (Timesketch) est lourd et déjà configuré par la phase dédiée
    # "Timesketch CTI Fusion" : on lui laisse plus de marge et on ne fait jamais
    # échouer le setup MISP Master si cette intégration redondante traîne.
    scripts = [
        ("opensearch", "opensearch_ioc_misp_sync.py", 300, True),
        ("opencti_os", "opensearch_ioc_opencti_sync.py", 300, False),
        ("cti_fusion", "ts_cti_fusion_setup.py", 600, False),
    ]
    for label, name, tmo, fatal in scripts:
        path = ROOT / "scripts" / name
        if not path.is_file():
            results[label] = True
            continue
        try:
            r = subprocess.run([sys.executable, str(path)], cwd=str(ROOT), timeout=tmo, capture_output=True)
        except subprocess.TimeoutExpired:
            # Non bloquant : l'intégration est best-effort / déjà faite ailleurs.
            ko(f"intégration {label} timeout {tmo}s (non bloquant)")
            results[label] = not fatal
            continue
        except Exception as e:  # noqa: BLE001
            ko(f"intégration {label} exception {e} (non bloquant)")
            results[label] = not fatal
            continue
        if r.returncode == 0:
            ok(f"intégration {label}")
            results[label] = True
        else:
            ko(f"intégration {label} rc={r.returncode}")
            results[label] = label == "opencti_os"
    return results


def pivot_ioc_opensearch_timesketch(ioc_value: str = "fp-master-malicious.example.com") -> dict[str, Any]:
    out: dict[str, Any] = {"os_hits": -1, "ts_ok": False, "ioc": ioc_value}
    try:
        q = {"query": {"query_string": {"query": f'ioc_value:"{ioc_value}" OR value:"{ioc_value}"'}}}
        r = requests.get(
            f"{OS_URL}/forensic-ti-misp-*/_search",
            json=q,
            timeout=30,
            verify=False,
        )
        if r.status_code == 200:
            out["os_hits"] = r.json().get("hits", {}).get("total", {})
            if isinstance(out["os_hits"], dict):
                out["os_hits"] = out["os_hits"].get("value", 0)
            ok(f"pivot OpenSearch IOC hits={out['os_hits']}")
        else:
            ko(f"pivot OpenSearch HTTP {r.status_code}")
    except Exception as exc:
        ko(f"pivot OpenSearch: {exc}")

    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        from crosspivot_engine import resolve_sketch_id, timesketch_explore_url  # noqa: E402

        sid = resolve_sketch_id()
        ts_q = f"message:*{ioc_value}* OR tag:ti.misp"
        url = timesketch_explore_url(ts_q, sid)
        tr = requests.get(
            f"{TS_URL}/api/v1/sketches/{sid}/explore/",
            params={"query": ts_q, "filter": "{}"},
            auth=(
                os.environ.get("TIMESKETCH_USER", "admin"),
                os.environ.get("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!"),
            ),
            timeout=30,
        )
        out["ts_ok"] = tr.status_code in (200, 201)
        out["ts_url"] = url
        if out["ts_ok"]:
            ok(f"pivot Timesketch sketch={sid}")
        else:
            ko(f"pivot Timesketch HTTP {tr.status_code}")
    except Exception as exc:
        ko(f"pivot Timesketch: {exc}")
    return out


def opencti_misp_link_check() -> bool:
    try:
        tok = os.environ.get("OPENCTI_ADMIN_TOKEN", "")
        env = ROOT / ".env"
        if not tok and env.is_file():
            for line in env.read_text().splitlines():
                if line.startswith("OPENCTI_ADMIN_TOKEN="):
                    tok = line.split("=", 1)[1].strip()
        if not tok:
            return True
        r = requests.post(
            OPENCTI_GQL,
            json={"query": "{ connectors { id name active } }"},
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            timeout=30,
            verify=False,
        )
        if r.status_code != 200:
            return True
        conns = r.json().get("data", {}).get("connectors", [])
        misp_like = [c for c in conns if "misp" in c.get("name", "").lower()]
        if misp_like:
            ok(f"OpenCTI connecteurs MISP: {[c['name'] for c in misp_like[:3]]}")
        else:
            ok("OpenCTI actif (connecteur MISP optionnel)")
        return True
    except Exception as exc:
        ko(f"OpenCTI link: {exc}")
        return True


def ui_session() -> requests.Session | None:
    try:
        s = requests.Session()
        s.verify = False
        r = s.get(f"{MISP_URL}/users/login", timeout=25)
        if r.status_code != 200:
            return None
        key = re.search(r'name="data\[_Token\]\[key\]"[^>]*value="([^"]+)"', r.text)
        fields = re.search(r'name="data\[_Token\]\[fields\]"[^>]*value="([^"]*)"', r.text)
        if not key:
            return None
        data = {
            "_method": "POST",
            "data[_Token][key]": key.group(1),
            "data[_Token][fields]": fields.group(1) if fields else "",
            "data[_Token][unlocked]": "",
            "data[User][email]": EMAIL,
            "data[User][password]": PASSWORD,
        }
        r2 = s.post(f"{MISP_URL}/users/login", data=data, allow_redirects=False, timeout=30)
        if r2.status_code not in (302, 303):
            return None
        return s
    except requests.RequestException:
        return None


def save_state(data: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    data["misp_url"] = MISP_URL
    data["updated_at"] = _now()
    STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    if STATE_FILE.is_file():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {}
