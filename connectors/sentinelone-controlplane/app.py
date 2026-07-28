"""CYBERCORP — SentinelOne control-plane connector.

Service isole (Python 3 + Flask + requests) expose des endpoints internes
/control/s1/* consommes par le portail CERT. Collecte ciblee (on-demand)
uniquement : threats/activities filtrees par host/ip/agentId.

Le token API est lu via S1_API_TOKEN ; la console via S1_BASE_URL. Si non
configure, les endpoints repondent 200 avec {"configured": false} (aucune
erreur HTTP cote UI).
"""
import os
import logging

import requests
from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [s1-cp] %(message)s")
log = logging.getLogger("s1-cp")

API_TOKEN = os.environ.get("S1_API_TOKEN", "").strip()
BASE_URL = os.environ.get("S1_BASE_URL", "").strip().rstrip("/")
S1_LAB_DEMO = os.environ.get("S1_LAB_DEMO", "").strip().lower() in ("1", "true", "yes")
PORT = int(os.environ.get("CONTROLPLANE_PORT", "8082"))
HTTP_TIMEOUT = int(os.environ.get("S1_HTTP_TIMEOUT", "25"))
MAX_PAGES = int(os.environ.get("S1_MAX_PAGES", "20"))
PAGE_SIZE = int(os.environ.get("S1_PAGE_SIZE", "100"))
API_PREFIX = os.environ.get("S1_API_PREFIX", "/web/api/v2.1")

app = Flask(__name__)


DEMO_ENDPOINTS = [
    {"id": "demo-agent-001", "computerName": "WIN-DC01", "osType": "windows", "osName": "Windows Server 2019",
     "machineType": "server", "networkStatus": "connected", "activeThreats": 0, "groupId": "demo-grp-1",
     "groupName": "Domain Controllers", "siteName": "HQ", "lastActiveDate": "2026-06-07T12:00:00Z"},
    {"id": "demo-agent-002", "computerName": "WS-FIN-042", "osType": "windows", "osName": "Windows 11",
     "machineType": "laptop", "networkStatus": "connected", "activeThreats": 1, "groupId": "demo-grp-2",
     "groupName": "Finance", "siteName": "HQ", "lastActiveDate": "2026-06-07T11:30:00Z"},
    {"id": "demo-agent-003", "computerName": "SRV-LINUX-09", "osType": "linux", "osName": "Ubuntu 22.04",
     "machineType": "server", "networkStatus": "disconnected", "activeThreats": 0, "groupId": "demo-grp-3",
     "groupName": "Infrastructure", "siteName": "DC2", "lastActiveDate": "2026-06-06T18:00:00Z"},
]
DEMO_GROUPS = [
    {"id": "demo-grp-1", "name": "Domain Controllers", "type": "static", "totalAgents": 1},
    {"id": "demo-grp-2", "name": "Finance", "type": "dynamic", "totalAgents": 1},
    {"id": "demo-grp-3", "name": "Infrastructure", "type": "static", "totalAgents": 1},
]
DEMO_POLICIES = [
    {"groupId": "demo-grp-1", "groupName": "Domain Controllers", "type": "static",
     "policy": {"agentUiOn": True, "autoMitigationAction": "mitigation.quarantineThreat"},
     "totalAgents": 1},
]
DEMO_RULES = [
    {"id": "demo-star-001", "name": "Suspicious PowerShell", "status": "Enabled", "severity": "HIGH"},
]
DEMO_API_USERS = [
    {"id": "demo-user-1", "fullName": "SOC API Lab", "apiToken": True, "scope": "admin"},
]


def configured() -> bool:
    return bool(API_TOKEN and BASE_URL) or S1_LAB_DEMO


def demo_mode() -> bool:
    return S1_LAB_DEMO and not (API_TOKEN and BASE_URL)


def _headers() -> dict:
    return {
        "Authorization": f"ApiToken {API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "cybercorp-s1-controlplane/1.0",
    }


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update(_headers())
    return s


def envelope(items=None, error=None, extra=None, source="sentinelone"):
    body = {
        "configured": configured(),
        "source": source,
        "base_url": BASE_URL,
        "count": len(items or []),
        "items": items or [],
    }
    if error:
        body["error"] = str(error)
    if extra:
        body.update(extra)
    return body


def paginate(path, params=None):
    """Pagination cursor SentinelOne (data + pagination.nextCursor)."""
    if demo_mode():
        if path == "/agents":
            return list(DEMO_ENDPOINTS), None
        if path == "/groups":
            return list(DEMO_GROUPS), None
        if path == "/cloud-detection/rules":
            return list(DEMO_RULES), None
        if path == "/users":
            return list(DEMO_API_USERS), None
        return [], None
    if not configured():
        return [], None
    params = dict(params or {})
    params.setdefault("limit", PAGE_SIZE)
    out = []
    cursor = None
    sess = _session()
    try:
        for _ in range(MAX_PAGES):
            q = dict(params)
            if cursor:
                q["cursor"] = cursor
            r = sess.get(f"{BASE_URL}{API_PREFIX}{path}", params=q, timeout=HTTP_TIMEOUT)
            if r.status_code >= 400:
                return out, f"HTTP {r.status_code}: {r.text[:200]}"
            data = r.json()
            page = data.get("data") if isinstance(data, dict) else data
            if isinstance(page, dict):
                page = [page]
            out.extend(page or [])
            cursor = ((data.get("pagination") or {}).get("nextCursor")
                      if isinstance(data, dict) else None)
            if not cursor:
                break
        return out, None
    except requests.RequestException as exc:
        return out, str(exc)


def s1_request(method, path, json_body=None, params=None):
    if not configured():
        return None, "SentinelOne non configure (S1_API_TOKEN / S1_BASE_URL absents)"
    try:
        r = _session().request(method, f"{BASE_URL}{API_PREFIX}{path}", json=json_body,
                               params=params, timeout=HTTP_TIMEOUT)
        try:
            payload = r.json()
        except ValueError:
            payload = {"raw": r.text[:400]}
        if r.status_code >= 400:
            return None, f"HTTP {r.status_code}: {r.text[:200]}"
        return payload, None
    except requests.RequestException as exc:
        return None, str(exc)


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
@app.get("/control/s1/health")
def health():
    return jsonify({"status": "ok", "service": "sentinelone-controlplane",
                    "configured": configured(), "base_url": BASE_URL or ("lab-demo" if S1_LAB_DEMO else ""),
                    "lab_demo": demo_mode()})


# ── Inventaires (GET / LIST) ────────────────────────────────────────────────────
@app.get("/control/s1/endpoints")
def endpoints():
    items, err = paginate("/agents")
    return jsonify(envelope(items, err))


@app.get("/control/s1/groups")
def groups():
    items, err = paginate("/groups")
    return jsonify(envelope(items, err))


@app.get("/control/s1/policies")
def policies():
    # Les policies S1 sont par groupe : on agrege group + policy resume.
    grps, err = paginate("/groups")
    items = []
    for g in grps or []:
        items.append({
            "groupId": g.get("id"),
            "groupName": g.get("name"),
            "type": g.get("type"),
            "inherits": g.get("inherits"),
            "policy": g.get("policy") or {},
            "totalAgents": g.get("totalAgents"),
        })
    return jsonify(envelope(items, err, source="sentinelone-policies"))


@app.get("/control/s1/rules")
def rules():
    items, err = paginate("/cloud-detection/rules")
    return jsonify(envelope(items, err, source="sentinelone-star-rules"))


@app.get("/control/s1/apikeys")
def apikeys():
    # S1 n'expose pas une liste de tokens en clair ; on remonte les users API.
    items, err = paginate("/users", params={"query": ""})
    api_users = [u for u in (items or []) if u.get("apiToken") or u.get("scope")]
    return jsonify(envelope(api_users or items, err, source="sentinelone-api-users"))


# ── Collecte ciblee (on-demand) ────────────────────────────────────────────────
@app.post("/control/s1/fetch")
def fetch():
    body = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or "").strip()
    ip = (body.get("ip") or "").strip()
    agent_id = (body.get("agentId") or body.get("agent_id") or "").strip()
    group_id = (body.get("groupId") or body.get("group") or "").strip()
    time_range = (body.get("timeRange") or body.get("time_range") or "24h").strip()

    if not (hostname or ip or agent_id or group_id):
        return jsonify({"error": "hostname, ip, agentId ou groupId requis", "items": []}), 400

    query = {"hostname": hostname, "ip": ip, "agentId": agent_id,
             "groupId": group_id, "timeRange": time_range}
    if not configured():
        return jsonify(envelope([], extra={
            "query": query, "threats": [], "activities": [],
            "note": "SentinelOne non configure — collecte ciblee indisponible",
        }))
    if demo_mode():
        return jsonify(envelope([], source="sentinelone-fetch", extra={
            "query": query, "agentIds": [a["id"] for a in DEMO_ENDPOINTS[:1]],
            "threats": [], "activities": [],
            "note": "Mode labo demo — connectez S1_API_TOKEN pour donnees reelles",
        }))

    # Resolution agentId via hostname/ip/groupId si besoin
    agent_ids = [agent_id] if agent_id else []
    if not agent_ids and (hostname or ip or group_id):
        a_params = {"limit": PAGE_SIZE}
        if hostname:
            a_params["computerName__contains"] = hostname
        if group_id:
            a_params["groupIds"] = group_id
        agents, _e = paginate("/agents", params=a_params)
        for a in agents or []:
            if ip and ip not in (a.get("externalIp"), a.get("lastIpToMgmt")):
                if ip not in [n.get("inet", [None])[0] for n in (a.get("networkInterfaces") or [])]:
                    continue
            if a.get("id"):
                agent_ids.append(a["id"])

    threats_params = {"limit": PAGE_SIZE}
    activities_params = {"limit": PAGE_SIZE}
    if agent_ids:
        threats_params["agentIds"] = ",".join(agent_ids)
        activities_params["agentIds"] = ",".join(agent_ids)
    elif hostname:
        threats_params["computerName__contains"] = hostname

    threats, e1 = paginate("/threats", params=threats_params)
    activities, e2 = paginate("/activities", params=activities_params)
    combined = ([{"_kind": "threat", **t} for t in (threats or [])]
                + [{"_kind": "activity", **a} for a in (activities or [])])
    return jsonify(envelope(combined, error=(e1 or e2), source="sentinelone-fetch", extra={
        "query": query, "agentIds": agent_ids,
        "threats": threats or [], "activities": activities or [],
        "forward_timesketch": bool(body.get("toTimesketch")),
    }))


# ── Edition / actions (PATCH / POST) ────────────────────────────────────────────
@app.post("/control/s1/endpoints/<agent_id>/move")
def move_endpoint(agent_id):
    body = request.get_json(silent=True) or {}
    group_id = body.get("groupId") or body.get("targetGroupId")
    if not group_id:
        return jsonify({"ok": False, "error": "groupId requis"}), 400
    payload, err = s1_request("PUT", f"/groups/{group_id}/move-agents",
                              json_body={"filter": {"ids": [agent_id]}})
    return jsonify({"ok": err is None, "error": err, "result": payload,
                    "agentId": agent_id, "groupId": group_id})


@app.post("/control/s1/endpoints/<agent_id>/tag")
def tag_endpoint(agent_id):
    body = request.get_json(silent=True) or {}
    tag = body.get("tag")
    if not tag:
        return jsonify({"ok": False, "error": "tag requis"}), 400
    payload, err = s1_request("POST", "/agents/actions/manage-tags",
                              json_body={"filter": {"ids": [agent_id]},
                                         "data": {"tags": [{"key": "cybercorp", "value": tag}]}})
    return jsonify({"ok": err is None, "error": err, "result": payload,
                    "agentId": agent_id, "tag": tag})


@app.patch("/control/s1/rules/<rule_id>")
def patch_rule(rule_id):
    body = request.get_json(silent=True) or {}
    payload, err = s1_request("PUT", f"/cloud-detection/rules/{rule_id}",
                              json_body={"data": body})
    return jsonify({"ok": err is None, "error": err, "rule": payload, "id": rule_id})


@app.patch("/control/s1/policies/<group_id>")
def patch_policy(group_id):
    body = request.get_json(silent=True) or {}
    payload, err = s1_request("PUT", f"/groups/{group_id}/policy",
                              json_body={"data": body})
    return jsonify({"ok": err is None, "error": err, "policy": payload, "groupId": group_id})


@app.patch("/control/s1/groups/<group_id>")
def patch_group(group_id):
    body = request.get_json(silent=True) or {}
    payload, err = s1_request("PUT", f"/groups/{group_id}", json_body={"data": body})
    return jsonify({"ok": err is None, "error": err, "group": payload, "groupId": group_id})


if __name__ == "__main__":
    from waitress import serve
    log.info("SentinelOne control-plane on :%s (configured=%s, base=%s)", PORT, configured(), BASE_URL)
    serve(app, host="0.0.0.0", port=PORT, threads=8)
