#!/usr/bin/env python3
"""Met à jour le profil analyste TheHive pour les tests E2E."""
import json
import os
import ssl
import sys
import urllib.request
import base64

sys.path.insert(0, os.path.dirname(__file__))
from fp_runtime_env import THEHIVE_URL, load_runtime_env

load_runtime_env()

TH_USER = os.environ.get("THEHIVE_ANALYST_LOGIN", "cert-analyst@forensic.local")
TH_PASS = os.environ.get("THEHIVE_ANALYST_PASSWORD", "F0r3ns1c_TH_Analyst!")
TH_ADMIN = os.environ.get("THEHIVE_ADMIN_LOGIN", "admin@thehive.local")
TH_ADMIN_PASS = os.environ.get("THEHIVE_ADMIN_PASSWORD", "secret")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def req(method, path, body=None, user=TH_ADMIN, password=TH_ADMIN_PASS):
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(
        f"{THEHIVE_URL}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(r, timeout=45, context=ctx) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


users = req("POST", "/api/v1/query", {"query": [{"_name": "listUser"}]})
target = next((u for u in users if u.get("login") == TH_USER), None)
orgs = req("POST", "/api/v1/query", {"query": [{"_name": "listOrganisation"}]})
org_id = orgs[0]["_id"] if orgs else "~12328"
if target:
    uid = target["_id"]
    req("PATCH", f"/api/v1/user/{uid}", {
        "profile": "org-admin",
        "organisations": [{"organisation": org_id, "profile": "org-admin"}],
    })
    print(f"updated {TH_USER} -> org-admin ({uid})")
else:
    req("POST", "/api/v1/user", {
        "login": TH_USER,
        "name": "CERT Analyst E2E",
        "profile": "org-admin",
        "password": TH_PASS,
        "organisations": [{"organisation": org_id, "profile": "org-admin"}],
    })
    print(f"created {TH_USER}")
