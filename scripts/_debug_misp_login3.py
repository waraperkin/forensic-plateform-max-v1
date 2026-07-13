#!/usr/bin/env python3
"""Test login MISP via nginx (hôte)."""
import os
import re
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(__file__))
from fp_runtime_env import MISP_URL, load_runtime_env

load_runtime_env()
import requests
import urllib3

urllib3.disable_warnings()

email = os.environ.get("MISP_ADMIN_EMAIL", "admin@forensic.local")
password = os.environ.get("MISP_ADMIN_PASSWORD", "")
s = requests.Session()
s.verify = False
r = s.get(f"{MISP_URL}/users/login", timeout=25)
key = re.search(r'name="data\[_Token\]\[key\]"[^>]*value="([^"]+)"', r.text)
fields = re.search(r'name="data\[_Token\]\[fields\]"[^>]*value="([^"]*)"', r.text)
# Corps application/x-www-form-urlencoded (comme curl --data-urlencode)
body = "&".join(
    [
        "_method=POST",
        f"data%5B_Token%5D%5Bkey%5D={quote(key.group(1) if key else '', safe='')}",
        f"data%5B_Token%5D%5Bfields%5D={quote(fields.group(1) if fields else '', safe='')}",
        "data%5B_Token%5D%5Bunlocked%5D=",
        f"data%5BUser%5D%5Bemail%5D={quote(email, safe='')}",
        f"data%5BUser%5D%5Bpassword%5D={quote(password, safe='')}",
    ]
)
r2 = s.post(
    f"{MISP_URL}/users/login",
    data=body,
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": f"{MISP_URL}/users/login",
    },
    allow_redirects=False,
    timeout=30,
)
print("POST", r2.status_code, r2.headers.get("Location", ""))
r3 = s.get(f"{MISP_URL}/events/index", allow_redirects=True, timeout=30)
print("EVENTS", r3.status_code, r3.url, "/users/login" not in r3.url)
