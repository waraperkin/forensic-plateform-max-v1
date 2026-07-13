#!/usr/bin/env python3
import os
import re
import sys

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
data = {
    "_method": "POST",
    "data[_Token][key]": key.group(1) if key else "",
    "data[_Token][fields]": fields.group(1) if fields else "",
    "data[_Token][unlocked]": "",
    "data[User][email]": email,
    "data[User][password]": password,
}
for url in (f"{MISP_URL}/users/login", "https://localhost:8443/users/login"):
    r2 = s.post(
        url,
        data=data,
        headers={"Referer": f"{MISP_URL}/users/login"},
        allow_redirects=False,
        timeout=30,
    )
    low = r2.text.lower()
    print(
        url,
        r2.status_code,
        r2.headers.get("Location", ""),
        "invalid" in low,
        "black" in low,
        "csrf" in low,
    )
