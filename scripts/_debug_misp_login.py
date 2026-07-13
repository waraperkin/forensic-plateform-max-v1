#!/usr/bin/env python3
import re
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from fp_runtime_env import MISP_URL
import requests
import urllib3
urllib3.disable_warnings()
email = os.environ.get("MISP_ADMIN_EMAIL", "admin@forensic.local")
password = os.environ.get("MISP_ADMIN_PASSWORD", "")
s = requests.Session()
s.verify = False
r = s.get(f"{MISP_URL}/users/login", timeout=25)
print("GET", r.status_code, "action=", re.search(r'form action="([^"]+)"', r.text).group(1) if re.search(r'form action="([^"]+)"', r.text) else "?")
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
r2 = s.post(f"{MISP_URL}/users/login", data=data, allow_redirects=False, timeout=30)
print("POST", r2.status_code, "location=", r2.headers.get("Location", ""))
print("body_snip=", r2.text[:300].replace("\n", " "))
r3 = s.get(f"{MISP_URL}/events/index", allow_redirects=True, timeout=30)
print("EVENTS", r3.status_code, r3.url)
