#!/usr/bin/env python3
"""Login MISP via nginx avec curl (même encodage que le test interne)."""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from fp_runtime_env import MISP_URL, load_runtime_env

load_runtime_env()

email = os.environ.get("MISP_ADMIN_EMAIL", "admin@forensic.local")
password = os.environ.get("MISP_ADMIN_PASSWORD", "")
jar = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
jar.close()
html = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
html.close()
base = f"{MISP_URL}/users/login"
subprocess.run(
    ["curl", "-sk", "-c", jar.name, "-b", jar.name, base, "-o", html.name],
    check=True,
)
text = Path(html.name).read_text(encoding="utf-8", errors="ignore")
key = re.search(r'name="data\[_Token\]\[key\]"[^>]*value="([^"]+)"', text)
fields = re.search(r'name="data\[_Token\]\[fields\]"[^>]*value="([^"]*)"', text)
if not key:
    print("no token"); sys.exit(1)
cmd = [
    "curl", "-sk", "-c", jar.name, "-b", jar.name,
    "-H", f"Referer: {base}",
    "-X", "POST", base,
    "--data-urlencode", "_method=POST",
    "--data-urlencode", f"data[_Token][key]={key.group(1)}",
    "--data-urlencode", f"data[_Token][fields]={fields.group(1) if fields else ''}",
    "--data-urlencode", "data[_Token][unlocked]=",
    "--data-urlencode", f"data[User][email]={email}",
    "--data-urlencode", f"data[User][password]={password}",
    "-w", "%{http_code}",
    "-o", html.name + ".post",
]
code = subprocess.check_output(cmd, text=True).strip()
print("POST", code)
ev = subprocess.check_output(
    ["curl", "-sk", "-b", jar.name, f"{MISP_URL}/events/index", "-w", "%{http_code}", "-o", "/dev/null"],
    text=True,
).strip()
print("EVENTS", ev)
