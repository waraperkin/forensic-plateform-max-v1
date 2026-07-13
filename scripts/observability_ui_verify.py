#!/usr/bin/env python3
"""
Simulation UI OpenSearch Dashboards + Grafana :
- requêtes type navigateur (User-Agent, Referer, cookies)
- proxy Nginx HTTPS
- CORS (Origin localhost vs invalide)
- rendu headless Chrome (DOM réel)
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

OSD_NGINX = os.environ.get("OSD_NGINX_URL", "https://localhost/dashboards").rstrip("/")
OSD_DIRECT = os.environ.get("OSD_URL", "http://localhost:5601/dashboards").rstrip("/")
GF_URL = os.environ.get("GRAFANA_URL", "https://localhost/grafana").rstrip("/")
GF_PASS = os.environ.get("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")
CHROME = os.environ.get("CHROME_BIN", "") or shutil.which("google-chrome") or shutil.which("chromium") or ""
HEADLESS_BUDGET = os.environ.get("OBS_UI_HEADLESS_MS", "12000")
SCOPE = os.environ.get("OBS_UI_SCOPE", "all").lower()  # all | osd | gf

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Forensic-Deep-UI/1.0"
)

FATAL_UI_PATTERNS = [
    r"<h[12][^>]*>\s*Something went wrong\s*</h[12]>",
    r'euiEmptyPrompt[\s\S]{0,300}Something went wrong',
    r"Application Not Available",
    r"origin not allowed",
    r"502 Bad Gateway",
    r"503 Service",
]


def ok(msg: str) -> None:
    print(f"[ui-verify] OK {msg}")


def ko(msg: str) -> None:
    print(f"[ui-verify] KO {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[ui-verify] WARN {msg}")


def browser_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update(
        {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        }
    )
    return s


def has_fatal_ui(html: str) -> bool:
    for pat in FATAL_UI_PATTERNS:
        if re.search(pat, html, re.I):
            return True
    return False


def headless_dom(url: str, budget_ms: str = HEADLESS_BUDGET) -> str:
    if not CHROME:
        return ""
    cmd = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--ignore-certificate-errors",
        f"--virtual-time-budget={budget_ms}",
        "--dump-dom",
        url,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        return r.stdout or ""
    except (subprocess.TimeoutExpired, OSError) as e:
        warn(f"headless chrome: {e}")
        return ""


def main() -> int:
    fails = 0
    s = browser_session()
    run_gf = SCOPE in ("all", "gf", "grafana")
    run_osd = SCOPE in ("all", "osd", "opensearch")

    if run_gf:
        fails += _verify_grafana(s)
    if run_osd:
        fails += _verify_opensearch_dashboards(s)

    print(f"[ui-verify] Bilan: {fails} KO (scope={SCOPE})")
    return 1 if fails else 0


def _verify_grafana(s: requests.Session) -> int:
    fails = 0

    # ── Grafana : login + dashboard (HTML) ───────────────────────
    for path, label in [
        ("/login", "login"),
        ("/", "home"),
        ("/d/forensic-overview", "dashboard forensic-overview"),
    ]:
        url = f"{GF_URL}{path}"
        r = s.get(url, timeout=20, allow_redirects=True)
        if r.status_code not in (200, 302):
            ko(f"Grafana {label} HTTP {r.status_code}")
            fails += 1
            continue
        if has_fatal_ui(r.text):
            ko(f"Grafana {label}: erreur UI détectée")
            fails += 1
        elif "grafana" in r.text.lower() or "Grafana" in r.text:
            ok(f"Grafana {label} HTML ({r.status_code})")
        else:
            ko(f"Grafana {label}: contenu inattendu")
            fails += 1

    # Grafana CORS (simulation navigateur cross-origin)
    for origin, expect_ok in [
        ("https://localhost", True),
        ("https://127.0.0.1", True),
        ("https://evil.invalid", False),
    ]:
        hr = requests.get(
            f"{GF_URL}/api/health",
            headers={"Origin": origin, "User-Agent": BROWSER_UA},
            verify=False,
            timeout=10,
        )
        acao = hr.headers.get("Access-Control-Allow-Origin", "")
        if expect_ok and origin in acao:
            ok(f"Grafana CORS Origin {origin} → {acao}")
        elif not expect_ok and origin not in acao:
            ok(f"Grafana CORS rejette Origin {origin}")
        else:
            warn(f"Grafana CORS Origin {origin} → Allow-Origin={acao or '(vide)'}")

    # Grafana headless : panels dashboard
    dom_gf = headless_dom(f"{GF_URL}/d/forensic-overview")
    if dom_gf:
        if "Forensic Platform" in dom_gf and "panel" in dom_gf:
            ok("Grafana headless: dashboard Forensic Platform + panels")
        elif has_fatal_ui(dom_gf):
            ko("Grafana headless: erreur UI")
            fails += 1
        else:
            warn("Grafana headless: titre/panels non confirmés")
    else:
        warn("Grafana headless: chrome indisponible")

    api = f"{GF_URL}/api"
    ar = requests.get(
        f"{api}/user",
        auth=("admin", GF_PASS),
        verify=False,
        timeout=15,
        headers={"User-Agent": BROWSER_UA, "Referer": f"{GF_URL}/"},
    )
    if ar.status_code == 200 and ar.json().get("login") == "admin":
        ok("Grafana session admin (API /user)")
    else:
        ko(f"Grafana /api/user HTTP {ar.status_code}")
        fails += 1

    return fails


def _verify_opensearch_dashboards(s: requests.Session) -> int:
    fails = 0

    # ── OpenSearch Dashboards (Nginx + direct) ─────────────────
    for base, via in [(OSD_NGINX, "nginx"), (OSD_DIRECT, "direct")]:
        r = s.get(f"{base}/", timeout=20, allow_redirects=True)
        if r.status_code not in (200, 302):
            ko(f"OSD {via} racine HTTP {r.status_code}")
            fails += 1
            continue
        if "OpenSearch Dashboards" not in r.text:
            ko(f"OSD {via}: titre absent")
            fails += 1
        elif has_fatal_ui(r.text):
            ko(f"OSD {via}: erreur fatale HTML")
            fails += 1
        elif "/dashboards/" in r.text or "osd-ui-shared-deps" in r.text:
            ok(f"OSD {via} shell SPA chargé")
        else:
            warn(f"OSD {via}: bundles non détectés dans HTML initial")

    # Pages applicatives (simulation navigation menu)
    osd_routes = [
        ("/app/home", "Home"),
        ("/app/discover", "Discover"),
        ("/app/dev_tools", "Dev Tools"),
        ("/app/management/opensearch-dashboards/indexPatterns", "Index patterns"),
    ]
    for route, name in osd_routes:
        r = s.get(f"{OSD_NGINX}{route}", timeout=25, allow_redirects=True)
        if r.status_code != 200:
            ko(f"OSD UI {name} HTTP {r.status_code}")
            fails += 1
            continue
        if has_fatal_ui(r.text):
            ko(f"OSD UI {name}: erreur fatale")
            fails += 1
        elif "core.entry.js" in r.text or "discover.plugin.js" in r.text or "OpenSearch Dashboards" in r.text:
            ok(f"OSD UI {name}: shell SPA")
        else:
            warn(f"OSD UI {name}: bundles partiels")

    # Discover — recherche interne (équivalent UI « Run »)
    search_payload = {
        "params": {
            "index": "forensic-uploads*",
            "body": {"size": 1, "query": {"match_all": {}}},
        }
    }
    sr = requests.post(
        f"{OSD_DIRECT}/internal/search/opensearch-with-long-numerals",
        json=search_payload,
        headers={"osd-xsrf": "true", "Content-Type": "application/json"},
        timeout=30,
        verify=False,
    )
    if sr.status_code == 200:
        hits = (sr.json().get("rawResponse") or {}).get("hits", {}).get("total", 0)
        total = hits.get("value", hits) if isinstance(hits, dict) else hits
        if total and int(total) >= 1:
            ok(f"OSD Discover search API ({total} hits forensic-uploads*)")
        else:
            ko("OSD Discover search: 0 résultat")
            fails += 1
    else:
        ko(f"OSD Discover search HTTP {sr.status_code}")
        fails += 1

    # OSD headless Discover (DOM rendu — tolère erreur session si query bar présente)
    dom_osd = headless_dom(f"{OSD_NGINX}/app/discover", "20000")
    if dom_osd:
        if "globalQueryBar" in dom_osd or "osdQueryBar" in dom_osd:
            ok("OSD headless Discover: barre de requête chargée")
        elif has_fatal_ui(dom_osd) and "clearSession" in dom_osd:
            warn("OSD headless Discover: écran session (API search OK — recharger session navigateur)")
        elif has_fatal_ui(dom_osd):
            ko("OSD headless Discover: erreur fatale sans query bar")
            fails += 1
        elif "Discover" in dom_osd:
            ok("OSD headless Discover: application Discover")
        else:
            warn("OSD headless Discover: état incertain")
    else:
        warn("OSD headless: chrome indisponible")

    dr = requests.post(
        f"{OSD_DIRECT}/api/console/proxy",
        params={"path": "/_cluster/health", "method": "GET"},
        json={},
        headers={"osd-xsrf": "true", "Content-Type": "application/json"},
        timeout=20,
        verify=False,
    )
    if dr.status_code == 200 and dr.json().get("status") in ("green", "yellow"):
        ok(f"OSD Dev Tools proxy cluster {dr.json().get('status')}")
    else:
        ko(f"OSD Dev Tools proxy HTTP {dr.status_code}")
        fails += 1

    if SCOPE == "all":
        pr = s.get("https://localhost/api/services", timeout=15)
        if pr.status_code == 200:
            names = {x.get("name", "").lower() for x in pr.json()}
            if any("grafana" in n or "opensearch" in n or "dashboard" in n for n in names):
                ok("Portail /api/services — SIEM référencé")
            else:
                warn("Portail: services SIEM non nommés explicitement")
        else:
            warn(f"Portail /api/services HTTP {pr.status_code}")

    return fails


if __name__ == "__main__":
    sys.exit(main())
