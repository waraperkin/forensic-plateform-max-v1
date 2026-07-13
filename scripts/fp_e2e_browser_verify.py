#!/usr/bin/env python3
"""Vérification E2E stricte dans le navigateur."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_browser_qa_assertions import JS_OSD_DASHBOARD, JS_PAGE_METRICS, JS_TS_EXPLORE, audit_osd_dashboard, audit_timesketch_explore
from fp_browser_qa_lib import LOG_DIR, get_expectation_rules, load_env, service_urls, strict_check_page_text  # noqa: E402

CASE_ID = os.environ.get("FP_E2E_CASE_ID", "")


def human_scroll(page, passes: int = 4) -> None:
    for i in range(passes):
        try:
            page.evaluate(
                "([i,p]) => window.scrollTo(0, (document.body.scrollHeight/Math.max(p,1))*(i+1))",
                [i, passes],
            )
        except Exception:
            page.wait_for_timeout(400)
        time.sleep(0.3)


def _run_audit(audit_fn, metrics: dict, rules: dict, ekey: str, name: str):
    if audit_fn is None:
        return True, "OK", {}
    import inspect

    sig = inspect.signature(audit_fn)
    n = len(sig.parameters)
    if n >= 3:
        return audit_fn(metrics, rules, ekey or name)
    return audit_fn(metrics, rules)


def visit_strict(page, name: str, url: str, ekey: str, js: str | None, audit_fn) -> dict:
    rules = get_expectation_rules(ekey) if ekey else {}
    shot = ""
    try:
        resp = page.goto(url, wait_until="domcontentloaded", timeout=90000)
        if resp and resp.status >= 400:
            return {"name": name, "ok": False, "detail": f"HTTP {resp.status}", "url": url, "screenshot": ""}
        if "dashboards" in url or "timesketch" in url or ":5000" in url:
            try:
                page.wait_for_load_state("networkidle", timeout=60000)
            except Exception:
                page.wait_for_timeout(10000)
        else:
            page.wait_for_timeout(2500)
        human_scroll(page, 5 if "dashboards" in url else 4)
        if "dashboards" in url:
            page.goto(f"{service_urls()['osd']}/app/home", wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1500)
            page.goto(url, wait_until="domcontentloaded", timeout=90000)
            try:
                page.wait_for_load_state("networkidle", timeout=60000)
            except Exception:
                page.wait_for_timeout(10000)
        page.reload(wait_until="domcontentloaded", timeout=50000)
        if "dashboards" in url:
            try:
                page.wait_for_load_state("networkidle", timeout=60000)
            except Exception:
                page.wait_for_timeout(8000)
        else:
            page.wait_for_timeout(1500)
        human_scroll(page, 3)
        html = page.content()
        ok = True
        detail = "OK"
        metrics = {}
        if js and audit_fn:
            metrics = page.evaluate(js)
            ok, detail, _ = _run_audit(audit_fn, metrics, rules, ekey, name)
        elif js:
            metrics = page.evaluate(js)
            if metrics.get("hasErrorPhrase") or metrics.get("rootOnly"):
                ok, detail = False, "page invalide (métriques)"
        ok2, msg2 = strict_check_page_text(html, rules or {"min_body_text": 400}, name)
        if not ok2:
            ok, detail = False, msg2
        safe = name.replace(":", "_").replace(" ", "_")[:80]
        shot = str(LOG_DIR / f"e2e_{safe}.png")
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=shot, timeout=15000)
        return {"name": name, "ok": ok, "detail": detail, "url": url, "screenshot": shot, "metrics": metrics}
    except Exception as e:
        return {"name": name, "ok": False, "detail": str(e), "url": url, "screenshot": shot}


def main() -> int:
    if not CASE_ID:
        print("FP_E2E_CASE_ID requis", file=sys.stderr)
        return 1
    load_env()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return 2

    u = service_urls()
    checks = [
        ("e2e_ui:osd_platform_health", f"{u['osd']}/app/dashboards#/view/fp-platform-health", "osd.fp_platform_health", JS_OSD_DASHBOARD, audit_osd_dashboard),
        ("e2e_ui:osd_discover", f"{u['osd']}/app/discover#/", "osd.discover", JS_PAGE_METRICS, None),
        ("e2e_ui:portal_cert", f"{u['cert']}/", "portal_cert.home", None, None),
        ("e2e_ui:ts_explore", f"{u['ts']}/login/", "timesketch.login", JS_TS_EXPLORE, audit_timesketch_explore),
    ]
    steps = []
    headless = os.environ.get("FP_BROWSER_HEADLESS", "1") == "1"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--no-sandbox"])
        context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
        for name, url, ekey, js, audit_fn in checks:
            page = context.new_page()
            if name == "e2e_ui:ts_explore":
                try:
                    page.goto(f"{u['ts']}/login/", timeout=60000)
                    from fp_browser_qa_lib import env

                    page.fill('input[name="username"]', env("TIMESKETCH_USER", "admin"))
                    page.fill('input[name="password"]', env("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!"))
                    page.locator('button[type="submit"]').click(timeout=10000)
                    page.wait_for_load_state("networkidle", timeout=30000)
                    page.goto(u["ts"] + "/", timeout=30000)
                    links = page.locator("a[href*='/sketch/']")
                    sid = "1"
                    if links.count():
                        import re

                        m = re.search(r"/sketch/(\d+)", links.first.get_attribute("href") or "")
                        if m:
                            sid = m.group(1)
                    url = f"{u['ts']}/sketch/{sid}/explore/"
                    ekey = "timesketch.explore"
                    page.goto(url, timeout=60000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=45000)
                    except Exception:
                        page.wait_for_timeout(8000)
                    human_scroll(page, 4)
                except Exception as e:
                    steps.append({"name": name, "ok": False, "detail": f"login TS: {e}", "url": url})
                    page.close()
                    continue
            r = visit_strict(page, name, url, ekey, js, audit_fn)
            steps.append(r)
            print(f"{'OK' if r['ok'] else 'KO'} {name} {r['detail']}")
            page.close()
        context.close()
        browser.close()

    Path("/tmp/fp-e2e-browser-steps.json").write_text(json.dumps(steps, indent=2), encoding="utf-8")
    return 0 if all(s["ok"] for s in steps) else 1


if __name__ == "__main__":
    sys.exit(main())
