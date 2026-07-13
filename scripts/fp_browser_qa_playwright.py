#!/usr/bin/env python3
"""
QA navigateur strict (Playwright) — pessimiste, screenshots obligatoires sur vues critiques.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fp_browser_qa_assertions import (  # noqa: E402
    JS_GRAFANA_DASH,
    JS_OSD_DASHBOARD,
    JS_PAGE_METRICS,
    JS_TS_EXPLORE,
    JS_TS_INTELLIGENCE,
    JS_TS_OVERVIEW,
    JS_TS_STORIES,
    audit_grafana_platform,
    audit_osd_dashboard,
    audit_page_content_text,
    audit_timesketch_explore,
    audit_timesketch_intelligence,
    audit_timesketch_overview,
    audit_timesketch_stories,
)
from fp_browser_qa_lib import (  # noqa: E402
    LOG_DIR,
    BrowserStep,
    all_browser_journeys,
    env,
    get_expectation_rules,
    load_env,
    record_step,
    service_urls,
    strict_check_page_text,
    write_browser_results,
)

try:
    from playwright.sync_api import TimeoutError as PwTimeout
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[fp-browser] KO — pip install playwright && playwright install chromium", file=sys.stderr)
    sys.exit(2)

import requests

STRICT = os.environ.get("FP_QA_STRICT", "1") == "1"


def try_login(page, step: BrowserStep) -> None:
    if not step.login:
        return
    user, pwd = step.login.get("user", ""), step.login.get("pass", "")
    for sel_u, sel_p in [
        ('input[name="user"]', 'input[name="password"]'),
        ('input[name="username"]', 'input[name="password"]'),
    ]:
        try:
            if page.locator(sel_u).count() > 0:
                page.fill(sel_u, user, timeout=5000)
                page.fill(sel_p, pwd, timeout=5000)
                page.locator('button[type="submit"]').first.click(timeout=10000)
                page.wait_for_load_state("networkidle", timeout=25000)
                return
        except Exception:
            continue


def human_scroll(page, passes: int) -> None:
    for i in range(passes):
        try:
            page.evaluate(
                "([i,p]) => window.scrollTo(0, (document.body.scrollHeight/Math.max(p,1))*(i+1))",
                [i, passes],
            )
        except Exception:
            page.wait_for_timeout(400)
        time.sleep(0.3)


def mandatory_screenshot(page, step: BrowserStep, screenshot_dir: Path) -> str:
    safe = re.sub(r"[^\w\-]+", "_", step.name)[:90]
    shot = screenshot_dir / f"{safe}.png"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    try:
        page.screenshot(path=str(shot), full_page=False, timeout=20000)
    except Exception:
        page.screenshot(path=str(shot), timeout=12000)
    return str(shot)


def run_assertions(page, step: BrowserStep, html: str) -> tuple[bool, str, dict]:
    rules = get_expectation_rules(step.expectation_key) if step.expectation_key else {}
    metrics: dict = {}
    try:
        if step.assert_fn == "osd_dashboard":
            metrics = page.evaluate(JS_OSD_DASHBOARD)
            return audit_osd_dashboard(metrics, rules, step.expectation_key or step.name)
        if step.assert_fn == "grafana":
            metrics = page.evaluate(JS_GRAFANA_DASH)
            return audit_grafana_platform(metrics, rules)
        if step.assert_fn == "portal_api":
            return _audit_portal_api(step)
        base_metrics = page.evaluate(JS_PAGE_METRICS)
        metrics = base_metrics
        if base_metrics.get("hasErrorPhrase") or base_metrics.get("upgradeBrowser") or base_metrics.get("rootOnly"):
            return False, f"page invalide: {base_metrics}", metrics
        ok_text, msg_text = strict_check_page_text(html, rules, step.name)
        if not ok_text:
            return False, msg_text, metrics
        if not step.expectation_key:
            return True, "OK (métriques de base)", metrics
        return True, msg_text, metrics
    except Exception as e:
        return False, f"assertion error: {e}", metrics


def _audit_portal_api(step: BrowserStep) -> tuple[bool, str, dict]:
    rules = get_expectation_rules(step.expectation_key)
    u = service_urls()
    path = rules.get("api_path", "")
    try:
        r = requests.get(f"{u['cert']}{path}", timeout=25, verify=False)
        if r.status_code >= 400:
            return False, f"API HTTP {r.status_code}", {}
        data = r.json()
        if not isinstance(data, list):
            return False, "réponse API non-liste", {}
        if step.expectation_key == "portal_cert.dashboard_cert":
            need = int(rules.get("min_incidents", 1))
            if len(data) < need:
                return False, f"incidents={len(data)} < {need}", {"count": len(data)}
        if step.expectation_key == "portal_cert.dashboard_it":
            need = int(rules.get("min_assets", 1))
            if len(data) < need:
                return False, f"assets={len(data)} < {need}", {"count": len(data)}
        return True, f"API count={len(data)}", {"count": len(data)}
    except Exception as e:
        return False, str(e), {}


def run_step(page, step: BrowserStep, screenshot_dir: Path) -> dict:
    actions = ["navigate"]
    try:
        if step.login:
            base = step.url.split("/d/")[0].rstrip("/")
            login_url = f"{base}/login"
            page.goto(login_url, wait_until="domcontentloaded", timeout=60000)
            try_login(page, step)
            actions.append("pre_login")
        resp = page.goto(step.url, wait_until="domcontentloaded", timeout=90000)
        status = resp.status if resp else 0
        if status >= 400:
            return {"ok": False, "detail": f"HTTP {status}", "url": step.url, "actions": actions, "screenshot": ""}
        if "dashboards" in step.url or "grafana" in step.url:
            try:
                page.wait_for_load_state("networkidle", timeout=60000)
            except Exception:
                page.wait_for_timeout(8000)
        else:
            page.wait_for_timeout(2000)
        try_login(page, step)
        human_scroll(page, step.scroll_passes)
        for tab in step.extra_clicks:
            try:
                page.get_by_role("button", name=re.compile(tab, re.I)).first.click(timeout=5000)
                page.wait_for_timeout(1200)
                actions.append(f"click:{tab}")
            except Exception:
                actions.append(f"click_fail:{tab}")
        html = page.content()
        if step.reload:
            page.reload(wait_until="domcontentloaded", timeout=45000)
            page.wait_for_timeout(1500)
            human_scroll(page, 2)
            html = page.content()
            actions.append("reload")
        ok, detail, metrics = run_assertions(page, step, html)
        if step.must_contain:
            ok2, msg2 = strict_check_page_text(html, {"min_body_text": 100, "must_contain": list(step.must_contain)}, step.name)
            if not ok2:
                ok, detail = False, msg2
        shot = mandatory_screenshot(page, step, screenshot_dir) if (step.critical or STRICT) else ""
        if step.critical and not shot:
            ok, detail = False, "screenshot critique manquant"
        return {
            "ok": ok,
            "detail": detail,
            "url": step.url,
            "actions": actions,
            "screenshot": shot,
            "metrics": metrics,
            "expectation_key": step.expectation_key,
            "critical": step.critical,
        }
    except PwTimeout as e:
        return {"ok": False, "detail": f"timeout: {e}", "url": step.url, "actions": actions, "screenshot": ""}
    except Exception as e:
        return {"ok": False, "detail": str(e), "url": step.url, "actions": actions, "screenshot": ""}


def run_timesketch_critical(page, base_ts: str, steps: list) -> None:
    load_env()
    try:
        page.goto(f"{base_ts}/login/", timeout=60000)
        page.fill('input[name="username"]', env("TIMESKETCH_USER", "admin"), timeout=5000)
        page.fill('input[name="password"]', env("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!"), timeout=5000)
        page.locator('button[type="submit"]').click(timeout=10000)
        page.wait_for_load_state("networkidle", timeout=30000)
    except Exception as e:
        record_step(steps, "timesketch.login_session", False, str(e), critical=True)
        return

    page.goto(base_ts + "/", timeout=45000)
    sid = "1"
    links = page.locator("a[href*='/sketch/']")
    if links.count() > 0:
        m = re.search(r"/sketch/(\d+)", links.first.get_attribute("href") or "")
        if m:
            sid = m.group(1)

    views = [
        ("Explore", f"/sketch/{sid}/explore/", "timesketch.explore", JS_TS_EXPLORE, audit_timesketch_explore),
        ("Overview", f"/sketch/{sid}/", "timesketch.overview", JS_TS_OVERVIEW, audit_timesketch_overview),
        ("Intelligence", f"/sketch/{sid}/intelligence/", "timesketch.intelligence", JS_TS_INTELLIGENCE, audit_timesketch_intelligence),
        ("Stories", f"/sketch/{sid}/", "timesketch.stories", JS_TS_STORIES, audit_timesketch_stories),
    ]
    for label, path, ekey, js, audit_fn in views:
        url = base_ts + path
        try:
            page.goto(url, timeout=60000)
            try:
                page.wait_for_load_state("networkidle", timeout=45000)
            except Exception:
                page.wait_for_timeout(8000)
            human_scroll(page, 5)
            page.reload(timeout=40000)
            try:
                page.wait_for_load_state("networkidle", timeout=30000)
            except Exception:
                page.wait_for_timeout(5000)
            human_scroll(page, 3)
            metrics = page.evaluate(js)
            rules = get_expectation_rules(ekey)
            ok, detail, _ = audit_fn(metrics, rules)
            html = page.content()
            if rules.get("must_contain"):
                ok2, msg2 = strict_check_page_text(html, rules, f"ts:{label}")
                if not ok2:
                    ok, detail = False, msg2
            shot = mandatory_screenshot(page, BrowserStep(name=f"ts:{label}", url=url, critical=True), LOG_DIR)
            record_step(
                steps,
                f"ts:{label}",
                ok,
                detail,
                url=url,
                screenshot=shot,
                expectation_key=ekey,
                critical=True,
                metrics=metrics,
            )
            print(f"[browser] {'OK' if ok else 'KO'} ts:{label}: {detail}")
        except Exception as e:
            record_step(steps, f"ts:{label}", False, str(e), url=url, expectation_key=ekey, critical=True)


def main() -> int:
    load_env()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    steps: list[dict] = []
    headless = os.environ.get("FP_BROWSER_HEADLESS", "1") == "1"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = browser.new_context(viewport={"width": 1440, "height": 900}, ignore_https_errors=True)
        page = context.new_page()

        for j in all_browser_journeys():
            r = run_step(page, j, LOG_DIR)
            record_step(
                steps,
                j.name,
                r["ok"],
                r["detail"],
                url=r.get("url"),
                actions=r.get("actions"),
                screenshot=r.get("screenshot"),
                expectation_key=j.expectation_key,
                critical=j.critical,
                metrics=r.get("metrics"),
            )
            print(f"[browser] {'OK' if r['ok'] else 'KO'} {j.name}: {str(r['detail'])[:120]}")

        run_timesketch_critical(page, service_urls()["ts"], steps)
        context.close()
        browser.close()

    data = write_browser_results(steps, "playwright_strict")
    print(f"[fp-browser] GLOBAL={data['global_status']} errors={data['error_count']}/{data['total_steps']}")
    print(f"[fp-browser] human_validation_required={data.get('human_validation_required')}")
    return 0 if data["global_status"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
