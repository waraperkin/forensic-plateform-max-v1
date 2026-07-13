#!/usr/bin/env python3
"""Détection panels cassés / pages blanches — Playwright DOM uniquement."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dashboard_metrics_lib import (  # noqa: E402
    DashboardTarget,
    PANELS_JSON,
    PANELS_SCREENSHOT_DIR,
    all_panel_targets,
    evaluate_panel_dom,
    load_env,
    load_panels_expected,
    log,
    utc_now,
)
from fp_browser_qa_assertions import (  # noqa: E402
    JS_GRAFANA_DASH,
    JS_GRAFANA_STAT_PANELS,
    JS_OSD_DASHBOARD,
    JS_PAGE_METRICS,
    JS_TS_EXPLORE,
    JS_TS_INTELLIGENCE,
    JS_TS_OVERVIEW,
    JS_TS_STORIES,
)
from fp_browser_qa_lib import env  # noqa: E402

try:
    from playwright.sync_api import TimeoutError as PwTimeout
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[dashboard-panels] KO — pip install playwright && playwright install chromium", file=sys.stderr)
    sys.exit(2)

JS_DOM_NODES = """
() => ({
  nodeCount: document.querySelectorAll('*').length,
  bodySample: ((document.body && document.body.innerText) || '').slice(0, 4000),
})
"""

JS_PORTAL_ZONE = """
(zoneId) => {
  const el = document.getElementById(zoneId);
  const text = el ? (el.innerText || '') : '';
  const nums = (text.match(/\\b[\\d][\\d\\s.,]*\\d|\\d+\\b/g) || []);
  const byLabel = {};
  if (el) {
    el.querySelectorAll('.fp-stat').forEach(st => {
      const v = st.querySelector('.fp-stat-value');
      const l = st.querySelector('.fp-stat-label');
      if (v && l) byLabel[(l.innerText||'').trim().toLowerCase()] = (v.innerText||'').trim();
    });
  }
  let incidentCount = null;
  let assetCount = null;
  for (const [lab, raw] of Object.entries(byLabel)) {
    if (/incident|ticket/.test(lab)) incidentCount = parseInt(String(raw).replace(/\\D/g,''), 10) || null;
    if (/asset/.test(lab)) assetCount = parseInt(String(raw).replace(/\\D/g,''), 10) || null;
  }
  const fallback = (key) => {
    const variants = [key, key.replace(/_/g, ' '), key.replace(/ /g, '_')];
    for (const v of variants) {
      if (byLabel[v]) return parseInt(String(byLabel[v]).replace(/\\D/g,''), 10) || null;
    }
    return null;
  };
  if (assetCount === null) assetCount = fallback('zones_active');
  if (assetCount === null) assetCount = fallback('uploads_it');
  return {
    textLen: text.length,
    nums,
    byLabel,
    incidentCount,
    assetCount,
    panelCount: el ? el.querySelectorAll('.fp-stat, .card, [class*="panel"]').length : 0,
    panelsWithContent: el ? [...el.querySelectorAll('.fp-stat')].filter(x => (x.innerText||'').length > 10).length : 0,
    empty: text.trim().length < 30,
  };
}
"""


def try_grafana_login(page, cred: dict[str, str]) -> None:
    try:
        page.fill('input[name="user"]', cred.get("user", "admin"), timeout=4000)
        page.fill('input[name="password"]', cred.get("pass", ""), timeout=4000)
        page.locator('button[type="submit"]').click(timeout=8000)
        page.wait_for_timeout(1500)
    except Exception:
        pass


def try_timesketch_login(page) -> str:
    base = env("TIMESKETCH_URL", "https://localhost/timesketch").rstrip("/")
    page.goto(f"{base}/login/", wait_until="domcontentloaded", timeout=60000)
    page.fill('input[name="username"]', env("TIMESKETCH_USER", "admin"), timeout=5000)
    page.fill('input[name="password"]', env("TIMESKETCH_PASSWORD", "F0r3ns1c_TS_2024!"), timeout=5000)
    page.locator('button[type="submit"]').click(timeout=10000)
    try:
        page.wait_for_load_state("networkidle", timeout=30000)
    except Exception:
        page.wait_for_timeout(5000)
    try:
        from timesketch_master_lib import get_master_sketch_id, ts_client  # noqa: E402

        return str(get_master_sketch_id(ts_client()))
    except Exception:
        pass
    page.goto(f"{base}/", timeout=45000)
    sid = "1"
    links = page.locator("a[href*='/sketch/']")
    if links.count() > 0:
        m = re.search(r"/sketch/(\d+)", links.first.get_attribute("href") or "")
        if m:
            sid = m.group(1)
    return sid


def human_scroll(page, n: int = 4) -> None:
    for _ in range(n):
        page.mouse.wheel(0, 700)
        page.wait_for_timeout(400)


def profile_js(profile: str) -> str:
    return {
        "osd": JS_OSD_DASHBOARD,
        "grafana": JS_GRAFANA_STAT_PANELS,
        "ts_overview": JS_TS_OVERVIEW,
        "ts_explore": JS_TS_EXPLORE,
        "ts_intelligence": JS_TS_INTELLIGENCE,
        "ts_stories": JS_TS_STORIES,
        "portal": JS_PAGE_METRICS,
        "portal_zone": JS_PORTAL_ZONE,
    }.get(profile, JS_PAGE_METRICS)


def merge_dom(*parts: dict) -> dict:
    merged: dict = {}
    max_text = 0
    for part in parts:
        if isinstance(part, dict):
            max_text = max(max_text, int(part.get("textLen") or 0))
            merged.update(part)
    if max_text:
        merged["textLen"] = max_text
    return merged


def check_target(page, target: DashboardTarget, ts_sid: str, rules: dict, global_meta: dict) -> dict:
    url = target.url
    if target.timesketch_path == "overview":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sid}/"
    elif target.timesketch_path == "intelligence":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sid}/intelligence/"
    elif target.timesketch_path == "explore":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sid}/explore/"
    elif target.timesketch_path == "stories":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sid}/"

    out: dict = {
        "target_id": target.target_id,
        "title": target.title,
        "url": url,
        "check_ok": False,
        "screenshot": "",
        "dom": {},
        "issues": [],
        "errors": [],
    }

    js_profile = rules.get("js_profile", "portal")
    try:
        if target.login:
            base = url.split("/d/")[0].rstrip("/")
            page.goto(f"{base}/login", wait_until="domcontentloaded", timeout=60000)
            try_grafana_login(page, target.login)

        resp = page.goto(url, wait_until="domcontentloaded", timeout=90000)
        if resp and resp.status >= 400:
            out["errors"].append(f"HTTP {resp.status}")
            return out

        if target.wait_networkidle:
            try:
                page.wait_for_load_state("networkidle", timeout=60000)
            except Exception:
                page.wait_for_timeout(8000)
        else:
            page.wait_for_timeout(2500)

        for tab in target.extra_clicks:
            for sel in (
                f'[data-tab-btn="{tab}"]',
                f'button[data-tab-btn="{tab}"]',
                f'button:has-text("Dashboard CERT")' if tab == "dashboard-cert" else f'button:has-text("Dashboard IT")',
            ):
                try:
                    page.locator(sel).first.click(timeout=6000)
                    page.wait_for_timeout(1500)
                    break
                except Exception:
                    continue

        if target.portal_zone_id:
            try:
                page.wait_for_function(
                    """(zid) => {
                        const el = document.getElementById(zid);
                        if (!el) return false;
                        const t = (el.innerText || '').trim();
                        if (t.length < 40) return false;
                        if (/chargement/i.test(t)) return false;
                        if (el.querySelectorAll('.fp-stat').length < 1) return false;
                        return true;
                    }""",
                    arg=target.portal_zone_id,
                    timeout=15000,
                )
            except Exception:
                page.wait_for_timeout(3000)

        if target.timesketch_path == "stories":
            for sel in ('a[href*="story"]', 'button:has-text("Stories")', '[aria-label*="Stories"]'):
                try:
                    page.locator(sel).first.click(timeout=5000)
                    page.wait_for_timeout(2000)
                    break
                except Exception:
                    continue

        human_scroll(page, target.scroll_passes)

        js = profile_js(js_profile)
        if js_profile == "portal_zone" and target.portal_zone_id:
            dom = merge_dom(page.evaluate(JS_DOM_NODES), page.evaluate(js, target.portal_zone_id))
        else:
            dom = merge_dom(page.evaluate(JS_DOM_NODES), page.evaluate(js))

        out["dom"] = dom
        eval_result = evaluate_panel_dom(target.target_id, dom, rules, global_meta)
        out["issues"] = eval_result.get("issues") or []
        out["check_ok"] = bool(eval_result.get("ok"))

        safe = target.target_id.replace(".", "_")
        shot = PANELS_SCREENSHOT_DIR / f"{safe}.png"
        shot.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(shot), full_page=True)
        out["screenshot"] = str(shot)

        if target.portal_zone_id and dom.get("empty"):
            out["check_ok"] = False
            out["issues"].append("zone portail vide")

    except PwTimeout as e:
        out["errors"].append(f"timeout: {e}")
    except Exception as e:
        out["errors"].append(str(e))

    if out["errors"]:
        out["check_ok"] = False
        out["issues"].extend(out["errors"])

    return out


def main() -> int:
    load_env()
    cfg = load_panels_expected()
    global_meta = cfg.get("meta") or {}
    targets_rules = cfg.get("targets") or {}
    PANELS_SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    store: dict = {
        "meta": {
            "checked_at": utc_now(),
            "engine": "playwright_dom",
            "human_validation_required": True,
            "human_validated": os.environ.get("FP_DASHBOARD_METRICS_HUMAN_OK", "") == "1",
            "pessimistic": True,
        },
        "targets": {},
    }

    headless = os.environ.get("FP_BROWSER_HEADLESS", "1") == "1"
    failures = 0

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = browser.new_context(viewport={"width": 1440, "height": 900}, ignore_https_errors=True)
        page = context.new_page()

        ts_sid = "1"
        try:
            ts_sid = try_timesketch_login(page)
            log(f"Timesketch sketch_id={ts_sid}")
        except Exception as e:
            log(f"Timesketch login WARN: {e}")

        for target in all_panel_targets():
            if not target.timesketch_path and target.group == "timesketch":
                continue
            rules = targets_rules.get(target.target_id) or {}
            log(f"panels {target.target_id} …")
            result = check_target(page, target, ts_sid, rules, global_meta)
            store["targets"][target.target_id] = result
            status = "OK" if result["check_ok"] else "KO"
            log(f"  {status} issues={len(result.get('issues') or [])} shot={bool(result.get('screenshot'))}")
            if not result["check_ok"]:
                failures += 1
                for issue in result.get("issues") or []:
                    log(f"    → {issue}")

        browser.close()

    PANELS_JSON.parent.mkdir(parents=True, exist_ok=True)
    PANELS_JSON.write_text(json.dumps(store, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log(f"écrit {PANELS_JSON} ({len(store['targets'])} cibles)")

    if failures:
        log(f"KO — {failures} dashboard(s) avec panels/page invalides")
        return 1
    log("panels check terminé — comparaison/verify requis ensuite")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
