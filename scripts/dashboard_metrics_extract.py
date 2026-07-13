#!/usr/bin/env python3
"""Extraction DOM stricte des métriques dashboard (Playwright uniquement — pas HTTP/API)."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dashboard_metrics_lib import (  # noqa: E402
    EXTRACTION_ENGINE,
    JS_EXTRACT_GENERIC,
    JS_EXTRACT_PORTAL_HOME,
    JS_EXTRACT_PORTAL_ZONE,
    METRICS_JSON,
    SCREENSHOT_DIR,
    DashboardTarget,
    all_extraction_targets,
    load_env,
    log,
    map_dom_to_metrics,
    save_metrics_store,
    utc_now,
)
from fp_browser_qa_lib import env  # noqa: E402

try:
    from playwright.sync_api import TimeoutError as PwTimeout
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[dashboard-metrics] KO — pip install playwright && playwright install chromium", file=sys.stderr)
    sys.exit(2)


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
    # Sketch Master via API (priorité [FP] Timesketch Master — données réelles)
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


def screenshot_path(target_id: str) -> Path:
    safe = target_id.replace(".", "_")
    return SCREENSHOT_DIR / f"{safe}.png"


def extract_target(page, target: DashboardTarget, ts_sketch_id: str) -> dict:
    url = target.url
    if target.timesketch_path == "overview":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sketch_id}/"
    elif target.timesketch_path == "intelligence":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sketch_id}/intelligence/"
    elif target.timesketch_path == "explore":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sketch_id}/explore/"
    elif target.timesketch_path == "stories":
        url = f"{env('TIMESKETCH_URL', 'https://localhost/timesketch').rstrip('/')}/sketch/{ts_sketch_id}/"

    out: dict = {
        "target_id": target.target_id,
        "title": target.title,
        "url": url,
        "group": target.group,
        "extract_ok": False,
        "screenshot": "",
        "dom": {},
        "metrics": {},
        "errors": [],
    }

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

        if target.group == "osd":
            for sel in (
                '[data-test-subj="dashboardPanel"]',
                ".embPanel",
                '[class*="embPanel"]',
                '[data-test-subj="dashboardViewport"]',
            ):
                try:
                    page.wait_for_selector(sel, timeout=90000)
                    break
                except Exception:
                    continue
            page.wait_for_timeout(6000)

        for tab in target.extra_clicks:
            clicked = False
            for sel in (
                f'[data-tab-btn="{tab}"]',
                f'button[data-tab-btn="{tab}"]',
                f'button:has-text("Dashboard CERT")' if tab == "dashboard-cert" else f'button:has-text("Dashboard IT")',
            ):
                try:
                    page.locator(sel).first.click(timeout=6000)
                    page.wait_for_timeout(1500)
                    clicked = True
                    break
                except Exception:
                    continue
            if not clicked:
                out["errors"].append(f"click tab {tab} échoué")

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

        if target.portal_zone_id:
            zone_dom = page.evaluate(JS_EXTRACT_PORTAL_ZONE, target.portal_zone_id)
            dom = merge_dom(page.evaluate(JS_EXTRACT_GENERIC), zone_dom)
        elif target.target_id == "portal.cert_home":
            dom = merge_dom(page.evaluate(JS_EXTRACT_GENERIC), page.evaluate(JS_EXTRACT_PORTAL_HOME))
        elif target.target_id == "osd.platform_health":
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(800)
            from fp_browser_qa_assertions import JS_OSD_HEALTH_METRICS  # noqa: E402

            dom = merge_dom(page.evaluate(JS_EXTRACT_GENERIC), page.evaluate(JS_OSD_HEALTH_METRICS))
        elif target.group == "grafana":
            from fp_browser_qa_assertions import JS_GRAFANA_STAT_PANELS  # noqa: E402

            extra = page.evaluate(JS_GRAFANA_STAT_PANELS)
            dom = extra if isinstance(extra, dict) else {}
        else:
            dom = page.evaluate(JS_EXTRACT_GENERIC)
            if not isinstance(dom, dict):
                dom = {}
            if target.group == "timesketch":
                from fp_browser_qa_assertions import (  # noqa: E402
                    JS_TS_EXPLORE,
                    JS_TS_INTELLIGENCE,
                    JS_TS_OVERVIEW,
                    JS_TS_STORIES,
                )

                extra = page.evaluate(
                    JS_TS_INTELLIGENCE
                    if target.timesketch_path == "intelligence"
                    else JS_TS_OVERVIEW
                    if target.timesketch_path == "overview"
                    else JS_TS_STORIES
                    if target.timesketch_path == "stories"
                    else JS_TS_EXPLORE
                )
                generic = page.evaluate(JS_EXTRACT_GENERIC)
                dom = merge_dom(extra if isinstance(extra, dict) else {}, generic if isinstance(generic, dict) else {})

        out["dom"] = dom
        text_len = int(dom.get("textLen") or 0)
        if dom.get("hasError"):
            out["errors"].append("phrase erreur UI détectée (warning)")
        zone_empty = bool(dom.get("empty")) if target.portal_zone_id else False
        min_text = 80 if target.portal_zone_id else 300
        if zone_empty or text_len < min_text:
            out["errors"].append("page blanche / texte insuffisant")

        out["metrics"] = map_dom_to_metrics(target.target_id, dom)
        if not out["metrics"]:
            out["errors"].append("aucune métrique mappée depuis le DOM")

        shot = screenshot_path(target.target_id)
        shot.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(shot), full_page=True)
        out["screenshot"] = str(shot)
        # Pessimiste : au moins une métrique + page non vide ; erreurs panel isolées tolérées si chiffres présents
        out["extract_ok"] = bool(out["metrics"]) and not zone_empty and text_len >= min_text
        if not out["extract_ok"] and not out["errors"]:
            out["errors"].append("extraction pessimiste: doute sur qualité DOM")

    except PwTimeout as e:
        out["errors"].append(f"timeout: {e}")
    except Exception as e:
        out["errors"].append(str(e))

    return out


def main() -> int:
    load_env()
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    targets_cfg = all_extraction_targets()
    store: dict = {
        "meta": {
            "extracted_at": utc_now(),
            "engine": EXTRACTION_ENGINE,
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

        for target in targets_cfg:
            if not target.timesketch_path and target.group == "timesketch":
                continue
            log(f"extract {target.target_id} …")
            result = extract_target(page, target, ts_sid)
            store["targets"][target.target_id] = result
            status = "OK" if result["extract_ok"] else "KO"
            log(f"  {status} {target.target_id} metrics={len(result.get('metrics') or {})} shot={bool(result.get('screenshot'))}")
            if not result["extract_ok"]:
                failures += 1
                for err in result.get("errors") or []:
                    log(f"    → {err}")

        browser.close()

    path = save_metrics_store(store)
    log(f"écrit {path} ({len(store['targets'])} cibles)")
    if failures:
        log(f"KO — {failures} extraction(s) en échec (mode pessimiste)")
        return 1
    log("extractions DOM terminées — comparaison requise ensuite")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
