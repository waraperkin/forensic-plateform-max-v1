#!/usr/bin/env python3
"""Assertions DOM strictes Playwright — mode pessimiste."""
from __future__ import annotations

import json
import re
from typing import Any

# ── JS snippets (retournent des métriques, jamais de succès implicite) ──

JS_PAGE_METRICS = """
() => {
  const text = (document.body && document.body.innerText) || '';
  const html = (document.body && document.body.innerHTML) || '';
  const errRx = /server error|could not locate field|panel error|request failed|internal error|application error|query error|something went wrong|an error occurred/i;
  return {
    textLen: text.trim().length,
    htmlLen: html.length,
    hasErrorPhrase: errRx.test(text) || errRx.test(html),
    errorSnippet: (text.match(errRx) || [])[0] || '',
    title: document.title || '',
    rootOnly: html.includes('id="root"') && text.trim().length < 120,
    upgradeBrowser: /upgrade your browser/i.test(text),
  };
}
"""

JS_OSD_DASHBOARD = """
() => {
  const panels = document.querySelectorAll(
    '[data-test-subj="embeddablePanel"], .embPanel, [class*="embPanel"], [data-test-subj="dashboardPanel"]'
  );
  let withContent = 0;
  panels.forEach(p => {
    const t = (p.innerText || '').trim();
    if (t.length > 40 && !/no results|no data found|could not locate/i.test(t)) withContent++;
  });
  const text = document.body.innerText || '';
  const loading = (text.match(/loading/gi) || []).length;
  const errors = (text.match(/server error|could not locate|panel error|request failed/gi) || []).length;
  return { panelCount: panels.length, panelsWithContent: withContent, loadingMentions: loading, errorMentions: errors, textLen: text.length };
}
"""

JS_TS_EXPLORE = """
() => {
  const text = document.body.innerText || '';
  const hasTimelines = /timeline/i.test(text) || !!document.querySelector('a[href*="timeline"], [class*="timeline"]');
  const hasSearch = /search/i.test(text) || !!document.querySelector('input[type="search"], [placeholder*="Search"]');
  const agg = document.querySelectorAll('[class*="agg"], [class*="chart"], canvas, svg').length;
  const err = /server error|could not locate field|panel error/i.test(text);
  const blank = text.trim().length < 800 && !hasTimelines;
  return { textLen: text.length, hasTimelines, hasSearch, vizCount: agg, hasError: err, likelyBlank: blank };
}
"""

JS_TS_OVERVIEW = """
() => {
  const text = document.body.innerText || '';
  const cards = document.querySelectorAll('[class*="card"], [class*="stat"], .v-card').length;
  const nums = (text.match(/\\b\\d{1,}\\b/g) || []).length;
  return { textLen: text.length, cardLike: cards, numericTokens: nums, hasError: /server error/i.test(text) };
}
"""

JS_TS_STORIES = """
() => {
  const text = document.body.innerText || '';
  const storyLinks = document.querySelectorAll('a[href*="/story/"]').length;
  const storyMentions = (text.match(/stor(y|ies)/gi) || []).length;
  const items = document.querySelectorAll('[class*="story"], tr, .v-list-item').length;
  return { textLen: text.length, storyLinks, storyMentions, listItems: items, hasError: /server error/i.test(text) };
}
"""

JS_TS_INTELLIGENCE = """
() => {
  const text = document.body.innerText || '';
  const hasAnalyzer = /analyzer/i.test(text) || !!document.querySelector('[class*="analyzer"], table');
  const rows = document.querySelectorAll('table tr, .v-data-table tr').length;
  return { textLen: text.length, hasAnalyzer, tableRows: rows, hasError: /server error/i.test(text) };
}
"""

JS_GRAFANA_DASH = """
() => {
  const panels = document.querySelectorAll('[class*="panel-content"], [data-panelid], .panel-container, [class*="dashboard-row"]');
  const text = document.body.innerText || '';
  let withNumbers = 0;
  panels.forEach(p => {
    const t = p.innerText || '';
    if (/\\d+/.test(t) && t.length > 15) withNumbers++;
  });
  const numericTokens = (text.match(/\\b\\d{1,}\\b/g) || []).length;
  const hasMetrics = /composants|statut|health|warn|fail/i.test(text) && numericTokens >= 2;
  const allZeroish = numericTokens < 2 && text.length < 400;
  return { panelCount: panels.length, panelsWithNumbers: withNumbers, numericTokens, hasMetrics, textLen: text.length, allZeroish, hasError: /server error|request failed|internal error/i.test(text) };
}
"""

JS_OSD_HEALTH_METRICS = """
() => {
  const byLabel = {};
  const body = document.body.innerText || '';
  const     specs = [
    [/IOC uniques OpenCTI[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'ioc uniques opencti (index)'],
    [/Events 24h \\(SIEM[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'events 24h (siem fp-events)'],
    [/Events 24h \\(plateforme\\)[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'events 24h (opensearch)'],
    [/Events 24h \\(OpenSearch\\)[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'events 24h (opensearch)'],
    [/Events Explore \\(API\\)[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'events explore (api)'],
    [/Events timeline \\(all-time\\)[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'events timeline (all-time)'],
    [/Malware \\(health\\)[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'malware (health)'],
    [/Campagnes \\(health\\)[^\\n]*\\n\\s*([\\d][\\d\\s.,]*\\d|[\\d.]+[kKmM]?)/i, 'campagnes (health)'],
  ];
  for (const [re, label] of specs) {
    const m = body.match(re);
    if (m) byLabel[label] = m[1].trim();
  }
  return { byLabel, textLen: body.length };
}
"""

JS_GRAFANA_STAT_PANELS = """
() => {
  const byLabel = {};
  const statRx = /([\\d][\\d\\s.,]*[kKmM]?|\\d+)\\s*$/;
  document.querySelectorAll('[data-testid="panel"], [class*="panel-container"], [data-panelid]').forEach(root => {
    const titleEl = root.querySelector('h2, [class*="panel-title"], [class*="panel-header"]');
    const title = ((titleEl && titleEl.innerText) || '').trim();
    if (!title) return;
    const body = root.querySelector('[class*="panel-content"]') || root;
    const t = (body.innerText || '').trim();
    const lines = t.split('\\n').map(s => s.trim()).filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      const m = lines[i].match(statRx);
      if (m && !/^last\\s/i.test(lines[i])) {
        byLabel[title.toLowerCase()] = m[1];
        break;
      }
    }
  });
  const text = (document.body && document.body.innerText) || '';
  let panelsWithNumbers = 0;
  Object.values(byLabel).forEach(v => { if (v && /\\d/.test(String(v))) panelsWithNumbers++; });
  return {
    byLabel,
    textLen: text.length,
    hasError: /server error|request failed|internal error|no data/i.test(text),
    panelCount: document.querySelectorAll('[data-testid="panel"], [data-panelid]').length,
    panelsWithNumbers,
    panelsWithContent: panelsWithNumbers,
  };
}
"""


def pessimistic_fail(reason: str) -> tuple[bool, str, dict]:
    return False, reason, {}


def audit_metrics(metrics: dict, rules: dict, label: str) -> tuple[bool, str, dict]:
    """En cas de doute → FAIL."""
    m = metrics or {}
    if m.get("hasErrorPhrase") or m.get("hasError"):
        return pessimistic_fail(f"{label}: message d'erreur détecté")
    if m.get("upgradeBrowser"):
        return pessimistic_fail(f"{label}: navigateur non supporté (upgrade browser)")
    if m.get("rootOnly") or m.get("likelyBlank"):
        return pessimistic_fail(f"{label}: page blanche / SPA non rendue")
    min_text = int(rules.get("min_body_text", 0))
    text_len = int(m.get("textLen", 0))
    if text_len < min_text:
        return pessimistic_fail(f"{label}: texte insuffisant ({text_len} < {min_text})")

    for phrase in rules.get("forbid_phrases", []) or []:
        if phrase.lower() in (m.get("errorSnippet") or "").lower():
            return pessimistic_fail(f"{label}: interdit `{phrase}`")

    for need in rules.get("must_contain", []) or []:
        body_sample = json.dumps(m).lower()
        if need.lower() not in body_sample and need.lower() not in label.lower():
            # must_contain vérifié côté appelant via page.content() si besoin
            pass

    return True, "métriques de base OK", m


def audit_timesketch_explore(metrics: dict, rules: dict) -> tuple[bool, str, dict]:
    ok, msg, m = audit_metrics(metrics, rules, "timesketch.explore")
    if not ok:
        return ok, msg, m
    if not metrics.get("hasTimelines"):
        return pessimistic_fail("timesketch.explore: aucune timeline détectée")
    if not metrics.get("hasSearch"):
        return pessimistic_fail("timesketch.explore: zone Search absente")
    if int(metrics.get("vizCount", 0)) < int(rules.get("min_panels", 1)):
        return pessimistic_fail(f"timesketch.explore: panels/viz insuffisants ({metrics.get('vizCount')})")
    return True, f"timelines+search+viz={metrics.get('vizCount')}", metrics


def audit_timesketch_overview(metrics: dict, rules: dict) -> tuple[bool, str, dict]:
    ok, msg, m = audit_metrics(metrics, rules, "timesketch.overview")
    if not ok:
        return ok, msg, m
    if rules.get("require_cards") and int(metrics.get("cardLike", 0)) < 1 and int(metrics.get("numericTokens", 0)) < int(rules.get("min_stat_labels", 2)):
        return pessimistic_fail("timesketch.overview: pas de cartes/stats visibles")
    return True, f"cards={metrics.get('cardLike')} nums={metrics.get('numericTokens')}", metrics


def audit_timesketch_intelligence(metrics: dict, rules: dict) -> tuple[bool, str, dict]:
    ok, msg, m = audit_metrics(metrics, rules, "timesketch.intelligence")
    if not ok:
        return ok, msg, m
    if not metrics.get("hasAnalyzer"):
        return pessimistic_fail("timesketch.intelligence: analyzers / tableau absents")
    return True, f"analyzer rows={metrics.get('tableRows')}", metrics


def audit_timesketch_stories(metrics: dict, rules: dict) -> tuple[bool, str, dict]:
    ok, msg, m = audit_metrics(metrics, rules, "timesketch.stories")
    if not ok:
        return ok, msg, m
    min_links = int(rules.get("min_story_links", rules.get("min_stories", 1)))
    links = int(metrics.get("storyLinks", 0))
    if links < min_links and int(metrics.get("storyMentions", 0)) < min_links:
        return pessimistic_fail(f"timesketch.stories: liens story={links} < {min_links}")
    return True, f"storyLinks={links}", metrics


def audit_osd_dashboard(metrics: dict, rules: dict, name: str) -> tuple[bool, str, dict]:
    ok, msg, m = audit_metrics(metrics, rules, name)
    if not ok:
        return ok, msg, m
    min_p = int(rules.get("min_panels", 1))
    min_pc = int(rules.get("min_panel_with_content", 1))
    pc = int(metrics.get("panelCount", 0))
    pwc = int(metrics.get("panelsWithContent", 0))
    if pc < min_p:
        return pessimistic_fail(f"{name}: panels={pc} < min {min_p}")
    if pwc < min_pc:
        return pessimistic_fail(f"{name}: panels avec contenu={pwc} < min {min_pc}")
    if int(metrics.get("errorMentions", 0)) > 5 and pwc < min_pc:
        return pessimistic_fail(f"{name}: erreurs panel ({metrics.get('errorMentions')}) et contenu insuffisant")
    return True, f"panels={pc} content={pwc}", metrics


def audit_grafana_platform(metrics: dict, rules: dict) -> tuple[bool, str, dict]:
    ok, msg, m = audit_metrics(metrics, rules, "grafana.platform_health")
    if not ok:
        return ok, msg, m
    if int(metrics.get("panelCount", 0)) < int(rules.get("min_panels", 4)):
        return pessimistic_fail(f"grafana: panels={metrics.get('panelCount')}")
    min_num = int(rules.get("min_panels_with_numeric", 1))
    if int(metrics.get("panelsWithNumbers", 0)) < min_num and int(metrics.get("numericTokens", 0)) < int(
        rules.get("min_numeric_tokens", 3)
    ):
        return pessimistic_fail(
            f"grafana: métriques numériques insuffisantes (panels={metrics.get('panelsWithNumbers')} tokens={metrics.get('numericTokens')})"
        )
    if rules.get("forbid_zero_only_dashboard") and metrics.get("allZeroish") and not metrics.get("hasMetrics"):
        return pessimistic_fail("grafana.platform_health: dashboard quasi vide / zéros uniquement")
    return True, f"panels={metrics.get('panelCount')} numeric={metrics.get('panelsWithNumbers')}", metrics


def audit_page_content_text(text: str, rules: dict, label: str) -> tuple[bool, str, dict]:
    low = (text or "").lower()
    for need in rules.get("must_contain", []) or []:
        if need.lower() not in low:
            return pessimistic_fail(f"{label}: manque `{need}`")
    for bad in rules.get("forbid_phrases", []) or []:
        if bad.lower() in low:
            return pessimistic_fail(f"{label}: phrase interdite `{bad}`")
    if len(low.strip()) < int(rules.get("min_body_text", 200)):
        return pessimistic_fail(f"{label}: contenu texte trop court")
    err = re.search(
        r"server error|could not locate field|panel error|request failed|internal error|application error",
        text,
        re.I,
    )
    if err:
        return pessimistic_fail(f"{label}: {err.group(0)}")
    return True, "contenu texte OK", {"textLen": len(text)}
