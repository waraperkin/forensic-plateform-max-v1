#!/usr/bin/env python3
"""Moteur de comparaison de métriques dashboard — extraction DOM, normalisation, règles strictes."""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

ROOT = Path(__file__).resolve().parents[1]
RELATIONS_PATH = ROOT / "config" / "dashboard_expected_relations.yaml"
PANELS_PATH = ROOT / "config" / "dashboard_panels_expected.yaml"
METRICS_JSON = Path(os.environ.get("FP_DASHBOARD_METRICS_JSON", "/tmp/fp-dashboard-metrics.json"))
PANELS_JSON = Path(os.environ.get("FP_DASHBOARD_PANELS_JSON", "/tmp/fp-dashboard-panels.json"))
COMPARE_JSON = Path(os.environ.get("FP_DASHBOARD_METRICS_COMPARE_JSON", "/tmp/fp-dashboard-metrics-compare.json"))
REPORT_MD = ROOT / "docs" / "DASHBOARD_METRICS_REPORT.md"
SCREENSHOT_DIR = Path(os.environ.get("FP_DASHBOARD_METRICS_SCREENSHOTS", str(ROOT / "logs" / "fp-browser-qa" / "dashboards")))
PANELS_SCREENSHOT_DIR = Path(os.environ.get("FP_DASHBOARD_PANELS_SCREENSHOTS", str(ROOT / "logs" / "fp-browser-qa" / "panels")))

# Chemins métriques alias → cible réelle (comparaison inter-outils)
METRIC_PATH_ALIASES: dict[str, str] = {
    "opencti.indicators.total": "osd.ti_overview.total_ioc",
    "opencti.entities.total": "osd.ti_overview.total_cti_entities",
    "thehive.cases.total": "osd.incident_commander.total_incidents",
    "sigma.hits": "osd.security_events.total_sigma_hits",
    "sigma.hits.total": "osd.security_events.total_sigma_hits",
    "ts.incident.total_events": "osd.incident_commander.total_incident_commander_events",
    "ts.purple.total_events": "osd.purple_team.total_purple_team_events",
    "portal.cert.total_incidents": "portal.cert_dashboard.total_incidents",
    "portal.cert.total_uploads": "portal.cert_dashboard.total_uploads",
    "portal.it.total_assets": "portal.it_dashboard.total_assets",
    "portal.it.total_uploads": "portal.it_dashboard.total_uploads",
    "ts.intelligence.analyzers_results": "ts.intelligence.total_analyzers_results",
}

# Extraction DOM uniquement — pas d'API/HTTP comme source primaire
EXTRACTION_ENGINE = "playwright_dom"

METRIC_KEYS = (
    "total_events",
    "total_events_24h_siem",
    "total_alerts",
    "total_ioc",
    "total_anomalies",
    "total_incidents",
    "total_assets",
    "total_cti_entities",
    "total_sigma_hits",
    "total_analyzers_results",
    "total_purple_team_events",
    "total_incident_commander_events",
    "total_uploads",
    "uploads_cert",
    "uploads_it",
    "tokens_active",
    "events_windows",
    "events_linux_macos",
    "events_web",
    "events_network",
    "events_cloud",
    "events_endpoint",
)

# ── JavaScript DOM extractors (retournent dict label→raw string + agrégats) ──

JS_EXTRACT_GENERIC = """
() => {
  const out = { byLabel: {}, panels: [], numericTokens: [] };
  const text = (document.body && document.body.innerText) || '';
  const tokenRx = /\\b([\\d][\\d\\s.,]*\\d|\\d+)(?:\\s*([kKmM]))?\\b/g;
  let m;
  while ((m = tokenRx.exec(text)) !== null) {
    out.numericTokens.push(m[0].trim());
  }
  const panelSel = [
    '[data-test-subj="embeddablePanel"]',
    '.embPanel',
    '[class*="panel-content"]',
    '[data-panelid]',
    '.panel-container',
    '[class*="dashboard-row"]',
    '.fp-stat',
    '[class*="stat-panel"]',
  ].join(',');
  document.querySelectorAll(panelSel).forEach((el, i) => {
    const t = (el.innerText || '').trim();
    if (t.length < 3) return;
    const lines = t.split('\\n').map(s => s.trim()).filter(Boolean);
    const nums = (t.match(/\\b[\\d][\\d\\s.,]*\\d|\\d+\\b/g) || []);
    out.panels.push({ i, lines: lines.slice(0, 8), nums, len: t.length });
    if (lines.length >= 2) {
      const label = lines.slice(0, 3).join(' ').toLowerCase();
      const num = nums[nums.length - 1] || nums[0];
      if (num) out.byLabel[label] = num;
    }
  });
  document.querySelectorAll('.fp-stat').forEach(st => {
    const val = st.querySelector('.fp-stat-value');
    const lab = st.querySelector('.fp-stat-label');
    if (val && lab) out.byLabel[(lab.innerText || '').trim().toLowerCase()] = (val.innerText || '').trim();
  });
  out.textLen = text.length;
  out.title = document.title || '';
  out.hasError = /server error|could not locate|panel error|no data found|request failed|internal error/i.test(text);
  out.hasBlank = text.trim().length < 400;
  return out;
}
"""

JS_EXTRACT_PORTAL_HOME = """
() => {
  const ids = {
    uploads_cert: 'su', uploads_it: 'si', tokens_active: 'st',
    events_windows: 'ps-win', events_linux_macos: 'ps-lin',
    events_web: 'ps-web', events_network: 'ps-net',
    events_cloud: 'ps-cld', events_endpoint: 'ps-ep'
  };
  const byId = {};
  for (const [k, id] of Object.entries(ids)) {
    const el = document.getElementById(id);
    byId[k] = el ? (el.innerText || '').trim() : null;
  }
  const text = (document.body && document.body.innerText) || '';
  return {
    byId,
    textLen: text.length,
    title: document.title || '',
    hasError: /error|échec/i.test(text) && text.length < 500,
    hasBlank: text.trim().length < 400
  };
}
"""

JS_EXTRACT_PORTAL_ZONE = """
(zoneId) => {
  const el = document.getElementById(zoneId);
  const text = el ? (el.innerText || '') : '';
  const byLabel = {};
  if (el) {
    el.querySelectorAll('.fp-stat').forEach(st => {
      const v = st.querySelector('.fp-stat-value');
      const l = st.querySelector('.fp-stat-label');
      if (v && l) byLabel[(l.innerText||'').trim().toLowerCase()] = (v.innerText||'').trim();
    });
  }
  const nums = (text.match(/\\b[\\d][\\d\\s.,]*\\d|\\d+\\b/g) || []);
  return { byLabel, nums, textLen: text.length, empty: text.trim().length < 30 };
}
"""


@dataclass
class DashboardTarget:
    target_id: str
    title: str
    url: str
    group: str
    login: dict[str, str] | None = None
    extra_clicks: list[str] = field(default_factory=list)
    wait_networkidle: bool = False
    timesketch_path: str = ""
    portal_zone_id: str = ""
    grafana_uid: str = ""
    osd_dashboard_id: str = ""
    scroll_passes: int = 4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(msg: str) -> None:
    print(f"[dashboard-metrics] {msg}", flush=True)


def load_env() -> None:
    env = ROOT / ".env"
    if not env.is_file():
        return
    for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def service_urls() -> dict[str, str]:
    load_env()
    base_cert = env("CERT_PORTAL_URL", "https://localhost").rstrip("/")
    return {
        "osd": env("OSD_URL", "https://localhost/dashboards").rstrip("/"),
        "grafana": env("GRAFANA_URL", "https://localhost/grafana").rstrip("/"),
        "ts": env("TIMESKETCH_URL", "https://localhost/timesketch").rstrip("/"),
        "cert": base_cert,
        "it": env("IT_PORTAL_URL", f"{base_cert}/it").rstrip("/"),
    }


def all_extraction_targets() -> list[DashboardTarget]:
    u = service_urls()
    ts_base = u["ts"]
    return [
        DashboardTarget("osd.security_events", "Security Operations — Overview", f"{u['osd']}/app/dashboards#/view/fp-opensearch-security", "osd", wait_networkidle=True, osd_dashboard_id="fp-opensearch-security", scroll_passes=10),
        DashboardTarget("osd.ti_overview", "Threat Intelligence — Overview", f"{u['osd']}/app/dashboards#/view/fp-ti-overview", "osd", wait_networkidle=True, osd_dashboard_id="fp-ti-overview"),
        DashboardTarget("osd.incident_commander", "Incident Response — Commander", f"{u['osd']}/app/dashboards#/view/fp-incident-commander-playbook", "osd", wait_networkidle=True, osd_dashboard_id="fp-incident-commander-playbook"),
        DashboardTarget("osd.purple_team", "Purple Teaming — Operations", f"{u['osd']}/app/dashboards#/view/fp-purple-team-playbook", "osd", wait_networkidle=True, osd_dashboard_id="fp-purple-team-playbook"),
        DashboardTarget("osd.platform_health", "Platform Health — System Metrics", f"{u['osd']}/app/dashboards#/view/fp-platform-health", "osd", wait_networkidle=True, osd_dashboard_id="fp-platform-health", scroll_passes=8),
        DashboardTarget("grafana.platform_health", "Metrics — Platform Overview", f"{u['grafana']}/d/fp-platform-health-gf/fp-platform-health", "grafana", login={"user": env("GRAFANA_ADMIN_USER", "admin"), "pass": env("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")}, grafana_uid="fp-platform-health-gf", wait_networkidle=True),
        DashboardTarget("grafana.opensearch_metrics", "Metrics — OpenSearch Cluster", f"{u['grafana']}/d/fp-opensearch-metrics/fp-opensearch-metrics", "grafana", login={"user": env("GRAFANA_ADMIN_USER", "admin"), "pass": env("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")}, grafana_uid="fp-opensearch-metrics", wait_networkidle=True),
        DashboardTarget("grafana.timesketch_metrics", "Metrics — Timesketch Activity", f"{u['grafana']}/d/fp-timesketch-metrics/fp-timesketch-metrics", "grafana", login={"user": env("GRAFANA_ADMIN_USER", "admin"), "pass": env("GRAFANA_ADMIN_PASSWORD", "F0r3ns1c_GF_2024!")}, grafana_uid="fp-timesketch-metrics", wait_networkidle=True),
        DashboardTarget("portal.cert_home", "CERT — National Operations Portal", f"{u['cert']}/", "portal", scroll_passes=3),
        DashboardTarget("portal.cert_dashboard", "CERT — Situation Overview", f"{u['cert']}/", "portal", extra_clicks=["dashboard-cert"], portal_zone_id="zone-dashboard-cert"),
        DashboardTarget("portal.it_dashboard", "IT — Exposure Overview", f"{u['cert']}/", "portal", extra_clicks=["dashboard-it"], portal_zone_id="zone-dashboard-it"),
        # Timesketch views filled dynamically with sketch id
        DashboardTarget("ts.overview", "Forensics — Overview", f"{ts_base}/", "timesketch", timesketch_path="overview"),
        DashboardTarget("ts.intelligence", "Forensics — Intelligence", f"{ts_base}/", "timesketch", timesketch_path="intelligence"),
        DashboardTarget("ts.explore", "Forensics — Timeline Explorer", f"{ts_base}/", "timesketch", timesketch_path="explore", wait_networkidle=True),
        DashboardTarget("ts.stories", "Forensics — Stories", f"{ts_base}/", "timesketch", timesketch_path="stories"),
    ]


def all_panel_targets() -> list[DashboardTarget]:
    return all_extraction_targets()


def normalize_number(raw: Any) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        if raw < 0 or math.isnan(raw):
            return None
        return int(raw)
    s = str(raw).strip()
    if "\n" in s:
        s = s.split("\n", 1)[0].strip()
    s = s.lower().replace("\u202f", "").replace(" ", "").replace(",", "")
    if not s or s in ("—", "-", "n/a", "na", "null"):
        return None
    mult = 1
    # Évite de traiter l'intervalle Grafana « 1m » comme 1 million
    if re.match(r"^\d{2,}[km]$", s) or re.match(r"^\d+\.\d+[km]$", s):
        if s.endswith("k"):
            mult = 1000
            s = s[:-1]
        elif s.endswith("m"):
            mult = 1_000_000
            s = s[:-1]
    s = re.sub(r"[^\d.]", "", s)
    if not s:
        return None
    try:
        v = float(s)
    except ValueError:
        return None
    if v < 0:
        return None
    return int(v * mult)


def extract_of_totals(panels: list[dict[str, Any]]) -> list[int]:
    """Extrait les totaux « 1–N of TOTAL » des panels OSD (évite concaténation de chiffres)."""
    totals: list[int] = []
    for p in panels:
        blob = " ".join(p.get("lines") or [])
        found = False
        # Pattern pagination Discover (« 1–50 of 257638 ») — prioritaire
        for m in re.finditer(r"1[–\-]\d+\s+of\s+([\d][\d,]*\d|\d+)\b", blob, re.I):
            v = normalize_number(m.group(1))
            if v is not None and v > 0:
                totals.append(v)
                found = True
        if found:
            continue
        for m in re.finditer(r"of\s+([\d][\d,]*\d|\d+)\b", blob, re.I):
            v = normalize_number(m.group(1))
            if v is not None and v > 0:
                totals.append(v)
    return totals


def map_grafana_stat_labels(target_id: str, by_label: dict[str, str], metrics: dict[str, dict[str, Any]], setm) -> None:
    """Mappe les stats Grafana par titre de panel (health.value affiché)."""
    hints: list[tuple[str, str, str]] = []
    if target_id == "grafana.timesketch_metrics":
        hints = [
            (r"^sketches?$", "total_assets", "sketch_count"),
            (r"^timelines?$", "total_incidents", "timeline_count"),
            (r"events explore", "total_events", "explore_events"),
            (r"events timeline \(all-time\)|events timeline", "total_timeline_events", "timeline_events"),
            (r"events timeline \(24h\)", "total_timeline_events_24h", "timeline_events_24h"),
            (r"events timesketch", "total_events", "timeline_events"),
            (r"analyzer run", "total_analyzers_results", "analyzer_runs"),
            (r"analyzer fail", "total_anomalies", "analyzer_failures"),
        ]
    elif target_id == "grafana.platform_health":
        hints = [
            (r"events 24h \(siem", "total_events_siem", "events_24h_siem"),
            (r"events 24h \((plateforme|opensearch)\)", "total_events", "events_24h"),
            (r"events 24h", "total_events", "events_24h"),
            (r"statut global", "total_events", "global_status"),
            (r"composants ok", "total_alerts", "components_ok"),
        ]
    elif target_id == "grafana.opensearch_metrics":
        hints = [
            (r"events 24h \(siem", "total_events_siem", "events_24h_siem"),
            (r"events 24h \((plateforme|opensearch)\)", "total_events", "events_24h"),
            (r"events 24h", "total_events", "events_24h"),
            (r"index forensic", "total_assets", "index_count"),
            (r"latence", "total_anomalies", "latency_ms"),
        ]
    for lab, raw in by_label.items():
        ll = lab.lower()
        for pat, mkey, _src in hints:
            if re.search(pat, ll):
                setm(mkey, raw, f"dom:grafana_stat:{lab[:48]}")
                break


def map_dom_to_metrics(target_id: str, dom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Heuristiques label → métrique canonique (pessimiste : une seule valeur dominante par défaut)."""
    metrics: dict[str, dict[str, Any]] = {}
    by_label: dict[str, str] = dom.get("byLabel") or dom.get("byId") or {}
    panels = dom.get("panels") if isinstance(dom.get("panels"), list) else []
    tokens = dom.get("numericTokens") if isinstance(dom.get("numericTokens"), list) else []

    def setm(key: str, raw: Any, source: str) -> None:
        n = normalize_number(raw)
        if n is None and raw is not None and str(raw).strip():
            metrics[key] = {"raw": str(raw), "normalized": None, "source": source, "missing": True}
        elif n is not None:
            metrics[key] = {"raw": str(raw), "normalized": n, "source": source, "missing": False}

    # Portail home IDs
    if target_id == "portal.cert_home":
        for k in ("uploads_cert", "uploads_it", "tokens_active", "events_windows", "events_linux_macos", "events_web", "events_network", "events_cloud", "events_endpoint"):
            setm(k, (dom.get("byId") or {}).get(k), f"dom:#{k}")
        return metrics

    if target_id in ("portal.cert_dashboard", "portal.it_dashboard"):
        bl = dom.get("byLabel") or {}
        for lab, raw in bl.items():
            ll = lab.lower()
            if "incident" in ll:
                setm("total_incidents", raw, "dom:portal_zone")
            if "upload" in ll:
                setm("total_uploads", raw, "dom:portal_zone")
            if "asset" in ll:
                setm("total_assets", raw, "dom:portal_zone")
            if "ticket" in ll:
                setm("total_incidents", raw, "dom:portal_zone")
        nums = dom.get("nums") or []
        if nums and "total_incidents" not in metrics:
            setm("total_incidents", nums[0], "dom:portal_zone:first_num")
        return metrics

    # Label keyword mapping (FR/EN)
    label_map = [
        (r"event|événement|volume|count|total", "total_events"),
        (r"alert|alerte", "total_alerts"),
        (r"ioc|indicator", "total_ioc"),
        (r"anomal", "total_anomalies"),
        (r"incident", "total_incidents"),
        (r"asset", "total_assets"),
        (r"cti|threat|menace", "total_cti_entities"),
        (r"sigma", "total_sigma_hits"),
        (r"analyzer|analyseur", "total_analyzers_results"),
        (r"purple", "total_purple_team_events"),
        (r"commander", "total_incident_commander_events"),
        (r"sketch", "total_events"),
        (r"timeline", "total_events"),
        (r"upload", "total_uploads"),
        (r"malware", "total_cti_entities"),
        (r"campaign|campagn", "total_cti_entities"),
        (r"intrusion", "total_cti_entities"),
    ]

    if target_id == "osd.platform_health":
        for label, raw in by_label.items():
            ll = label.lower()
            if re.search(r"total ioc|ioc uniques|ioc opencti|total iocs", ll):
                setm("total_ioc", raw, f"dom:label:{label[:40]}")
            if re.search(r"indicators opencti", ll) and "total_ioc" not in metrics:
                setm("total_ioc", raw, f"dom:label:{label[:40]}")
            if re.search(r"events 24h \(siem", ll):
                setm("total_events_siem", raw, f"dom:label:{label[:40]}")
            if re.search(r"events 24h", ll) and "total_events" not in metrics:
                setm("total_events", raw, f"dom:label:{label[:40]}")
            if re.search(r"events explore", ll):
                setm("total_events", raw, f"dom:label:{label[:40]}")
            if re.search(r"sigma.*hit|hits sigma", ll):
                setm("total_sigma_hits", raw, f"dom:label:{label[:40]}")
            if re.search(r"malware|campagn|intrusion", ll):
                setm("total_cti_entities", raw, f"dom:label:{label[:40]}")
        return metrics

    if target_id == "osd.security_events":
        for label, raw in by_label.items():
            ll = label.lower()
            if re.search(r"total events \(24h\)", ll):
                setm("total_events_24h_siem", raw, f"dom:label:{label[:40]}")
        for p in panels:
            blob = " ".join(p.get("lines") or [])
            if re.search(r"discover\s*\(events\)", blob, re.I):
                for m in re.finditer(r"1[–\-]\d+\s+of\s+([\d][\d,]*\d|\d+)\b", blob, re.I):
                    setm("total_events", m.group(1), "dom:discover_events_of_total")
                    break
                if "total_events" in metrics:
                    break
        ofs = extract_of_totals(panels)
        if ofs and "total_events" not in metrics:
            setm("total_events", max(ofs), "dom:panel_of_total_max")
        for label, raw in by_label.items():
            ll = label.lower()
            if re.search(r"pivot alert|forensic-alerts", ll):
                for pat in (r"of\s+([\d][\d\s,\.]*\d|\d+)",):
                    m = re.search(pat, f"{label} {raw}", re.I)
                    if m:
                        setm("total_alerts", m.group(1), f"dom:label:{label[:40]}")
                        break
        # Ne pas laisser label_map écraser total_events (panels TI match « 7 of 7 » etc.)
        skip_label_events = True
    else:
        skip_label_events = False

    # Grafana : titres de panels stat uniquement (pas tokens globaux « 1m » / navigation)
    if target_id.startswith("grafana."):
        map_grafana_stat_labels(target_id, by_label, metrics, setm)
    else:
        for label, raw in by_label.items():
            ll = label.lower()
            if target_id == "osd.ti_overview":
                if re.search(r"total\s*ioc|ioc\s*opencti|opencti.*uniques", ll):
                    setm("total_ioc", raw, f"dom:label:{label[:40]}")
                    continue
                if re.search(r"misp ioc|opencti ioc", ll):
                    continue
                if re.search(r"opencti docs \(index|opencti docs.*canonique", ll):
                    setm("total_cti_entities", raw, f"dom:label:{label[:40]}")
                    continue
                if re.search(r"misp docs|misp.*doc", ll):
                    continue
            if target_id == "osd.purple_team":
                if re.search(r"replay logs|replay ioc", ll):
                    continue
                if re.search(r"s[1-4] —|tests |scénarios|règles |coverage |gaps ", ll):
                    m = re.search(r"of\s+([\d][\d,\.\s]*\d|\d+)", f"{label} {raw}", re.I)
                    if m:
                        setm("total_purple_team_events", m.group(1), f"dom:label:{label[:40]}")
                    continue
            if target_id.startswith("osd.") and target_id != "osd.platform_health":
                if re.search(r"purple", ll):
                    setm("total_purple_team_events", raw, f"dom:label:{label[:40]}")
                    continue
            for pat, mkey in label_map:
                if skip_label_events and mkey == "total_events":
                    continue
                if re.search(pat, ll):
                    setm(mkey, raw, f"dom:label:{label[:40]}")
                    break

    # OSD : totaux « of N » des tableaux (plus fiable que max token)
    if target_id.startswith("osd."):
        ofs = extract_of_totals(panels)
        if ofs:
            best = max(ofs)
            if target_id == "osd.security_events":
                setm("total_events", best, "dom:panel_of_total_max")
            elif target_id == "osd.ti_overview" and "total_ioc" not in metrics:
                setm("total_ioc", min(ofs), "dom:panel_of_total_min")
            elif target_id in ("osd.platform_health", "osd.incident_commander"):
                if "total_events" not in metrics:
                    setm("total_events", best, "dom:panel_of_total")
            elif target_id == "osd.purple_team":
                _purple_exclude = re.compile(
                    r"replay logs|replay ioc|🔗|analyst|soc mgr|ti lead|th lead|global soc|crisis|soc auto|purple team — hub|side panel",
                    re.I,
                )
                purple_totals: list[int] = []
                for p in panels:
                    blob = " ".join(p.get("lines") or [])
                    if _purple_exclude.search(blob):
                        continue
                    for m in re.finditer(r"1[–\-]\d+\s+of\s+([\d][\d,]*\d|\d+)", blob, re.I):
                        v = normalize_number(m.group(1))
                        if v is not None and v > 0:
                            purple_totals.append(v)
                            break
                if purple_totals:
                    setm("total_purple_team_events", sum(purple_totals), "dom:purple_panels_sum")
                else:
                    # Aucune activité purple-team détectée hors panels "side" (replay
                    # logs/ioc, hubs, dashboards SOC). On comptabilise les scénarios
                    # spécifiques S1–S4 NON exclus : si TOUS sont en "no results
                    # found", la métrique vaut explicitement 0 (réalité métier).
                    specific_total = 0
                    specific_empty = 0
                    for p in panels:
                        blob = " ".join(p.get("lines") or [])
                        bl = blob.lower()
                        if not re.search(r"\bs[1-4]\s*[—\-]", bl):
                            continue
                        if _purple_exclude.search(blob):
                            continue
                        specific_total += 1
                        if "no results found" in bl:
                            specific_empty += 1
                    if specific_total and specific_empty >= specific_total:
                        setm(
                            "total_purple_team_events",
                            0,
                            "dom:purple_specific_scenarios_no_results",
                        )
                if "total_events" not in metrics and ofs:
                    setm("total_events", best, "dom:panel_of_total")
        if target_id == "osd.ti_overview":
            for p in panels:
                blob = " ".join(p.get("lines") or [])
                if re.search(r"total iocs.*opencti.*uniques|ioc opencti.*uniques", blob, re.I):
                    nums = [normalize_number(n) for n in (p.get("nums") or [])]
                    nums = [n for n in nums if n is not None and n > 0]
                    if nums:
                        setm("total_ioc", max(nums), "dom:ti_opencti_viz")
                        break
            for p in panels:
                blob = " ".join(p.get("lines") or [])
                if re.search(r"opencti docs.*canonique|opencti docs \(index", blob, re.I):
                    nums = [normalize_number(n) for n in (p.get("nums") or [])]
                    nums = [n for n in nums if n is not None and n > 100]
                    if nums:
                        setm("total_cti_entities", max(nums), "dom:ti_opencti_docs")
                        break

    # Plus grand nombre visible → total_events si absent (hors Grafana)
    all_nums = []
    for p in panels:
        for n in p.get("nums") or []:
            v = normalize_number(n)
            if v is not None:
                all_nums.append(v)
    for t in tokens:
        v = normalize_number(t)
        if v is not None:
            all_nums.append(v)

    def sane_event_count(values: list[int], ceiling: int = 50_000_000) -> int | None:
        if not values:
            return None
        sorted_v = sorted(values, reverse=True)
        for v in sorted_v:
            if v <= ceiling:
                return v
        return sorted_v[-1] if sorted_v[-1] <= ceiling * 2 else None

    if all_nums and not target_id.startswith("grafana."):
        dominant = sane_event_count(all_nums)
        if dominant is not None and "total_events" not in metrics:
            setm("total_events", dominant, "dom:max_sane_token")
        if target_id.startswith("osd.") and "total_alerts" not in metrics:
            small = [x for x in all_nums if x <= 10_000]
            if small:
                setm("total_alerts", min(small), "dom:min_token")

    if target_id == "ts.intelligence" and "total_analyzers_results" not in metrics:
        rows = dom.get("tableRows") or 0
        if isinstance(rows, int) and rows > 1:
            setm("total_analyzers_results", rows - 1, "dom:table_rows")

    if target_id == "ts.overview":
        nums = dom.get("numericTokens") if isinstance(dom.get("numericTokens"), list) else []
        if nums and "total_events" not in metrics:
            parsed = [normalize_number(x) for x in nums]
            parsed = [x for x in parsed if x is not None and x <= 10_000_000]
            if parsed:
                setm("total_events", max(parsed), "dom:overview_tokens")
        card_like = dom.get("cardLike")
        if isinstance(card_like, int) and card_like > 0 and "total_analyzers_results" not in metrics:
            setm("total_analyzers_results", card_like, "dom:card_like")

    if target_id == "ts.stories":
        links = dom.get("storyLinks")
        if isinstance(links, int) and links > 0:
            setm("total_events", links, "dom:story_links")

    return metrics


def load_panels_expected() -> dict[str, Any]:
    if not PANELS_PATH.is_file():
        raise FileNotFoundError(f"Missing {PANELS_PATH}")
    text = PANELS_PATH.read_text(encoding="utf-8")
    if yaml:
        return yaml.safe_load(text) or {}
    return json.loads(text)


def normalize_metric_path(path: str) -> str:
    return METRIC_PATH_ALIASES.get(path, path)


ERROR_PHRASES_DEFAULT = (
    "error",
    "server error",
    "could not locate field",
    "request failed",
    "internal error",
    "panel error",
    "no data found",
    "something went wrong",
)


def evaluate_panel_dom(target_id: str, dom: dict[str, Any], rules: dict[str, Any], global_meta: dict[str, Any]) -> dict[str, Any]:
    """Évalue panels / page blanche — pessimiste."""
    min_nodes = int(rules.get("min_dom_nodes", global_meta.get("min_dom_nodes", 200)))
    min_text = int(rules.get("min_body_text", global_meta.get("min_body_text", 300)))
    forbid = [p.lower() for p in (rules.get("forbid_phrases") or global_meta.get("forbid_phrases") or ERROR_PHRASES_DEFAULT)]

    text_len = int(dom.get("textLen") or 0)
    node_count = int(dom.get("nodeCount") or 0)
    panel_count = int(dom.get("panelCount") or dom.get("panels") or 0)
    if isinstance(dom.get("panels"), list):
        panel_count = len(dom["panels"])
    panels_with_content = int(
        dom.get("panelsWithContent") or dom.get("panels_with_content") or dom.get("panelsWithNumbers") or 0
    )
    visible_panels = int(dom.get("visiblePanels") or panel_count)
    body_text = (dom.get("bodySample") or "").lower()
    has_error = bool(dom.get("hasError") or dom.get("hasErrorPhrase"))
    issues: list[str] = []

    if node_count > 0 and node_count < min_nodes:
        issues.append(f"DOM trop petit ({node_count} nœuds < {min_nodes})")
    if text_len < min_text:
        issues.append(f"texte insuffisant ({text_len} < {min_text})")
    if has_error:
        issues.append("message d'erreur UI détecté")
    for phrase in forbid:
        if phrase in body_text and len(body_text) < 8000:
            issues.append(f"phrase interdite: `{phrase}`")
            break

    min_panels = int(rules.get("min_panels", 0))
    min_pc = int(rules.get("min_panel_with_content", rules.get("min_panels_with_content", 0)))
    if min_panels and panel_count < min_panels:
        issues.append(f"panels={panel_count} < min {min_panels}")
    if min_pc and panels_with_content < min_pc:
        issues.append(f"panels avec contenu={panels_with_content} < min {min_pc}")
    if min_panels and visible_panels < 1 and panel_count < 1:
        issues.append("aucun panel visible")

    min_cards = int(rules.get("min_cards", 0))
    if min_cards and int(dom.get("cardLike") or 0) < min_cards:
        issues.append(f"cartes={dom.get('cardLike', 0)} < min {min_cards}")

    min_agg = int(rules.get("min_aggregations", 0))
    if min_agg and int(dom.get("vizCount") or 0) < min_agg:
        issues.append(f"agrégations/viz={dom.get('vizCount', 0)} < min {min_agg}")

    min_stories = int(rules.get("min_stories", rules.get("min_story_links", 0)))
    if min_stories and int(dom.get("storyLinks") or 0) < min_stories and int(dom.get("storyMentions") or 0) < min_stories:
        issues.append(f"stories insuffisantes (links={dom.get('storyLinks', 0)})")

    min_incidents = int(rules.get("min_incidents", 0))
    if min_incidents:
        inc = dom.get("incidentCount")
        if inc is None:
            nums = dom.get("nums") or []
            inc = normalize_number(nums[0]) if nums else None
        if inc is None or int(inc) < min_incidents:
            issues.append(f"incidents={inc} < min {min_incidents}")

    min_assets = int(rules.get("min_assets", 0))
    if min_assets:
        assets = dom.get("assetCount")
        if assets is None:
            bl = dom.get("byLabel") or {}
            for lab, raw in bl.items():
                if "asset" in lab.lower():
                    assets = normalize_number(raw)
                    break
        if assets is None or int(assets) < min_assets:
            issues.append(f"assets={assets} < min {min_assets}")

    ok = len(issues) == 0
    return {
        "target_id": target_id,
        "ok": ok,
        "issues": issues,
        "dom": {
            "nodeCount": node_count,
            "textLen": text_len,
            "panelCount": panel_count,
            "panelsWithContent": panels_with_content,
            "visiblePanels": visible_panels,
            "hasError": has_error,
        },
    }


def load_relations() -> dict[str, Any]:
    if not RELATIONS_PATH.is_file():
        raise FileNotFoundError(f"Missing {RELATIONS_PATH}")
    text = RELATIONS_PATH.read_text(encoding="utf-8")
    if yaml:
        return yaml.safe_load(text) or {}
    return json.loads(text)


def load_metrics_store(path: Path | None = None) -> dict[str, Any]:
    p = path or METRICS_JSON
    if not p.is_file():
        return {"meta": {}, "targets": {}}
    return json.loads(p.read_text(encoding="utf-8"))


def save_metrics_store(data: dict[str, Any], path: Path | None = None) -> Path:
    p = path or METRICS_JSON
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return p


def resolve_metric_path(store: dict[str, Any], path: str) -> tuple[int | None, str]:
    path = normalize_metric_path(path)
    if path.startswith("literal:"):
        v = normalize_number(path.split(":", 1)[1])
        return v, "literal"
    parts = path.split(".")
    if len(parts) < 2:
        return None, f"path invalide: {path}"
    target_id = ".".join(parts[:-1])
    metric_key = parts[-1]
    tgt = (store.get("targets") or {}).get(target_id)
    if not tgt:
        return None, f"cible absente: {target_id}"
    if not tgt.get("extract_ok"):
        return None, f"extraction KO: {target_id}"
    m = (tgt.get("metrics") or {}).get(metric_key)
    if not m:
        return None, f"métrique absente: {path}"
    if m.get("missing") or m.get("normalized") is None:
        return None, f"métrique non normalisée: {path}"
    return int(m["normalized"]), "ok"


def eval_rule(store: dict[str, Any], rule: dict[str, Any], default_tol: float) -> dict[str, Any]:
    rid = rule.get("id", "?")
    left_path = rule.get("left", "")
    right_path = rule.get("right", "")
    op = rule.get("op", "==")
    tol = float(rule.get("tolerance_pct", default_tol))
    tol_abs = rule.get("tolerance_abs")
    opt_l = rule.get("optional_left", False)
    opt_r = rule.get("optional_right", False)
    when_left_gt = rule.get("when_left_gt")
    when_right_gt = rule.get("when_right_gt")

    lv, lreason = resolve_metric_path(store, left_path)
    rv, rreason = resolve_metric_path(store, right_path)

    result: dict[str, Any] = {
        "id": rid,
        "description": rule.get("description", ""),
        "left": left_path,
        "right": right_path,
        "op": op,
        "left_value": lv,
        "right_value": rv,
        "left_reason": lreason,
        "right_reason": rreason,
        "passed": False,
        "skipped": False,
    }

    if lreason != "ok" and lreason != "literal":
        if opt_l:
            result["skipped"] = True
            result["passed"] = True
            result["detail"] = f"left optionnel absent: {lreason}"
            return result
        result["detail"] = f"FAIL left: {lreason}"
        return result

    if rreason != "ok" and not right_path.startswith("literal:"):
        if opt_r:
            result["skipped"] = True
            result["passed"] = True
            result["detail"] = f"right optionnel absent: {rreason}"
            return result
        result["detail"] = f"FAIL right: {rreason}"
        return result

    if when_left_gt is not None and (lv is None or lv <= when_left_gt):
        result["skipped"] = True
        result["passed"] = True
        result["detail"] = "skipped (when_left_gt)"
        return result

    if when_right_gt is not None and (rv is None or rv <= when_right_gt):
        result["skipped"] = True
        result["passed"] = True
        result["detail"] = "skipped (when_right_gt)"
        return result

    if lv is None or rv is None:
        result["detail"] = "FAIL valeur manquante"
        return result

    abs_slack = int(tol_abs) if tol_abs is not None else 0
    if op == "==":
        ok = abs(lv - rv) <= abs_slack
    elif op == "!=":
        ok = lv != rv
    elif op == ">":
        ok = lv > (rv - abs_slack)
    elif op == ">=":
        ok = lv >= (rv - abs_slack)
    elif op == "<":
        ok = lv < (rv + abs_slack)
    elif op == "<=":
        ok = lv <= (rv + abs_slack)
    elif op == "approx":
        if rv == 0:
            ok = lv == 0 or abs(lv) <= abs_slack
        else:
            ok = abs(lv - rv) <= max(1, int(rv * tol / 100.0), abs_slack)
    else:
        result["detail"] = f"op inconnue: {op}"
        return result

    result["passed"] = ok
    result["detail"] = "OK" if ok else f"FAIL {lv} {op} {rv} (tol {tol}%)"
    return result


def check_required_metrics(store: dict[str, Any], relations: dict[str, Any]) -> list[dict[str, Any]]:
    failures = []
    required = relations.get("required_metrics") or {}
    for target_id, keys in required.items():
        tgt = (store.get("targets") or {}).get(target_id)
        if not tgt:
            failures.append({"target": target_id, "reason": "cible non extraite"})
            continue
        if not tgt.get("extract_ok"):
            failures.append({"target": target_id, "reason": "extraction DOM échouée"})
            continue
        if not tgt.get("screenshot"):
            failures.append({"target": target_id, "reason": "screenshot manquant"})
        for key in keys:
            m = (tgt.get("metrics") or {}).get(key)
            if not m or m.get("normalized") is None:
                failures.append({"target": target_id, "metric": key, "reason": "métrique requise absente"})
    return failures
