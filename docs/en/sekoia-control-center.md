# Sekoia Control Center (v2.3)

The **Sekoia Control Center** is the full management plane for your Sekoia.io SIEM: editable inventories, real-time ingestion monitoring, event search, CTI federation, advanced analytics, a SOL workspace and SOAR incident management — far beyond the standard Sekoia console capabilities.

## The 22 tabs

| Tab | Purpose |
|---|---|
| Overview | Intake / rule / connector / format counters, charts, global health |
| Inventory | Intakes: create, edit, rename, delete, search, filtering, bulk actions |
| Rules | Detection rules: full CRUD, pattern / SIGMA payload, 0-100 severity, bulk enable / disable |
| Playbooks | Sekoia playbooks: CRUD, triggers, status |
| Connectors | Connectors: inventory, renaming, configuration |
| Modules | Sekoia modules and their configurations |
| Formats | Referenced log formats (parsers), taxonomy |
| Ingestion alerts | Volume drop, silent intake, missing hostname, parsing anomalies — with acknowledgement |
| Events | Real-time Lucene search (async job, tunable range and limit) |
| IOC / CTI | Federated lookup OpenCTI + MISP + OpenSearch; one-click TheHive case and Cortex analysis |
| Coverage | Formats × rules matrix: active intakes with no detection rule (GAP) |
| Volumetry | Events per intake / source / hostname, top hostnames, last event seen |
| Log tester | Automatic log format detection with Sekoia format suggestions |
| Intake health (v2.2) | 0-100 score per intake, A-D grade, freshness SLO, volume forecast |
| Anomalies (v2.2) | Z-score on 7-day baselines, drops/spikes, silent intakes, new/disappeared hosts |
| Hosts (v2.2) | New hosts, disappeared hosts, multi-intake hosts, top talkers |
| Rule effectiveness (v2.2) | Noisy/silent rules, top-5 concentration, MITRE ATT&CK coverage |
| Watchlists (v2.2) | Watch hosts / IOCs / users in telemetry, 24 h hits |
| Snapshots (v2.2) | Config capture, diff vs current state, dry-run restore |
| SOC digest (v2.2) | Daily summary: global score, volumes, alerts, anomalies, top talkers |
| SOL (v2.3) | SOL editor (Sekoia Operating Language): instant local validation, API execution, query library, commented official examples |
| Incidents (v2.3) | SOAR: incident CRUD, timeline/notes/evidence/IOCs, IOC scan on ingested logs, Markdown report, full end-of-investigation purge |
| Audit | Journal of every change made from the portal |

## SOL workspace (v2.3)

The **SOL** language (Sekoia Operating Language, KQL-inspired pipe syntax) is built into the platform:

- **Local validation** before any call: tables (`events`, `alerts`, `cases`, `intakes`, `event_telemetry`, `asset_accounts`), operators (`where`, `aggregate`, `limit`, `order`, `select`, `lookup`, `let`…), pipe and quote balancing — instant feedback without consuming the Sekoia API quota (10 queries/min, 10,000 rows max).
- **Execution** through the Sekoia API (configurable endpoint `SEKOIA_SOL_API_PATH`).
- **Reusable query library** (save, tags, one-click insert) and **8 commented official examples** (hunting, supervision, SOC).

## Incidents tab — SOAR (v2.3)

Full forensic incident management, from ingestion to purge:

1. **Creation**: `INC-YYYYMMDD-XXXXXX` incident with severity, assignee, description; the `case_id` is the incident identifier.
2. **Ingestion**: analysts upload their logs (any format: application, network, OS — EVTX, syslog, CSV, JSON, PCAP…) via the Upload tab with this `case_id`; the MinIO → ingest-worker → OpenSearch + Timesketch pipeline parses and indexes every field.
3. **Investigation**: timestamped timeline, notes, evidence, IOCs (automatic ip/hash/domain/URL typing); existing cases can be linked to the incident.
4. **IOC scan**: matching of incident IOCs **and Sekoia watchlists** against the case logs — matches with samples, persisted as evidence; parsing statistics (documents per index, top `source.ip`, log levels).
5. **Report**: generated Markdown (summary, timeline, evidence, matched IOCs, ingested files, closure checklist), one-click copy.
6. **Full purge**: at the end of the investigation, deletion of all incident data — OpenSearch logs, MinIO objects, upload metadata, Timesketch sketch. **Mandatory dry-run** then double confirmation; every purge is audited. HELK remains a manual purge (separate stack).

## Ingestion monitoring

Local telemetry in OpenSearch (`forensic-sekoia-telemetry-*`): volumetry per intake / source / `log.hostname`, top hostnames, automatic alerts (volume drop, silent intake, missing hostname, parsing anomaly), fingerprint-based acknowledgement, Grafana *Sekoia Ingestion* dashboard.

## CTI federation and pivots

- **Federated search**: an IOC is queried simultaneously against OpenCTI, MISP and local indices; the "Known" badge lists the sources.
- **TheHive case**: one-click case creation pre-filled with the IOC and its context (manual or automatic on critical alerts).
- **Cortex analysis**: launch available analyzers on the observable.

## Internal API

All actions go through `/api/sekoia/*` (see `docs/SEKOIA.md`): intake / rule / playbook CRUD, bulk enable / disable, `events/search`, `local/timeseries`, `local/top-hostnames`, `cti/ioc`, `cti/ioc/thehive-case`, `cti/ioc/cortex`, `logformat/detect`, `coverage`.

## Prerequisites

- `SEKOIA_API_KEY` (read + write) in `.env`;
- Optional CTI connectors: `OPENCTI_TOKEN`, `MISP_KEY`, `THEHIVE_API_KEY`, `CORTEX_API_KEY`;
- Validation: `./scripts/validate-sekoia.sh`.
