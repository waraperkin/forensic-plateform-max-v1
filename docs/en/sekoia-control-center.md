# Sekoia Control Center (v2.1)

The **Sekoia Control Center** is the full management plane for your Sekoia.io SIEM: editable inventories, real-time ingestion monitoring, event search, CTI federation and CERT automation — far beyond the standard Sekoia console capabilities.

## The 13 tabs

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
| Audit | Journal of every change made from the portal |

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
