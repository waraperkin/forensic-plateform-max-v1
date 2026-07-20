# Full Platform Manual — Forensic Minimal v2

**Platform version:** 2.1  
**Repository:** https://github.com/waraperkin/forensic-minimal-v2  
**Audience:** SOC, DFIR, CERT, engineering

This manual summarises the architecture, the flows and the behaviour of each service. For step-by-step procedures, see the dedicated guides (`deployment-guide.md`, `analyst-guide.md`, etc.).

---

## 1. Complete architecture

### 1.1 Logical view

```
                     ┌─────────────────────────────┐
                     │     Analyst / IT clients     │
                     └──────────────┬──────────────┘
                                    │ HTTPS :443
                     ┌──────────────▼──────────────┐
                     │     forensic-nginx (TLS)     │
                     └──────────────┬──────────────┘
           ┌────────────┬───────────┼───────────┬────────────┐
           ▼            ▼           ▼           ▼            ▼
     CERT Portal   IT Portal   /dashboards  /grafana    /misp /cti
           │            │       /timesketch /thehive   /velociraptor
           │            │       /helk/kibana /cortex   /minio /docs
           └─────┬──────┘
                 ▼
        forensic-net (Docker bridge)
                 │
     ┌───────────┼──────────────────────────────────────┐
     ▼           ▼            ▼             ▼           ▼
 OpenSearch   MinIO      Timesketch     OpenCTI      TheHive
 Logstash     Redis      Postgres       Connectors   Cortex
 Filebeat     RabbitMQ   MISP+MySQL     Cassandra    Grafana
 Ingest-worker           Velociraptor   HELK sidecar Prometheus/Loki/Tempo
```

### 1.2 Layers

| Layer | Role |
|-------|------|
| **Edge** | Nginx TLS, sub-path routing |
| **Portals** | CERT/IT UX, auth, upload, 16/16 health |
| **Ingest** | Logstash, Filebeat, ingest-worker, HELK HTTP |
| **Data** | OpenSearch, MinIO, Postgres, Cassandra, Redis, RabbitMQ |
| **Analysis** | Timesketch, TheHive, Cortex, Velociraptor |
| **CTI** | OpenCTI + connectors, MISP |
| **Obs** | Grafana, Prometheus, Loki, Tempo |

---

## 2. Flow diagrams

### 2.1 DFIR flow

```
Endpoint / disk image
    → Velociraptor collect / CERT upload
    → MinIO (raw)
    → parsers / Logstash
    → OpenSearch (forensic-*)
    → Timesketch (timeline)
    → TheHive case + report
```

### 2.2 SOC flow

```
Beats / Syslog / Upload
    → Logstash pipelines
    → OpenSearch
    → Alerting / Dashboards / HELK Sigma
    → Portal triage
    → TheHive + Cortex
```

### 2.3 CTI flow

```
External feeds → OpenCTI connectors
              ↘ MISP events/attrs
    → sync scripts → forensic-ti-opencti-* / forensic-ti-misp-*
    → IOC / match dashboards
    → hunting pivots
```

### 2.4 Ingestion flow

```
CERT upload ──┐
IT token ─────┼→ cert-portal / ingest-worker → MinIO
API upload ───┘         ↓
                 Logstash / HELK
                        ↓
                 OpenSearch + Timesketch queue
```

### 2.5 Export flow

```
MISP JSON/STIX export → third-party sharing / OpenCTI
OpenCTI STIX → files / export connectors
Timesketch → stories / CSV
MinIO → mc mirror / evidence ZIP
VR → artifact ZIP
Portal → forensic reports
```

### 2.6 Typical investigation flow

See `analyst-guide.md` §8 and `docs/PORTAL/PIVOTS.md`.

---

## 3. Services — reference

### 3.1 Nginx

- Container `forensic-nginx`.
- Config: `config/nginx/conf.d/forensic.conf` + snippets.
- Health: `/nginx-health`.

### 3.2 CERT Portal

- Node/Express, session auth, overview, upload, CTI panel, VR/HELK modules.
- Aggregated health across **16 services**.
- Docs served under `/docs/`.

### 3.3 IT Portal

- Evidence drop through TTL **tokens**.
- Health `/it/api/health`.

### 3.4 OpenSearch + Dashboards

- 2-node lab cluster, `forensic-*` indices, TI, ISM.
- UI `/dashboards/` — SOC playbooks imported during full-start.

### 3.5 Logstash / Filebeat

- Multi-pipeline ingest (beats, syslog, HEC, HTTP).
- Filebeat → OS.

### 3.6 MinIO

- Object storage for evidence / raw logs.
- Console through the `/minio/` proxy or port 9001.

### 3.7 Timesketch

- Sketches, Sigma/MISP analyzers, import worker.
- External URL patched with `PUBLIC_HOST`.

### 3.8 MISP

- Event-based CTI, galaxies, warninglists.
- `/misp` proxy (prefix preserved).
- 40-char hex API key required.

### 3.9 OpenCTI

- CTI graph + connectors (URLhaus, MITRE, CVE…).
- UI `/cti/`, GraphQL `/cti/graphql`.

### 3.10 TheHive

- IR cases v5, org `cert`, FP-Master templates.
- Base path `/thehive`.

### 3.11 Cortex

- Analyzers / responders; CSRF + API key.
- TheHive integration.

### 3.12 Velociraptor

- Server 0.76.x, custom ForensicMinimal artifacts.
- GUI through the nginx plain-HTTP upstream.
- Health bridge sidecar.

### 3.13 HELK

- ES/Kibana/Logstash hunting sidecar.
- Kibana basePath `/helk/kibana`.
- `helk-*` index patterns.

### 3.14 Observability

- Grafana OS/TS datasources; Prometheus scraping; Loki/Tempo.

### 3.15 Infra

- Postgres, Redis, RabbitMQ, Cassandra — application dependencies.

---

## 4. Orchestration

Single script: `./forensic.sh`

| Command | Role |
|---------|------|
| `-full-start` | Bootstrap → build → start → masters → tests |
| `start` / `stop` / `status` | Lifecycle |
| `update-portals` | Portal rebuild |
| `repair-vr` | VR 502 |
| `*-master-setup/verify` | Tool packs |

Libraries: `scripts/lib/installer.sh`, `platform-host.sh`, `host-ip.sh`.

---

## 5. Lab vs production security

| Topic | Lab | Production |
|-------|-----|------------|
| TLS | Self-signed | PKI |
| Secrets | Generated in `.env` | Vault + rotation |
| Ports | Many exposed | Least exposure |
| Auth | Shared passwords | MFA / SSO |

Details: `hardening-plan.md`.

---

## 6. Operations & maintenance

- Daily: `operations-guide.md`
- Backups / updates: `maintenance-guide.md`
- Monitoring: `monitoring-plan.md`
- QA: `qa-continuous.md`

---

## 7. Technical annexes

### 7.1 Critical environment variables

`PUBLIC_HOST`, `PORTAL_ADMIN_*`, `MISP_ADMIN_*`, `OPENCTI_ADMIN_*`, `TIMESKETCH_*`, `GRAFANA_ADMIN_PASSWORD`, `MINIO_ROOT_*`, `VELOCIRAPTOR_ADMIN_*`, `THEHIVE_*`, `CORTEX_*`, `CERT_PORTAL_SECRET`, `IT_PORTAL_SECRET`.

### 7.2 Scripts of truth

| Script | Usage |
|--------|-------|
| `verify-platform-ready.sh` | HTTPS health gate |
| `portal_auth_ui_verify.py` | Portal auth |
| `helk-kibana-import.mjs` | HELK patterns |
| `misp-reset-admin.sh` | MISP admin |
| `post-start-align.sh` | IP/proxy alignment |
| `preflight-full-start.sh` | Pre-deployment gate |

### 7.3 Shadow Ops evidence

- `docs/SHADOW_OPS_REPORT.md`
- `docs/SHADOW_OPS_MATRIX.json`
- `docs/en/delivery-message.md`

### 7.4 Screenshots

Gallery: `docs/PORTAL/SCREENS.md` · images `docs/images/`.

### 7.5 Internal links

| Doc | Topic |
|-----|-------|
| `INSTALLATION.md` | Historical install |
| `LAB-ENDPOINTS.md` | Lab endpoints |
| `HELK-FULL-CONFIG.md` | HELK |
| `VELOCIRAPTOR-*.md` | VR |
| `PORTAL/*` | Portal modules |

---

## 8. Conclusion

Forensic Minimal v2 provides an **integrated SOC/DFIR platform**: one reverse proxy, two portals, a SIEM, a CTI stack, an IR system, a timeline and endpoint collection, orchestrated by a single script and validated by a battery of verifies.

To get started: `deployment-guide.md` → `operations-guide.md` → `analyst-guide.md`.
