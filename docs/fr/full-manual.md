# Manuel complet — Forensic Minimal v2

**Version plateforme :** 2.1  
**Dépôt :** https://github.com/waraperkin/forensic-minimal-v2  
**Public :** SOC, DFIR, CERT, ingénierie

Ce manuel synthétise l’architecture, les flux et le fonctionnement de chaque service. Pour les procédures pas-à-pas, voir les guides dédiés (`deployment-guide.md`, `analyst-guide.md`, etc.).

---

## 1. Architecture complète

### 1.1 Vue logique

```
                     ┌─────────────────────────────┐
                     │     Clients analystes / IT   │
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

### 1.2 Couches

| Couche | Rôle |
|--------|------|
| **Edge** | Nginx TLS, routage sous-chemins |
| **Portails** | UX CERT/IT, auth, upload, health 16/16 |
| **Ingest** | Logstash, Filebeat, ingest-worker, HELK HTTP |
| **Data** | OpenSearch, MinIO, Postgres, Cassandra, Redis, RabbitMQ |
| **Analyse** | Timesketch, TheHive, Cortex, Velociraptor |
| **CTI** | OpenCTI + connectors, MISP |
| **Obs** | Grafana, Prometheus, Loki, Tempo |

---

## 2. Schémas de flux

### 2.1 Flux DFIR

```
Endpoint / Image disque
    → Velociraptor collect / upload CERT
    → MinIO (brut)
    → parsers / Logstash
    → OpenSearch (forensic-*)
    → Timesketch (timeline)
    → TheHive case + rapport
```

### 2.2 Flux SOC

```
Beats / Syslog / Upload
    → Logstash pipelines
    → OpenSearch
    → Alerting / Dashboards / HELK Sigma
    → Triage portail
    → TheHive + Cortex
```

### 2.3 Flux CTI

```
Feeds externes → OpenCTI connectors
              ↘ MISP events/attrs
    → sync scripts → forensic-ti-opencti-* / forensic-ti-misp-*
    → dashboards IOC / matches
    → pivots hunting
```

### 2.4 Flux ingestion

```
CERT upload ──┐
IT token ─────┼→ cert-portal / ingest-worker → MinIO
API upload ───┘         ↓
                 Logstash / HELK
                        ↓
                 OpenSearch + Timesketch queue
```

### 2.5 Flux export

```
MISP export JSON/STIX → partage tiers / OpenCTI
OpenCTI STIX → fichiers / connecteurs export
Timesketch → stories / CSV
MinIO → mc mirror / evidence ZIP
VR → artifact ZIP
Portail → rapports forensic
```

### 2.6 Flux investigation type

Voir `analyst-guide.md` §8 et `docs/PORTAL/PIVOTS.md`.

---

## 3. Services — référence

### 3.1 Nginx

- Conteneur `forensic-nginx`.
- Conf : `config/nginx/conf.d/forensic.conf` + snippets.
- Santé : `/nginx-health`.

### 3.2 Portail CERT

- Node/Express, auth session, overview, upload, CTI panel, VR/HELK modules.
- Health agrégée **16 services**.
- Docs servies sous `/docs/`.

### 3.3 Portail IT

- Dépôt evidences via **jetons** TTL.
- Health `/it/api/health`.

### 3.4 OpenSearch + Dashboards

- Cluster 2 nœuds lab, indices `forensic-*`, TI, ISM.
- UI `/dashboards/` — playbooks SOC importés au full-start.

### 3.5 Logstash / Filebeat

- Ingest multi-pipelines (beats, syslog, HEC, HTTP).
- Filebeat → OS.

### 3.6 MinIO

- Object storage evidences / raw logs.
- Console via proxy `/minio/` ou port 9001.

### 3.7 Timesketch

- Sketches, analyzers Sigma/MISP, worker d’import.
- URL externe patchée avec `PUBLIC_HOST`.

### 3.8 MISP

- CTI événementiel, galaxies, warninglists.
- Proxy `/misp` (préfixe conservé).
- Clé API hex 40 chars obligatoire.

### 3.9 OpenCTI

- Graphe CTI + connecteurs (URLhaus, MITRE, CVE…).
- UI `/cti/`, GraphQL `/cti/graphql`.

### 3.10 TheHive

- Cases IR v5, org `cert`, templates FP-Master.
- Base path `/thehive`.

### 3.11 Cortex

- Analyzers / responders ; CSRF + API key.
- Intégration TheHive.

### 3.12 Velociraptor

- Serveur 0.76.x, artifacts custom ForensicMinimal.
- GUI via nginx HTTP plain upstream.
- Sidecar bridge santé.

### 3.13 HELK

- Sidecar ES/Kibana/Logstash hunting.
- Kibana basePath `/helk/kibana`.
- Index-patterns `helk-*`.

### 3.14 Observabilité

- Grafana datasources OS/TS ; Prometheus scrape ; Loki/Tempo.

### 3.15 Infra

- Postgres, Redis, RabbitMQ, Cassandra — dépendances apps.

---

## 4. Orchestration

Script unique : `./forensic.sh`

| Commande | Rôle |
|----------|------|
| `-full-start` | Bootstrap → build → start → masters → tests |
| `start` / `stop` / `status` | Cycle de vie |
| `update-portals` | Rebuild portails |
| `repair-vr` | VR 502 |
| `*-master-setup/verify` | Packs outil |

Librairies : `scripts/lib/installer.sh`, `platform-host.sh`, `host-ip.sh`.

---

## 5. Sécurité lab vs production

| Sujet | Lab | Production |
|-------|-----|------------|
| TLS | Auto-signé | PKI |
| Secrets | Générés `.env` | Vault + rotation |
| Ports | Nombreux exposés | Least exposure |
| Auth | Mots de passe partagés | MFA / SSO |

Détail : `hardening-plan.md`.

---

## 6. Exploitation & maintenance

- Quotidien : `operations-guide.md`
- Backup / updates : `maintenance-guide.md`
- Monitoring : `monitoring-plan.md`
- QA : `qa-continuous.md`

---

## 7. Annexes techniques

### 7.1 Variables d’environnement critiques

`PUBLIC_HOST`, `PORTAL_ADMIN_*`, `MISP_ADMIN_*`, `OPENCTI_ADMIN_*`, `TIMESKETCH_*`, `GRAFANA_ADMIN_PASSWORD`, `MINIO_ROOT_*`, `VELOCIRAPTOR_ADMIN_*`, `THEHIVE_*`, `CORTEX_*`, `CERT_PORTAL_SECRET`, `IT_PORTAL_SECRET`.

### 7.2 Scripts de vérité

| Script | Usage |
|--------|-------|
| `verify-platform-ready.sh` | Gate santé HTTPS |
| `portal_auth_ui_verify.py` | Auth portail |
| `helk-kibana-import.mjs` | Patterns HELK |
| `misp-reset-admin.sh` | Admin MISP |
| `post-start-align.sh` | Alignement IP/proxy |
| `preflight-full-start.sh` | Gate pré-déploiement |

### 7.3 Preuves Shadow Ops

- `docs/SHADOW_OPS_REPORT.md`
- `docs/SHADOW_OPS_MATRIX.json`
- `docs/fr/delivery-message.md`

### 7.4 Captures d’écran

Galerie : `docs/PORTAL/SCREENS.md` · images `docs/images/`.

### 7.5 Liens internes

| Doc | Sujet |
|-----|-------|
| `INSTALLATION.md` | Install historique |
| `LAB-ENDPOINTS.md` | Endpoints lab |
| `HELK-FULL-CONFIG.md` | HELK |
| `VELOCIRAPTOR-*.md` | VR |
| `PORTAL/*` | Modules portail |

---

## 8. Conclusion

Forensic Minimal v2 fournit une **plateforme SOC/DFIR intégrée** : un reverse-proxy, deux portails, un SIEM, une stack CTI, un IR, une timeline et une collecte endpoint, orchestrés par un script et validés par une batterie de verifies.

Pour démarrer : `deployment-guide.md` → `operations-guide.md` → `analyst-guide.md`.
