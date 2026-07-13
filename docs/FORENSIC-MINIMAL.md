# Forensic Minimal Platform

Version minimaliste SOC-grade de la plateforme forensic CYBERCORP.

## Architecture

```
                    ┌─────────────┐
                    │    Nginx    │ :80 / :443
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌────────────┐  ┌────────────┐  ┌──────────────┐
    │ CERT Portal│  │ IT Portal  │  │ Outils SOC   │
    │   :3000    │  │   :3002    │  │ (subpaths)   │
    └─────┬──────┘  └─────┬──────┘  └──────┬───────┘
          │               │                 │
          └───────────────┴─────────────────┘
                          │
    ┌─────────────────────┴─────────────────────┐
    │  PostgreSQL · Redis · RabbitMQ · Cassandra │
    │  MinIO · OpenSearch · Logstash · Ingest    │
    │  Timesketch · OpenCTI · MISP · TheHive     │
    │  Cortex · Grafana                          │
    └───────────────────────────────────────────┘
```

## Installation

```bash
cd /home/debian/Téléchargements/forensic-minimal
cp .env.example .env   # si .env absent
# Adapter PUBLIC_HOST / GRAFANA_DOMAIN à l'IP de la VM
./forensic.sh full-start
```

Prérequis : Docker, Docker Compose v2, curl, openssl, 16 Go RAM recommandés.

## Démarrage

| Commande | Description |
|----------|-------------|
| `./forensic.sh full-start` | Build + démarrage complet (première install) |
| `./forensic.sh full-stop` | Arrêt de toute la stack |
| `./forensic.sh full-restart` | Redémarrage |
| `./forensic.sh check-health` | Vérification santé services |
| `./forensic.sh logs` | Logs Docker (option : service) |

Démarrage rapide (sans rebuild) : `./forensic.sh start`

## Services

| Service | Rôle |
|---------|------|
| OpenSearch + Dashboards | SIEM, recherche, dashboards |
| Timesketch | Timeline forensic |
| OpenCTI | Threat intelligence |
| TheHive | Gestion incidents IR |
| MISP | Partage IOC |
| Cortex | Analyseurs / responders |
| MinIO | Stockage objets (evidences) |
| Grafana | Observabilité |
| CERT / IT Portals | Portails opérationnels |

## URLs (via Nginx HTTPS)

Remplacez `<IP>` par l'IP de la machine (`hostname -I`).

| Outil | URL |
|-------|-----|
| Portail CERT | `https://<IP>/` |
| Portail IT | `https://<IP>/it/` |
| OpenSearch Dashboards | `https://<IP>/dashboards/` |
| Timesketch | `https://<IP>/timesketch/` |
| OpenCTI | `https://<IP>/cti/` |
| TheHive | `https://<IP>/thehive/` |
| MISP | `https://<IP>/misp/` |
| Cortex | `https://<IP>/cortex/` |
| MinIO | `https://<IP>/minio/` |
| Grafana | `https://<IP>/grafana/` |
Timesketch direct : `http://<IP>:5000/`

## Health checks

```bash
./forensic.sh check-health
curl -sk https://<IP>/nginx-health
curl -sk https://<IP>/api/health          # CERT
curl -sk https://<IP>/it/api/health      # IT
curl -sk http://localhost:9200/_cluster/health
```

## Portails minimaux

### CERT
Dashboard, Operations, References, Admin uniquement (thèmes CYBERCORP inchangés).

### IT
Dashboard (Overview, Health), Operations (Ops, Agents, Evidence), References (Activity Log, Documentation), Admin.

## Tests

```bash
cd tests
npm install
npx playwright install chromium
BASE_URL=https://<IP> npm test
```

## Troubleshooting

| Problème | Action |
|----------|--------|
| Certificat navigateur | Accepter le certificat auto-signé ou `./forensic.sh tls` |
| OpenSearch RED | `./forensic.sh fix-opensearch` |
| Port occupé | Arrêter l'autre stack forensic sur la même machine |
| MISP lent au 1er boot | Attendre 2–3 min, vérifier `logs/misp-init.log` |
| OpenCTI long | Premier démarrage 3–5 min |

## Git

```bash
git init
git add .
git commit -m "Initial forensic-minimal platform"
git remote add origin <URL>
git push -u origin main
```
