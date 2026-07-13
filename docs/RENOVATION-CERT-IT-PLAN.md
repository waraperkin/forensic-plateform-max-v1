# Plan de rénovation CERT/IT — Forensic Minimal

Branche : `codex/renovation-cert-it-platform`  
Date baseline : 2026-07-11

## 1. Baseline initiale (avant corrections)

### Préflight `./scripts/preflight-full-start.sh`

| Test | Résultat initial | Action |
|------|------------------|--------|
| `test_host_ip.sh` | PASS | — |
| `test_tls_forensic_platform.sh` | PASS | — |
| `test_velociraptor_config.sh` | FAIL | `public_url` contenait `/app/index.html` |
| `test_velociraptor_sidecar_wiring.sh` | PASS | — |
| `test_proxy_subpath_config.sh` | FAIL | VR proxy sans `set $velociraptor_upstream` |
| `test_bootstrap_fresh_install.sh` | PASS | — |
| `test_bootstrap_prepare_host.sh` | PASS | — |
| `test_no_lab_ip_residual.sh` | PASS | — |
| `test_nginx_config.sh` | FAIL | upstream VR dynamique absent |
| `test_full_start_gates.sh` | PASS | — |
| Check structurel VR `public_url` | FAIL | `/app/index.html` dans server.config.yaml |

### Corrections baseline appliquées

- `velociraptor/scripts/generate-config.sh` : `public_url` → `https://<host>/velociraptor/` (sans `/app/index.html`)
- `config/nginx/conf.d/forensic.conf` : `set $velociraptor_upstream` + `set $vr_bridge_upstream`
- Tests Playwright : fallback BASE_URL `127.0.0.1` au lieu de `192.0.2.9`

## 2. Registre central des services

Fichier : `lib/service-registry.js`

Services déclarés : CERT, IT, Nginx, OpenSearch, Dashboards, Grafana, Timesketch, OpenCTI, MISP, TheHive, Cortex, MinIO, HELK, Velociraptor, Logstash, ingest-worker, Redis.

## 3. Santé globale et API services

- `lib/global-health.js` refondu (16 services, statuts OK/DEGRADED/DOWN)
- Routes :
  - `GET /api/health/global`
  - `GET /api/services/catalog`
  - `GET /api/services/health`
  - `GET /api/services/:id/health`
  - `GET /api/services/:id/links`
  - `GET /api/pivots?type=&value=`

## 4. Portail CERT

- Cockpit SOC : overview, health, ingest, HELK, Velociraptor, CTI, IR, observability
- Pivot drawer global : `portal-shared/js/pivot-drawer.js`
- Consommation `GlobalHealthService` + registre services

## 5. Portail IT

- Santé plateforme sans token via proxy CERT
- Routes `/api/services/catalog`, `/api/services/health`
- CORS restreint, secrets via `lib/platform-secrets.js`

## 6. Sécurité API

- CORS : `lib/cors-policy.js` (PUBLIC_HOST / PUBLIC_HOSTNAME)
- `/api/credentials` : auth admin + masquage secrets (`?reveal=1` pour admin)
- Rate limits : login, health, upload, token
- Audit : login, token generate/revoke, credentials view, purge

## 7. HELK / Velociraptor

- `lib/bridge-response.js` : format normalisé `{ ok, job_id, case_id, source, destination, indexed, links, errors }`
- Retries + timeouts sur sync/export/collect

## 8. Nginx

Chemins vérifiés : `/`, `/it/`, `/dashboards/`, `/grafana/`, `/timesketch/`, `/cti/`, `/misp/`, `/thehive/`, `/cortex/`, `/minio/`, `/helk/kibana/`, `/helk/api/`, `/velociraptor/`, `/velociraptor/api/health`

## 9. Tests Playwright

Fichier : `tests/playwright/ui-integration/ui-renovation-cert-it.spec.ts`

- Desktop 1440×900 et mobile 390×844
- Screenshots : overview, navigation, pivot, HELK, VR, IT
- Clics sidebar, boutons HELK/VR, API catalog/health

### Harness local (sans stack Docker complète)

```bash
bash scripts/local-portal-harness.sh test
```

- Symlink `portal-shared` → portails `public/shared`
- Redis éphémère Docker — n'interfère pas avec les autres projets
- `FP_HARNESS_MODE=1` : skip tests Nginx proxy
- Résultat 2026-07-11 : **9/9 tests harness passés**, screenshots `tests/artifacts/ui-renovation/`

## 10. Ports host configurables (Docker Desktop)

| Variable | Défaut |
|----------|--------|
| `FP_HTTP_PORT` | 80 |
| `FP_HTTPS_PORT` | 443 |
| `FP_OS_PORT` | 9200 |
| `FP_OSD_PORT` | 5601 |
| `FP_TIMESKETCH_PORT` | 5000 |
| `FP_MINIO_PORT` | 9000 |
| `FP_MINIO_CONSOLE_PORT` | 9001 |

```bash
bash scripts/detect-port-conflicts.sh
cp config/local-ports.env.example config/local-ports.env  # si conflit
export $(grep -v '^#' config/local-ports.env | xargs)
docker compose up -d
```

## 11. Validation finale (Windows `C:\Users\siaka\forensic-minimal`)

```bash
git fetch origin && git checkout codex/renovation-cert-it-platform && git pull
bash scripts/detect-port-conflicts.sh
./scripts/preflight-full-start.sh
./forensic.sh -full-start
BASE_URL=https://localhost cd tests && npm test
```

```bash
./forensic.sh check-health
curl -sk https://<IP>/api/health/global | jq .
BASE_URL=https://<IP> bash scripts/verify-platform-ready.sh
cd tests && BASE_URL=https://<IP> npm test
```

### Corrections tour 2 (2026-07-11)

- `platform-overview.js` : compat `{ services, summary }` de `getServicesCheck()`
- `/api/services` : retourne `services[]` (compat `cert-app.js`)
- `velociraptor/clients` : HTTP 200 dégradé si bridge absent
- Tests statiques : IP `203.0.113.10` (hors RFC5737)
- Preflight : **10/10 OK**
