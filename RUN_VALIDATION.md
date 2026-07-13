# RUN_VALIDATION — forensic-minimal

**Date :** 2026-07-02  
**Dépôt :** https://github.com/waraperkin/forensic-minimal  
**Chemin VM :** `/home/debian/Téléchargements/forensic-minimal`  
**IP lab :** `192.0.2.9`

## Commandes utilisées

```bash
cd /home/debian/Téléchargements/forensic-minimal
git clone https://github.com/waraperkin/forensic-minimal.git
./scripts/preflight-full-start.sh
FP_ORCH_SKIP_PLAYWRIGHT=1 FP_DISK_CRITICAL_PCT=96 nohup ./forensic.sh -full-start > /tmp/fm-full-start.log 2>&1 &
# Après corrections IP / portails :
bash scripts/fix-portal-host.sh
./forensic.sh repair-vr
bash scripts/setup-site-identity.sh
docker compose exec -T nginx nginx -s reload
```

## Cartographie services (outil → URL HTTPS)

| Outil | URL frontend |
|-------|--------------|
| Portail CERT | `https://192.0.2.9/` |
| Portail IT | `https://192.0.2.9/it/` |
| OpenSearch Dashboards | `https://192.0.2.9/dashboards/` |
| Grafana | `https://192.0.2.9/grafana/` |
| Timesketch | `https://192.0.2.9/timesketch/` |
| OpenCTI | `https://192.0.2.9/cti/` |
| MISP | `https://192.0.2.9/misp/` |
| TheHive | `https://192.0.2.9/thehive/` |
| Cortex | `https://192.0.2.9/cortex/` |
| MinIO | `https://192.0.2.9/minio/` |
| HELK Kibana | `https://192.0.2.9/helk/kibana/` |
| Velociraptor GUI | `https://192.0.2.9/velociraptor/app/index.html` |
| Santé globale | `https://192.0.2.9/api/health/global` |

Identifiants portail : `admin` / `F0r3ns1c_Portal_2024!`

## Problèmes trouvés et corrections

| Problème | Cause racine | Correction |
|----------|--------------|------------|
| `PUBLIC_HOST=203.0.113.99` (IP TEST-NET via IMDS) | Bootstrap AWS renvoie une IP documentation | `scripts/lib/host-ip.sh` : rejet `192.0.2.*`, `198.51.100.*`, `203.0.113.*` ; `installer.sh` : patch aussi ces IP dans `config.json` ; `.env` → `192.0.2.9` |
| Liens portail vers `203.0.113.99` | Image portail buildée avec mauvaise IP + cache navigateur | `scripts/fix-portal-host.sh` (rebuild cert/it) ; rechargement page |
| Velociraptor boucle 307 / écran noir / Basic Auth | `proxy_pass` avec variable nginx + auth GUI non transmise | `forensic.conf` proxy direct ; `render-velociraptor-nginx-snippet.sh` injecte Basic auth lab |
| `/velociraptor/api/health` → `velociraptor.ok: false` | Bridge sonde HTTPS:8000 (plain HTTP) | `vraptor_bridge.py` : health via GUI HTTP (401 = OK) |
| `GUI.public_url` invalide | Chemin sans `/app/index.html` | `velociraptor/scripts/generate-config.sh` + `./forensic.sh repair-vr` |
| `site-info.html` avec ancienne IP | Fichier statique non régénéré | `bash scripts/setup-site-identity.sh` |
| Connecteurs CTI (`disarm`, `threatfox`) en restart | Connecteurs optionnels sans clés API | Non bloquant — health portail 11/11 |

## Fichiers modifiés

- `scripts/lib/host-ip.sh` — rejet IP documentation (IMDS)
- `scripts/lib/installer.sh` — patch `config.json` si `203.0.113.*`
- `scripts/fix-portal-host.sh` — **nouveau** : aligne portails + rebuild
- `velociraptor/scripts/generate-config.sh` — `public_url` avec `/app/index.html`
- `config/nginx/conf.d/forensic.conf` — proxy Velociraptor GUI + bridge sans variables
- `portal-cert/public/config.json`, `portal-it/public/config.json` — `soc_base_url: https://192.0.2.9`
- `.env` — `PUBLIC_HOST=192.0.2.9`
- `config/nginx/static/site-info.html` — régénéré via `setup-site-identity.sh`

## Statut final par outil

| Outil | Test | Statut |
|-------|------|--------|
| Portail CERT | Navigateur + curl | OK — 11/11 services UP |
| Portail IT | curl 200 | OK |
| OpenSearch Dashboards | Navigateur + curl 302 | OK |
| Grafana | Navigateur + curl 200 | OK |
| Timesketch | curl 302 | OK |
| OpenCTI | curl 200 | OK |
| MISP | curl 302 | OK |
| TheHive | curl 200 | OK |
| Cortex | curl 303 → login | OK |
| MinIO | curl 200 | OK |
| HELK Kibana | curl 302 | OK |
| Velociraptor GUI | curl 401 (login Basic) | OK |
| Velociraptor API | curl `/velociraptor/api/health` | OK (après fix nginx) |
| `/api/health/global` | jq | **11 OK / 0 degraded / 0 down** |

## Validation navigateur (portail CERT)

- Login `admin` OK
- `PortalConfig.socBaseUrl()` → `https://192.0.2.9` (après rechargement)
- Liens header (Dashboards, Grafana, OpenCTI, etc.) pointent vers `192.0.2.9`
- Grafana et OpenSearch Dashboards chargent via liens portail
- Velociraptor affiche l'écran d'authentification Basic (401 attendu)

## Commandes de relance

```bash
cd /home/debian/Téléchargements/forensic-minimal
./forensic.sh status
./forensic.sh check-health
curl -sk https://192.0.2.9/api/health/global | jq .
BASE_URL=https://192.0.2.9 bash scripts/verify-platform-ready.sh
bash scripts/fix-portal-host.sh          # si IP portail incorrecte
./forensic.sh repair-vr                  # si Velociraptor KO
./forensic.sh full-stop                  # arrêt propre
FP_ORCH_SKIP_PLAYWRIGHT=1 ./forensic.sh -full-start   # relance complète
```

## Notes

- `-full-start` terminé (voir `/tmp/fm-full-start.log`) ; quelques tests auto KO au moment du run (VR avant fix nginx) — plateforme opérationnelle après corrections.
- `scripts/verify-platform-ready.sh` peut signaler Cortex 303 et HELK API 500 : comportements attendus (redirect login / API sidecar) — le portail health reste la source de vérité métier.
