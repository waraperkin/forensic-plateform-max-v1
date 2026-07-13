# CERT CYBERCORP Portal — Release Notes

**Version:** 2026.06.03-final1  
**Date:** 2026-06-03

## Nouveautés

- Intelligence SOC globale (`portal-ai.js`) — Assistant SOC, investigation assistée, audit assisté
- Polish IA final — mode explicatif, risque, optimisation requêtes, amélioration règles Sigma, pivots automatiques, résumés
- Documentation intégrée (`portal-doc.js`) — aide contextuelle, panneau Documentation, tutoriels, mode démo
- QA automatique — pytest, Playwright, pipeline `scripts/run-qa.sh`
- Polish Premium — virtual scroll, lazy-load bundles, skeletons, cache local

## Améliorations

- Performance UI sur panneaux lourds (Rules 1100+)
- Sekoia Control Center Enterprise++ (Query/Dashboard/Asset Profile)
- Exports Timesketch / OpenSearch depuis Telemetry & CERT Tools
- Packaging production (`scripts/build-production.sh`)

## Correctifs

- Dégradation propre si control-planes non configurés (HTTP 200, `configured: false`)
- Compatibilité lazy-load avec onglets Threat Platforms / Governance

## Modules impactés

| Module | Fichiers |
|--------|----------|
| Portail CERT | `portal-cert/public/index.html`, Dockerfile |
| Shared UI | `portal-shared/js/*`, `portal-shared/css/*` |
| Threat proxy | `portal-cert/lib/threat-platforms-routes.js` (inchangé routes existantes) |
| Connecteurs | `connectors/sekoia-controlplane`, `connectors/sentinelone-controlplane` |
| QA | `tests/`, `scripts/run-qa.sh` |
| Release | `release/`, `scripts/build-production.sh`, `scripts/export-soc.sh` |

## Compatibilité

- Docker Compose stack forensic-net inchangée (ports 3000 cert-portal)
- Variables `.env` existantes — secrets threat via UI Configuration
- Navigateur : Chromium récent (Playwright QA)

## Instructions upgrade

1. Backup : `Cybercorp-Backup-Portal-Final-YYYYMMDD-HHMMSS`
2. `./scripts/build-production.sh`
3. `docker compose up -d cert-portal`
4. Vérifier `http://localhost:3000/api/health`
5. Optionnel : `./scripts/export-soc.sh` pour archive SOC

## Améliorations IA (cette release)

- Confiance & score de risque sur chaque analyse
- Variantes requêtes : optimisée / large / précise / corrélation
- Variantes Sigma : améliorée / stricte / permissive + exclusions FP
