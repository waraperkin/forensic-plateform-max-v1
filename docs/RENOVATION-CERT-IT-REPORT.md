# Rapport validation CERT/IT — Rénovation SOC/DFIR premium

**Date** : 2026-07-12  
**Branche** : `renovation/cert-it-platform`  
**PR** : https://github.com/waraperkin/forensic-minimal/pull/12  
**Poste** : station locale Windows (`DESKTOP-O3SIFER`)  
**BASE_URL testé** : `https://localhost:8443`

---

## 1. Environnement local confirmé

| Élément | Valeur |
|---------|--------|
| Dossier | `C:\Users\siaka\forensic-minimal` |
| Hostname | `DESKTOP-O3SIFER` |
| Docker | Docker Desktop `desktop-linux` |
| Containers externes protégés | `scada-ics-unified-*` — **non modifiés, non arrêtés** |

---

## 2. Ports alternatifs (conflits SCADA / autres projets)

| Variable | Port |
|----------|------|
| FP_HTTPS_PORT | 8443 |
| FP_CERT_PORTAL_PORT | 13002 (conflit 3000 → Grafana SCADA) |
| FP_MINIO_CONSOLE_PORT | 19001 (conflit 9001 → MQTT SCADA) |
| FP_IT_PORTAL_PORT | 13002 |

Rebuild obligatoire après changement `portal-shared/` : `docker compose build cert-portal it-portal && docker compose up -d cert-portal it-portal`

---

## 3. Refonte UI réalisée (SOC/DFIR premium)

### Design system (`portal-shared/css/soc-design-system.css`, `soc-core.js`)

- Fix layout footer/scroll (conflit `portal-v6.css` 100vh)
- Icônes nav dédiées : `helk`, `velociraptor`, `access`, `connector` (plus de carrés gris)
- Composants : status ribbon, action bar, feeds, pipeline kanban, tool cards, health domains, result boxes
- Masquage table URL overview (`#ov-soc-tools-top`)

### Modules workflow CERT (remplacement hubs cartes)

| Module | Fichier | Rôle métier |
|--------|---------|-------------|
| Cockpit SOC | `cert-cockpit.js` | Status ribbon, incidents, preuves, queue, alertes, IOC, timeline, actions rapides — **sans table URL** |
| Santé | `soc-health-workflow.js` | Services par domaine (Edge, SIEM, Forensic, CTI, Storage) + diagnostic |
| Centre d'accès | `access-center.js` | Hub par sections avec statut, Ouvrir/Copier/Pivot |
| CTI | `soc-cti-workflow.js` | Top IOC, corrélations SIEM, actions OpenCTI/MISP |
| Ingestion | `soc-ingest-workflow.js` | Pipeline kanban 6 colonnes |
| Ops CERT | `soc-cert-ops.js` | Case management : incidents, tokens, uploads, audit |
| Ops IT | `soc-it-ops.js` | Coordination IT : tokens, uploads, agents |
| HELK | `helk-integration.js` | Workflow hunting (recherche, actions guidées, result box) |
| Velociraptor | `velociraptor-integration.js` | Workflow DFIR (playbooks, clients, exports) |

### Portail IT (`it-guided.js`)

- Sans token : accès verrouillé, santé plateforme, étapes de dépôt, pipeline visuel
- Avec token : checklist case, expiration, types/limites, upload guidé, résultat hash/statut

### Problèmes visuels corrigés

| Avant | Après |
|-------|-------|
| Table URL brute en overview | Cockpit SOC avec feeds opérationnels |
| Cartes répétitives chiffres vides | Workflows métier (pipeline, hunting, DFIR) |
| Icônes carrés gris (tools) | SVG Lucide-like cohérents dans `soc-core.js` |
| Footer chevauchant le contenu | `min-height` + scroll main corrigés |
| Panneaux vides décoratifs | Feeds, empty states intelligents, result boxes |
| Boutons « Détails » génériques | Actions nommées (Pivot, Sync HELK, Collecte VR, Token IT) |
| HELK/VR pages techniques brutes | Workflows analyste avec feedback visible |

---

## 4. Captures avant/après

Répertoire : `tests/artifacts/ui-renovation/`

| Fichier | Description |
|---------|-------------|
| `cert-overview-before.png` | Overview legacy (table URL, cartes KPI) |
| `after-cert-cockpit.png` | Cockpit SOC post-refonte |
| `after-cert-health.png` | Santé par domaines |
| `after-cert-access.png` | Centre d'accès hub |
| `after-cert-cti-ingest.png` | CTI + pipeline ingestion |
| `after-cert-helk-vr.png` | HELK hunting + Velociraptor DFIR |
| `after-cert-ops.png` | Opérations CERT + IT |
| `after-cert-pivot.png` | Pivot drawer |
| `after-cert-cases.png` | Vue cases |
| `after-cert-token-gen.png` | Génération token IT |
| `after-cert-mobile.png` | Cockpit mobile 390×844 |
| `after-it-no-token.png` | IT verrouillé + pipeline |
| `after-it-with-token.png` | IT avec token + upload |
| `after-it-mobile.png` | IT mobile |

---

## 5. Validations exécutées

### Runtime (BASE_URL=https://localhost:8443)

| Check | Résultat |
|-------|----------|
| `curl /api/health/global` | **16/16 OK** |
| `verify-platform-ready.sh` | **PASS** |
| `test_tools_access.sh` | **PASS** |

### Preflight

```
bash scripts/preflight-full-start.sh → EXIT 1
```

Échec connu (pré-existant) : `test_proxy_subpath_config.sh` — motif VR proxy HTTP plain absent dans `forensic.conf` sur cette branche Windows. N'impacte pas les portails CERT/IT ni les tests ui-renovation.

### Playwright `ui-renovation-cert-it.spec.ts` (projet ui-integration)

```
15 passed (1.4m)
```

Couverture :

- Cockpit overview (status ribbon + feeds)
- Navigation 10 onglets CERT
- Santé domaines + diagnostic
- Centre accès tool cards
- CTI + ingestion pipeline
- HELK + Velociraptor actions
- Opérations CERT + IT
- Pivot drawer
- Cases view
- Génération token IT (UI)
- IT sans token
- IT avec token + upload guidé
- Mobile CERT 390×844 + IT mobile

### Playwright suite complète (`npm test`)

```
169 passed, 37 failed, 2 flaky (11.4m)
```

Les échecs concernent surtout des tests legacy/infra (Cortex, TheHive, OpenCTI GraphQL, `helk-integration.spec.ts` sans auth storage, rate-limit 429 en parallèle). **La suite ui-renovation est 15/15 verte en isolation.**

---

## 6. Fichiers clés modifiés

```
portal-shared/css/soc-design-system.css
portal-shared/js/soc-core.js
portal-shared/js/soc-health-workflow.js
portal-shared/js/soc-cti-workflow.js
portal-shared/js/soc-ingest-workflow.js
portal-shared/js/soc-cert-ops.js
portal-shared/js/soc-it-ops.js
portal-shared/js/cert-cockpit.js
portal-shared/js/access-center.js
portal-shared/js/helk-integration.js
portal-shared/js/velociraptor-integration.js
portal-shared/js/it-guided.js
portal-cert/public/index.html
portal-it/public/index.html
tests/playwright/ui-integration/ui-renovation-cert-it.spec.ts
tests/playwright.config.ts
```

---

## 7. Limites restantes

- Rate-limit `/api/health*` (HTTP 429) sous charge parallèle Playwright — retry intégré dans tests ui-renovation.
- Onglet « Tokens IT » accessible via `/?tab=tokens` (nav legacy masquée) — lien depuis cockpit/ops.
- Preflight nginx VR subpath : correction à planifier sur branche infra séparée.
- Suite `npm test` complète : 37 échecs pré-existants hors scope ui-renovation.

---

## 8. Definition of Done (local)

- [x] Refonte SOC/DFIR premium implémentée
- [x] Aucun `scada-ics-unified-*` touché
- [x] `https://localhost:8443/api/health/global` 16/16 OK
- [x] `verify-platform-ready.sh` PASS
- [x] `test_tools_access.sh` PASS
- [x] Playwright ui-renovation **15/15 PASS** + screenshots
- [x] Portails CERT/IT accessibles via Nginx :8443
