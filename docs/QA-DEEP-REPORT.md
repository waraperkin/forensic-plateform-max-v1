# Rapport QA Deep — Plateforme FP-Master

**Date :** 2026-06-11  
**Cible :** `https://192.0.2.9`  
**Méthode :** exploration navigateur (CERT, IT, Grafana, HELK, Velociraptor), 165 tests Playwright `ui-integration`, scripts de vérification automatisés.

---

## Synthèse

| Domaine | Résultat |
|---------|----------|
| Playwright ui-integration | **165/165 OK** |
| `qa_deep_inventory.py` | **0 issue** |
| `global_health_dashboard_verify.py` | **27/27 OK** |
| `helk_full_config_verify.py` | **31/31 OK** |
| `velociraptor_full_config_verify.py` | **33/33 OK** |
| `helk_velociraptor_analyst_verify.py` | **18/18 OK** |
| Conteneurs Docker | **Tous healthy** |

---

## Bugs trouvés et corrigés

### Critique — Bridge HELK unhealthy

- **Symptôme :** `helk-bridge` unhealthy, sync OpenSearch échouait (`name 'requests' is not defined`).
- **Cause :** `import requests` supprimé par erreur dans `helk/scripts/helk_bridge.py`.
- **Fix :** réintroduction de l'import + rebuild `helk-bridge`.

### Moyen — Test Playwright route MITRE

- **Symptôme :** `ui-helk.spec.ts` attendait dashboard `helk-detections` pour `grafana_mitre`.
- **Fix :** alignement sur `helk-mitre` + ajout `grafana_sigma`.

### Faible — i18n clé brute

- **Symptôme :** bouton affichait `helk.hunt_overview_btn`.
- **Fix :** clés ajoutées dans `portal-shared/i18n/fr.json` et `en.json`.

### Faible — Health check Cortex

- **Symptôme :** HTTP 303 non accepté par le helper de santé.
- **Fix :** `303` ajouté aux statuts OK dans `helpers.ts`.

### Faible — URL `/cert/` 404

- **Symptôme :** `GET /cert/` renvoyait `Cannot GET /cert/` (portail servi à `/`).
- **Fix :** redirection nginx `301` `/cert` et `/cert/` → `/`.

### Préventif — Panneaux inactifs

- **Fix :** `pointer-events: none` sur `.fp-panel:not(.active)` dans `forensic-ui.css` et `portal-cybercorp-stable.css`.

---

## Observations (non bloquantes)

| Item | Détail |
|------|--------|
| Agents Velociraptor lab | Aucun agent connecté — comportement attendu offline (`docs/LAB-ENDPOINTS.md`). |
| Automatisation navigateur MCP | Clics sur boutons HELK/VR nécessitent `scrollIntoView` avant clic (Playwright le fait automatiquement). |
| Grafana | Accessible, dashboard Platform Overview chargé. |
| Portail IT | `/it/` opérationnel, upload et santé plateforme OK. |

---

## Périmètre testé (navigateur)

- **Portail CERT :** tous les onglets sidebar (Vue d'ensemble, Santé, Centre d'accès, CTI, Ingest, HELK, Velociraptor, Opérations, Incidents, KB, Journal, Doc, Admin).
- **HELK :** boutons ingest lab, exports Timesketch/OpenSearch/CTI, pivots host/IOC, liens Grafana/Kibana.
- **Velociraptor :** collecte offline, playbooks, artefacts, pivots DFIR, lien GUI OS.
- **Topbar :** liens Dashboards, Timesketch, OpenCTI, TheHive, MISP, Cortex, MinIO, Grafana.
- **Portail IT :** dashboard, santé, upload evidences, agents, journal.

---

## Commandes de revalidation

```bash
cd forensic-minimal
python3 scripts/qa_deep_inventory.py
python3 scripts/global_health_dashboard_verify.py
python3 scripts/helk_full_config_verify.py
python3 scripts/velociraptor_full_config_verify.py
python3 scripts/helk_velociraptor_analyst_verify.py
cd tests && BASE_URL=https://192.0.2.9 npx playwright test --project=ui-integration
docker compose exec nginx nginx -s reload   # après fix /cert/
```

---

## Fichiers modifiés durant la QA

- `helk/scripts/helk_bridge.py`
- `portal-shared/css/forensic-ui.css`, `portal-cybercorp-stable.css`
- `portal-shared/i18n/fr.json`, `en.json`
- `tests/playwright/ui-integration/helpers.ts`, `ui-helk.spec.ts`, `qa-deep-platform.spec.ts`
- `config/nginx/conf.d/forensic.conf`
- `scripts/qa_deep_inventory.py`
- `qa-reports/qa-deep-inventory.json`
