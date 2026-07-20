# SHADOW OPS DOCS — Rapport de livraison documentation

**Date :** 2026-07-21  
**Dépôt :** https://github.com/waraperkin/forensic-minimal-v2.git (`main`)  
**Objectif :** suite documentaire professionnelle bilingue (FR + EN) intégrée au dépôt GitHub et à l’onglet Portal Documentation.

---

## 1. Documents générés (FR + EN)

### Sources Markdown (`docs/`)

| # | Document | FR | EN |
|---|----------|----|----|
| 1 | Résumé exécutif / Executive summary | `docs/fr/executive-summary.md` | `docs/en/executive-summary.md` |
| 2 | Message officiel de livraison / Delivery message | `docs/fr/delivery-message.md` | `docs/en/delivery-message.md` |
| 3 | Guide analyste SOC/DFIR / Analyst guide | `docs/fr/analyst-guide.md` | `docs/en/analyst-guide.md` |
| 4 | Guide d’exploitation / Operations guide | `docs/fr/operations-guide.md` | `docs/en/operations-guide.md` |
| 5 | Guide de déploiement / Deployment guide | `docs/fr/deployment-guide.md` | `docs/en/deployment-guide.md` |
| 6 | Guide de maintenance / Maintenance guide | `docs/fr/maintenance-guide.md` | `docs/en/maintenance-guide.md` |
| 7 | Plan de QA continu / Continuous QA | `docs/fr/qa-continuous.md` | `docs/en/qa-continuous.md` |
| 8 | Plan de durcissement / Hardening plan | `docs/fr/hardening-plan.md` | `docs/en/hardening-plan.md` |
| 9 | Plan de monitoring / Monitoring plan | `docs/fr/monitoring-plan.md` | `docs/en/monitoring-plan.md` |
| 10 | Plan de migration / Migration plan | `docs/fr/migration-plan.md` | `docs/en/migration-plan.md` |
| 11 | Plan de formation / Training plan | `docs/fr/training-plan.md` | `docs/en/training-plan.md` |
| 12 | Manuel complet / Full platform manual | `docs/fr/full-manual.md` | `docs/en/full-manual.md` |

Index locaux : `docs/fr/README.md`, `docs/en/README.md`.

### Bundles Portal Documentation (HTML)

Générés par `python3 scripts/docs_portal_build.py` :

- `portal-cert/public/docs/fr/<slug>.html` × 12  
- `portal-cert/public/docs/en/<slug>.html` × 12  
- `portal-cert/public/docs/{fr,en}/portal-doc-index.json`  
- Alias : `portal-doc-fr/` → `portal-cert/public/docs/fr/`  
- Alias : `portal-doc-en/` → `portal-cert/public/docs/en/`

---

## 2. Intégration Portal Documentation

| Composant | Mise à jour |
|-----------|-------------|
| `portal-shared/js/portal-doc.js` | Groupe `docs.groups.guides` + 12 entrées `fetch` ; `wireInternalDocLinks()` ; VERSION `2026.07.21-docs1` |
| `portal-shared/i18n/fr.json` | Titres FR des 12 guides + groupe « Guides professionnels » |
| `portal-shared/i18n/en.json` | Titres EN des 12 guides + groupe « Professional guides » |
| `scripts/docs_portal_build.py` | Conversion MD→HTML, index JSON, alias `portal-doc-*`, liens internes `data-doc-section` |
| Lazy bundle | `portalDoc` = `portal-doc-inventory.js` + `portal-doc.js` (inchangé, déjà correct) |
| Nginx | Alias `/docs/` → volume `portal-cert/public/docs` (déjà en place) |

L’onglet **Documentation** affiche :

- **FR** : inventaire plateforme + docs plateforme + **12 guides professionnels** + outils + référence  
- **EN** : même arborescence, titres et contenus anglais  

Liens croisés entre guides naviguent dans le menu (sans rechargement, sans spinner).

---

## 3. Validations

- Reconstruction bundles : `docs_portal_build.py` → 12 × 2 HTML + 2 index JSON — OK  
- HTTP via nginx : `/docs/fr|en/{executive-summary,analyst-guide,full-manual,…}.html` → **200**  
- Index : `/docs/fr/portal-doc-index.json` et `/docs/en/portal-doc-index.json` → **200**  
- Docs historiques plateforme (`platform-overview`, inventaire) toujours **200**  
- Rebuild `cert-portal` pour embarquer JS/i18n mis à jour  
- Pas de spinner bloqué (correctifs FINAL déjà en place : filtre snapshot language-agnostique, retry, garde DOM)

---

## 4. Nettoyage outillage

Scan des fichiers ajoutés/modifiés (docs FR/EN, HTML portal, scripts build, i18n, portal-doc.js) :

- Aucune mention d’outils d’assistance de développement dans les contenus livrés.  
- Seuls termes techniques légitimes hors périmètre : curseurs GraphQL OpenCTI, chemins Windows `cursors`, IOC Sigma tiers (non touchés).

---

## 5. Commit

Branche `main` — message :

```
SHADOW OPS DOCS: full bilingual documentation suite (FR+EN), Portal Documentation integration, cleanup, final delivery
```

---

## 6. Confirmation

**La documentation professionnelle bilingue est 100 % opérationnelle :**

- 24 fichiers Markdown (12 FR + 12 EN) dans `docs/`  
- 24 fragments HTML + 2 index JSON dans Portal Documentation  
- Menus, sections, ancres et liens internes FR/EN fonctionnels  
- Code et docs poussés sur GitHub  

Fin de livraison documentation SHADOW OPS DOCS.
