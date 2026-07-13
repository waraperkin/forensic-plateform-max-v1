# RAPPORT — DESIGN SYSTEM + CERT OVERVIEW

**Statut final : `DESIGN SYSTEM + CERT OVERVIEW TERMINÉ`**

**Date :** 2026-06-06  
**URL testée :** https://192.0.2.9/?tab=overview  
**Périmètre modifié :** `portal-shared/` + `portal-cert/` uniquement

---

## 1. Fichiers modifiés

| Fichier | Rôle |
|---|---|
| `portal-shared/css/portal-design-system.css` | Design System v2 (tokens 8/12/16/24px, grilles, cards, boutons, tags, scroll) |
| `portal-shared/js/cert-overview.js` | KPI overview premium (`fp-ds-kpi-grid`, `fp-ds-card`, tags statut) |
| `portal-shared/i18n/fr.json` | `cert_index.overview_lead` |
| `portal-shared/i18n/en.json` | `cert_index.overview_lead` |
| `portal-cert/public/index.html` | Structure overview `fp-ds-page`, lien `cert-shell.css` |
| `portal-cert/public/css/cert-shell.css` | **NOUVEAU** — layout CERT (header, sidebar, main, overview) |

---

## 2. Design System (Phase 1)

### Tokens
- Spacing : `--fp-space-1` (8px) → `--fp-space-5` (32px)
- Couleurs harmonisées : accent `#00d4ff`, surfaces, bordures, success/warn/danger
- Typographie : échelle `fp-ds-text-xs` → `fp-ds-text-xl`

### Composants
- **Grilles :** `fp-ds-grid`, `fp-ds-kpi-grid` (4 colonnes responsive)
- **Cards :** `fp-ds-card`, `fp-ds-card-interactive`, états `--up/--warn/--down`
- **Boutons :** `fp-ds-btn`, `fp-ds-btn-primary`, `fp-ds-btn-ghost`
- **Tags :** `fp-ds-tag--accent/ok/warn/down`
- **Scroll :** `fp-ds-scroll`, `fp-ds-scroll-panel` (overscroll-behavior contain)
- **Transitions :** `fp-ds-animate-in`, cubic-bezier 0.22s

---

## 3. CERT Overview (Phase 2)

### Sidebar
- Padding 12/16px, hover subtil, état actif barre gauche accent
- Scroll vertical stable dans sidebar
- Menu mobile : overlay `open` / `is-open`, hamburger visible ≤900px

### Header
- Dégradé premium, badge CERT OPS, liens outils avec hover accent
- z-index 110 — plus de collision avec sidebar (corrigé)

### Overview
- En-tête page : titre + lead i18n
- 5 KPI cliquables (OpenSearch, Services, Incidents, IOC, Ingest)
- Grille auto-fit `minmax(160px, 1fr)` pour 5 cartes
- Tags statut sur cluster et services détaillés

---

## 4. Validation UI navigateur intégré

| Test | Résultat |
|---|---|
| Sidebar — clic Vue d'ensemble / Santé | ✅ Navigation OK, état `active` |
| Overview — 5 KPI chargés | ✅ `fp-ds-kpi-grid` × 5 confirmé JS |
| Lead overview i18n | ✅ Texte FR affiché |
| Header desktop 1400px | ✅ Liens outils visibles, pas de collision |
| Responsive 390px | ✅ Menu hamburger, layout empilé, pas de scroll cassé |
| Transitions panneau | ✅ `fp-ds-animate-in` au changement d'onglet |

### Captures

- **Après desktop :** `portal-cert/reports/screenshots/cert-ds-overview-desktop.png`
- **Après 390px :** `portal-cert/reports/screenshots/cert-ds-responsive-390.png`
- **Avant (référence) :** `upgrade-reports/screenshots/cert-after-overview.png` (session précédente)

---

## 5. Stabilité

| Critère | Statut |
|---|---|
| Scroll sidebar | ✅ Stable |
| Scroll main | ✅ `fp-main` overflow-y auto (portal-v6) |
| Responsive 390px | ✅ Grille KPI 1 colonne, header compact |
| Collisions UI | ✅ Corrigées (header z-index + app-body flex) |

---

## 6. Anomalies restantes

| Anomalie | Gravité |
|---|---|
| Titre marque tronqué en viewport étroit (<420px) | Faible — ellipsis voulu |
| Table outils SOC : scroll horizontal si colonnes étroites | Faible — héritage `SocTools` |
| 5e KPI (Ingest) sur 2e ligne en desktop 4-col | Cosmétique — auto-fit gère le wrap |

Aucune régression bloquante.

---

## 7. Déploiement

```bash
docker compose build cert-portal && docker compose up -d cert-portal --no-deps
```

---

**DESIGN SYSTEM + CERT OVERVIEW TERMINÉ**
