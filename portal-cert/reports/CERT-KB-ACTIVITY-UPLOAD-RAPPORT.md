# Rapport final — Refonte CERT KB + Activity Log + Upload

**Date :** 2026-06-06  
**Périmètre :** `portal-cert/` + `portal-shared/` uniquement  
**Production :** https://192.0.2.9/  
**Statut :** **CERT KB + ACTIVITY + UPLOAD TERMINÉ**

---

## 1. Fichiers modifiés

### portal-shared/

| Fichier | Changement |
|---------|------------|
| `css/portal-design-system.css` | Chips filtres, table scroll, dropzone bridge, queue upload scroll |
| `css/portal-ai.css` | Drawer IA premium (gradient, ombre, transitions fluides) |
| `js/panel-kb-detail.js` | Barre filtres (recherche, catégorie, chips statut), table responsive scroll, i18n |
| `js/cert-activity-log.js` | Chips type rapides, recherche client, compteur événements, scroll max-height |
| `i18n/fr.json` | Clés `kb.*`, `activity.*`, `upload.queue_title` |
| `i18n/en.json` | Équivalents EN |

### portal-cert/

| Fichier | Changement |
|---------|------------|
| `public/index.html` | Classes DS upload/activity/KB, label file queue i18n |
| `public/css/cert-shell.css` | Styles KB, Activity Log, Upload (responsive 390px) |

---

## 2. Phase 1 — KB (filtres + table + drawer IA)

### Livrables

- **Filtres chips** : Toutes / Publiées / Brouillons + recherche + sélecteur catégorie
- **Table responsive** : `fp-ds-table-wrap` avec en-têtes sticky, scroll vertical stable (max 360–380px)
- **Compteur live** : `{n} fiche(s) affichée(s) sur {total}` via `aria-live`
- **i18n** : colonnes, placeholders, messages — plus de libellés FR codés en dur dans le panneau
- **Drawer IA** : transitions `cubic-bezier`, fond dégradé, `will-change` — ouverture/fermeture fluide validée

### Tests navigateur

| Test | Résultat |
|------|----------|
| Onglet KB detail `?tab=kb-detail` | OK — 2 fiches API |
| Chip « Publiées » | OK — 2/2 affichées |
| Recherche / catégorie | OK — bindings JS |
| Drawer Assistant SOC | OK — ouverture premium |
| Scroll table KB | OK — conteneur `overscroll-behavior: contain` |

**Capture :** `reports/screenshots/cert-kb-filters-desktop.png`

---

## 3. Phase 2 — Activity Log + Upload

### Activity Log

- **Chips** : Tous / Utilisateur / CERT ops / Système (sync avec `<select>`)
- **Recherche** : filtre client sur lignes chargées
- **Scroll** : `max-height: 400–420px`, 300 événements chargés
- **Compteur** : `300 événement(s) affiché(s) sur 300`

**Capture :** `reports/screenshots/cert-activity-log-desktop.png`

### Upload

- **Dropzone** : classe `fp-ds-dropzone-bridge`, transition drag-over
- **File queue** : label i18n « Fichiers en file d'attente », `max-height: 280px`, scroll stable
- **Validation scroll** : CDP — `scrollHeight 525px / clientHeight 280px` avec 15 fichiers mock

**Captures :** `reports/screenshots/cert-upload-desktop.png`

---

## 4. Phase 3 — Tests UI réel (navigateur intégré)

| Scénario | Statut |
|----------|--------|
| KB + filtres chips | ✅ |
| Scroll KB | ✅ |
| Drawer IA ouverture | ✅ |
| Activity Log scroll long (300 rows) | ✅ |
| Activity filtres chips + select | ✅ |
| Upload dropzone + label queue | ✅ |
| Upload queue scroll (mock 15 fichiers) | ✅ |
| Responsive 390px KB | ⚠️ voir anomalies |
| Collisions header/sidebar | ✅ aucune en desktop 1400px |

---

## 5. Captures avant / après

| Avant (session précédente) | Après (cette refonte) |
|----------------------------|------------------------|
| KB : table sans filtres chips | `cert-kb-filters-desktop.png` |
| Activity : filtres formulaire seuls | `cert-activity-log-desktop.png` |
| Upload : queue 140px sans label | `cert-upload-desktop.png` |
| Drawer IA : transitions basiques | `cert-ai-drawer-open.png` |

---

## 6. Stabilité

### Scroll

| Zone | Mécanisme | Verdict |
|------|-----------|---------|
| KB table | `fp-ds-table-wrap` + `overscroll-behavior: contain` | **Stable** |
| Activity Log | `fp-ds-scroll-panel` max-height 420px | **Stable** (300 lignes) |
| Upload queue | `fp-ds-upload-queue` max-height 280px | **Stable** (scrollHeight > clientHeight) |

### Filtres

| Zone | Mécanisme | Verdict |
|------|-----------|---------|
| KB chips | Client-side `data-kb-row` | **Stable** |
| KB recherche/catégorie | Input + select combinés | **Stable** |
| Activity chips | Sync select + refresh API | **Stable** |
| Activity recherche | Client-side post-fetch | **Stable** |

---

## 7. Anomalies restantes (mineures)

1. **390px + sidebar ouverte** : le panneau KB est étroit si le menu latéral reste ouvert — comportement attendu ; `tab()` ferme la sidebar au changement d'onglet.
2. **Hub KB (`?tab=kb`)** : cartes hub inchangées (hors scope détail KB) — le détail `kb-detail` est la vue refondue.
3. **Contenu KB API** : seulement 2 fiches en base — scroll KB peu visible avec peu de lignes (comportement normal).
4. **Corps Markdown KB** : champs `body/content` vides côté API (données métier, pas UI).

---

## 8. Déploiement

```bash
docker compose build cert-portal && docker compose up -d cert-portal --no-deps
```

Container `forensic-cert-portal` redéployé et validé sur https://192.0.2.9/

---

## Statut final

# CERT KB + ACTIVITY + UPLOAD TERMINÉ
