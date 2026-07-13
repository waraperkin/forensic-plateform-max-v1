# Audit UI — Portails CERT & IT (forensic-minimal)

**Date** : 2026-07-13
**Périmètre** : `portal-cert/public/index.html`, `portal-it/public/index.html`, `portal-shared/css/*`, `portal-shared/js/*`, `portal-cert/server.js`, `docker-compose.yml`.
**Méthode** : lecture directe des fichiers sources + comparaison `git diff`/`git status` contre HEAD + inspection du fichier réellement servi par le conteneur `forensic-cert-portal` actif (`docker exec ... public/index.html`, mtime 2026-07-13 10:51 UTC).

> Ce document constate l'état réel du code à l'instant de l'audit. Il ne propose pas de correctifs — objectif : vous donner une base fiable pour prioriser vous-même les corrections.

---

## 1. Constat le plus important : régression par écrasement de fichiers

Une partie significative des correctifs déjà validés lors de sessions précédentes (freeze HELK, icônes sidebar, etc.) a été **annulée** — les fichiers sources sont revenus à un état proche de la version d'origine (`git diff` vide ou quasi-vide sur plusieurs fichiers clés), alors que d'autres fichiers ont évolué en parallèle avec de nouvelles fonctionnalités inconnues de ces sessions (« Command Center », « Forensic Report »).

Concrètement, `portal-it/public/index.html` est **identique à `HEAD`** (aucune différence), et `portal-shared/js/helk-integration.js`, `portal-shared/css/cybercorp-theme.css`, `portal-shared/js/it-app.js` ne montrent **aucune modification locale** — ils ont été soit jamais modifiés dans le commit courant, soit réinitialisés.

Deux fichiers CSS/JS volumineux existent sur disque mais **ne sont chargés par aucune des deux pages** (code mort, jamais lié) :

| Fichier | Lignes | Lié dans CERT ? | Lié dans IT ? |
|---|---|---|---|
| `portal-shared/css/command-center.css` | 1209 | Non | Non |
| `portal-shared/js/command-center.js` | 694 | Non | Non |
| `portal-shared/css/forensic-report.css` | 39 | Oui | Non |
| `portal-shared/js/forensic-report.js` | 447 | Oui (probable) | Non |
| `portal-shared/css/premium-cockpit.css` | ~230 | Non | Non |
| `portal-shared/js/responsive-tables.js` | ~80 | Non | Non |

→ Au minimum **~2200 lignes de CSS/JS orphelines**, vestiges de tentatives de refonte non abouties (`command-center`, plus une tentative antérieure). Ceci confirme et aggrave le problème déjà identifié : de multiples couches de design concurrentes cohabitent dans le repo sans qu'aucune ne soit le "système de vérité".

---

## 2. Portail CERT — état des lieux

### 2.1 Chargement des assets (poids/complexité)
- **13 fichiers CSS** et **60 balises `<script>`** chargés sur une seule page (`portal-cert/public/index.html`).
- Empilement de systèmes de design concurrents toujours présent : `cybercorp-theme.css`, `portal-layout-v2.css`, `portal-hub-premium.css`, `portal-v6.css`, `portal-design-system.css`, `cert-shell.css`, `portal-cybercorp-stable.css`, `panel-detail.css`, `portal-doc.css`, `forensic-report.css`, `global-health.css`, `global-error.css`.
- Aucun de ces fichiers n'a été retiré depuis les précédents audits — le risque de collision de spécificité CSS (un style qui écrase l'autre de façon imprévisible) reste entier.

### 2.2 Bug confirmé — icône sidebar cassée (régression)
`portal-shared/css/cybercorp-theme.css`, règle `[data-cc-icon="tools"]::before` :
```css
[data-edition="cybercorp"] .cc-nav-btn[data-cc-icon="tools"]::before {
  content: '⛭';
  margin-right: 0.35rem;
  opacity: 0.85;
}
```
Cette règle ne définit **aucun `mask-image`**, alors que la règle de base (`.cc-nav-btn::before`) applique un `background` plein avec un masque CSS obligatoire pour dessiner l'icône. Sans `mask-image`, l'icône s'affiche comme un **carré gris uni**. Ce bug avait été corrigé dans une session précédente ; il est revenu à l'identique.
**Pages affectées** : Centre d'accès, HELK Hunting, Velociraptor DFIR (les 3 entrées sidebar utilisant l'icône `"tools"`).

### 2.3 Bug confirmé — HELK Hunting peut geler la page (régression)
`portal-shared/js/helk-integration.js` ne contient **plus** de verrou anti-réentrance sur `loadHelkHuntingPage()`. La fonction peut être invoquée en cascade par les multiples scripts qui interceptent le routage d'onglets (`portal-v6.js`, `portal-nav-fluid.js`, `portal-lazy.js` patchent tous `window.tab`), ce qui avait provoqué un gel complet du navigateur lors des tests précédents. Le correctif (flag `helkPageLoading`) n'est plus présent dans le fichier actuel.
**Risque** : navigation répétée/rapide vers "HELK Hunting" peut à nouveau figer l'onglet navigateur.

### 2.4 En-tête (header) — risque de troncature du titre
`--header-h` est fixé à `56px` dans `forensic-ui.css`, et `portal-v6.css` force cette hauteur avec `!important` sur trois propriétés (`height`, `min-height`, `max-height`). La zone du titre (`.cc-brand > div`) a `overflow: hidden` et `min-width: 0`. Avec un logo, un titre, un sous-titre deux lignes, un badge d'édition, 8 liens d'outils externes et les actions (horloge, utilisateur, langue, thème) dans une barre unique de 56px, le titre "CERT CYBERCORP" risque de se faire tronquer sans ellipse (`CERT CYBE...`) — comportement déjà observé et corrigé, puis reperdu.

### 2.5 Portail IT — verrou visuel absent
`.it-locked` (classe togglée par `it-app.js` selon présence/absence de token) n'a **aucune règle CSS de base** dans les fichiers actuellement chargés par `portal-it/public/index.html` (seul `premium-cockpit.css`, non lié, en contient une). Résultat probable : la zone de dépôt (dropzone, champs, bouton upload) reste visuellement/fonctionnellement identique avec ou sans token, sans indication de verrouillage claire autre que le bandeau d'avertissement textuel.

### 2.6 IT — loader "Chargement..." potentiellement bloqué
`portal-shared/js/it-app.js` : la fonction `loadConfig()` fixe `hint.textContent` sur l'élément `#upload-limits-hint`, mais **ne retire plus** l'attribut `data-i18n="ui.loading"` de cet élément. Tout appel ultérieur à `i18n.translateDOM()` (déclenché à chaque changement d'onglet par les wrappers `portal-v6.js`) réécrase le texte réel avec la traduction littérale de la clé `ui.loading` ("Chargement..."). Ce correctif avait été appliqué puis retiré.

### 2.7 Sécurité — état actuel des credentials (point positif)
Vérifié à l'instant : `portal-cert/server.js` route `/api/credentials` exige **`req.query.reveal === '1'`** en plus du rôle admin (`const reveal = req.user.role === 'admin' && req.query.reveal === '1';`), et le frontend `access-center.js` appelle l'endpoint **sans** `reveal=1` par défaut. **Ce point est actuellement correct** : les secrets restent masqués tant qu'une action explicite n'est pas déclenchée (mais il n'existe plus de bouton "Révéler" dans l'UI — l'action explicite n'a donc plus de moyen d'être déclenchée depuis l'interface).

### 2.8 Sécurité — exposition Docker (point positif, à confirmer dans la durée)
`docker-compose.yml`, bloc `cert-portal` : **aucun montage `/var/run/docker.sock`** actuellement (vérifié ligne par ligne du bloc `cert-portal:`). Le seul montage `docker.sock` restant dans le fichier appartient à un autre service (`filebeat`, légitime pour la découverte de logs conteneurs). Ce point est correct dans l'état actuel.

### 2.9 URL du token IT — configuration correcte actuellement
`FP_HTTPS_PORT=${FP_HTTPS_PORT:-443}` est bien présent dans l'environnement de `cert-portal`, et aucun `IT_PORTAL_URL` codé en dur n'écrase `publicUrl()` pour ce service. **Ce point est actuellement correct** — sous réserve que `config/local-ports.env` (`FP_HTTPS_PORT=8443`) soit bien chargé au démarrage du conteneur (`--env-file .env --env-file config/local-ports.env`).

### 2.10 Sidebar — Upload evidences / Jetons IT
Présents comme entrées de premier niveau dans `portal-cert/public/index.html` (`data-tab-btn="upload"` et `data-tab-btn="tokens"` dans la liste visible, plus dupliqués dans la liste cachée `cc-nav-legacy` — doublon inoffensif mais à nettoyer).

### 2.11 Nouvelle fonctionnalité non documentée ici : "Forensic Reports"
Un onglet `tab-forensic-reports` avec script associé `forensic-report.js` (447 lignes) est présent dans la sidebar ("Opérations") et le contenu principal. Cette fonctionnalité n'a pas été construite dans les sessions précédentes ; son état qualité n'a pas été audité ici (hors du périmètre CERT/IT initialement traité).

---

## 3. Portail IT — état des lieux

`portal-it/public/index.html` est strictement identique à la version d'origine du dépôt (`git diff` vide). Tous les constats suivants sont donc les problèmes **d'origine**, non liés à un travail de rénovation :

- **9 fichiers CSS / 23 scripts** chargés.
- Page unique très longue (scroll continu) avec ancres (`#it-dashboard`, `#it-health`, `#it-upload`, `#it-operations`, `#it-agents`, `#it-activity-log`, `#it-documentation`, `#it-admin`) plutôt que des vues distinctes : la grille de santé complète (16 services) s'affiche **avant** la zone de dépôt, aussi bien sans token (où elle domine tout l'écran) qu'avec token (où il faut défiler pour atteindre le formulaire).
- `.it-locked` sans règle CSS (cf. §2.5) : verrouillage non visible.
- `#upload-limits-hint` : perte du texte réel au profit de la clé `ui.loading` (cf. §2.6).
- Mobile (390×844) : sans correctif responsive spécifique (`responsive-tables.js` non lié), les tableaux `.fp-table-wrap` déjà présents ailleurs dans l'app utilisent leur comportement par défaut (`overflow-x: auto`) — lisible mais pas optimal (scroll horizontal interne au tableau).

---

## 4. Synthèse par sévérité

| # | Problème | Portail | Sévérité | Régression ? |
|---|---|---|---|---|
| 1 | HELK Hunting peut geler l'onglet (pas de verrou anti-réentrance) | CERT | **Critique** | Oui |
| 2 | Icônes sidebar cassées (Centre d'accès / HELK / Velociraptor) | CERT | Élevée | Oui |
| 3 | `.it-locked` sans effet visuel/fonctionnel réel | IT | Élevée | Oui |
| 4 | Loader "Chargement..." peut rester affiché à la place des vraies limites d'upload | IT/CERT | Moyenne | Oui |
| 5 | Risque de troncature du titre header sous contrainte de largeur | CERT | Moyenne | Oui |
| 6 | ~2200 lignes de CSS/JS mortes (command-center, premium-cockpit, responsive-tables, forensic-report.js pour IT) | CERT/IT | Moyenne (dette) | — |
| 7 | 13 CSS / 60 scripts sur une seule page CERT (9 CSS / 23 scripts IT) | CERT/IT | Moyenne (dette/perf) | — |
| 8 | Pas de bouton "Révéler" pour les credentials (fonctionnalité disparue, mais comportement par défaut sûr) | CERT | Faible | Partielle |
| 9 | Doublon `data-tab-btn="upload"`/`"tokens"` entre liste visible et liste cachée | CERT | Faible (cosmétique code) | — |
| 10 | IT : santé complète avant le contenu utile, sans token comme avec token | IT | Moyenne | Non (jamais corrigé côté source d'origine) |

---

## 5. Ce qui fonctionne correctement à l'instant de l'audit
- Masquage des secrets par défaut dans `/api/credentials` (backend correct).
- Pas de montage `docker.sock` sur `cert-portal`.
- Construction d'URL de token IT avec le bon port (`FP_HTTPS_PORT`), pas d'URL codée en dur.
- Sidebar CERT contient bien "Upload evidences" et "Jetons IT" en entrées principales.
- Aucun mojibake (`�`) ni `??` littéral détecté dans les fichiers JS/HTML actuels (scan textuel complet).

## 6. Recommandation de méthode pour la suite
Avant toute nouvelle passe visuelle : **verrouiller** (commit dédié + tag, ou au minimum une sauvegarde locale hors du repo) l'état des fichiers une fois un correctif validé, pour éviter qu'un futur écrasement (linter, éditeur, autre session) ne défasse silencieusement le travail — c'est le mécanisme qui a produit la majorité des régressions listées ici.
