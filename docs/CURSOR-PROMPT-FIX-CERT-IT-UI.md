# Prompt pour Cursor — Corrections UI portails CERT & IT (forensic-minimal)

Copie-colle tout ce fichier tel quel dans Cursor comme instruction de départ.

---

## Contexte

Repo local : `C:\Users\siaka\forensic-minimal`, plateforme lancée via Docker Desktop (`docker-compose.yml`). Deux portails web :
- **CERT** : `portal-cert/public/index.html` + `portal-cert/public/css/cert-shell.css` + `portal-shared/js/*` + `portal-shared/css/*`
- **IT** : `portal-it/public/index.html` + `portal-it/public/css/it-shell.css` + mêmes dossiers partagés

Deux audits ont été produits dans `docs/` :
- `docs/AUDIT-UI-CERT-IT-2026-07-13.md` (audit par lecture de fichiers)
- `docs/AUDIT-UI-CERT-IT-2026-07-13-VISUEL.md` (audit par inspection navigateur réelle, **fait foi en cas de contradiction avec le premier**)

Lis ces deux fichiers avant de commencer.

## Règles absolues (ne pas déroger)

- Ne supprime aucune donnée, aucune fonctionnalité, aucun endpoint API existant.
- Ne casse aucun lien/proxy Nginx (`config/nginx/`) sauf preuve absolue de nécessité — et dans ce cas, demande confirmation avant de toucher Nginx.
- Ne touche jamais aux containers `scada-ics-unified-*` (autre projet sur la même machine Docker Desktop).
- Ne push rien sur Git sans validation explicite de l'utilisateur.
- Ne fais pas de nettoyage CSS/JS massif « à l'aveugle » : avant de supprimer un fichier, prouve qu'il n'est chargé par aucun des deux `index.html` (`grep` le nom du fichier dans les deux fichiers HTML).
- Le token IT (génération CERT → `/it/?token=...` → upload réel) doit rester fonctionnel de bout en bout après chaque changement — reteste-le.
- `/api/health/global` doit rester à 16/16 OK après chaque changement.
- Après chaque lot de correctifs : rebuild/recreate uniquement `cert-portal` et/ou `it-portal` (`docker compose build cert-portal it-portal && docker compose --env-file .env --env-file config/local-ports.env up -d --no-deps cert-portal it-portal`), jamais un `docker compose up` global.

## Objectif visuel — unifier CERT sur le thème IT

Le portail IT (`portal-it/public/css/it-shell.css`, 259 lignes) a un rendu jugé correct par l'utilisateur : header propre, cartes de statut nettes (badges LOCKED/READY/TOKEN ACTIVE), pas de troncature de titre sur mobile. Le portail CERT (`portal-cert/public/css/cert-shell.css`, 456 lignes) a des problèmes équivalents non résolus (titre tronqué en "C." sur mobile 390px, icônes sidebar cassées).

**Tâche** : prends `it-shell.css` comme référence de direction visuelle (couleurs, cartes, badges, densité, comportement responsive du header) et applique la même qualité de finition à `cert-shell.css`, **sans copier bêtement fichier à fichier** — CERT a plus de sections (sidebar à 4 groupes vs 3, plus d'onglets) donc adapte la structure, ne la remplace pas par celle d'IT. Concrètement :
1. Compare les deux fichiers CSS section par section (header/brand, badges, cartes de stat, responsive `@media`).
2. Repère toutes les règles qui, dans `it-shell.css`, empêchent la troncature du titre et gèrent proprement le responsive — porte l'équivalent dans `cert-shell.css` en gardant les sélecteurs `[data-portal="cert"]`.
3. Vérifie que rien dans `portal-shared/css/portal-v6.css` (règles `!important` sur `--header-h`, `.fp-header`, `.cc-brand > div`) n'écrase les nouvelles règles de `cert-shell.css` — si un `!important` fait obstacle, ajoute une règle de spécificité/ordre équivalente dans `cert-shell.css` plutôt que de modifier `portal-v6.css` (fichier partagé, risque de régression sur IT).

## Liste des corrections à faire (par priorité)

### Priorité 1 — bugs visibles immédiatement, faible risque

1. **Clé i18n manquante `ui.generate_token_btn`** (bouton principal de génération de token affiche le texte brut de la clé en anglais).
   - Fichier : `portal-shared/i18n/en.json`
   - Ajouter la clé (regarder `fr.json` ligne ~153 pour la clé française `"generate_token_btn": "🔑 GÉNÉRER LE TOKEN"`, section `"ui": {...}`) avec une traduction anglaise équivalente, ex. `"generate_token_btn": "🔑 GENERATE TOKEN"`.
   - Vérifier aussi `ui.download_cert` (absent d'`en.json` également, utilisé dans `portal-cert/public/index.html` ligne ~476).
   - Après correctif, lancer un script de vérification qui compare toutes les clés de `fr.json` et `en.json` (aplaties) et confirme 0 clé manquante dans les deux sens.

2. **Icônes sidebar cassées** (Access Center / HELK Hunting / Velociraptor DFIR — carré gris au lieu d'une icône).
   - Fichier : `portal-shared/css/cybercorp-theme.css`, règle `[data-edition="cybercorp"] .cc-nav-btn[data-cc-icon="tools"]::before`.
   - Cette règle fixe `content: '⛭'` mais ne définit **aucun `mask-image`**, alors que la règle de base `.cc-nav-btn::before` applique un `background` plein masqué obligatoirement par un `mask-image`. Résultat : carré plein.
   - Corriger en ajoutant un vrai `mask-image`/`-webkit-mask-image` (SVG data-URI, cohérent avec les autres icônes du même fichier, ex. les règles `[data-cc-icon="dash"]`, `[data-cc-icon="health"]` juste au-dessus dans le même fichier pour voir le pattern exact à respecter) — pas de `content` textuel.

3. **Titre CERT tronqué en "C." sur mobile 390px** — voir section "Objectif visuel" ci-dessus. Root cause probable : une règle `!important` dans `portal-shared/css/portal-v6.css` sur `.cc-brand > div` ou `--header-h` qui prend le dessus sur la règle `@media (max-width:390px) .cc-brand h1 { max-width:140px; ellipsis }` déjà présente dans `cert-shell.css` ligne ~326. À déboguer avec les DevTools (`getComputedStyle` sur `#portal-title` et son parent à 390px de large) avant de corriger, pour identifier précisément quelle règle gagne la cascade.

### Priorité 2 — cohérence linguistique

4. **Textes français codés en dur alors que la session est en anglais** (le sélecteur de langue change le menu/les titres mais pas ces textes) :
   - `portal-shared/js/velociraptor-integration.js` : labels "Playbook offline", "Collecte DFIR complète (offline)", "Voir artefacts", "Créer timeline Timesketch depuis Velociraptor", etc. → remplacer par des appels `i18n.t('velociraptor.xxx')` avec clés ajoutées dans `fr.json`/`en.json`.
   - `portal-shared/js/cybercorp-hub.js` : titre "Ingestion — activité récente" en dur dans un template literal → idem, passer par `i18n.t()`.
   - `portal-shared/js/it-app.js` ou `it-dashboard.js` (à localiser précisément — grep `"DEPOSER DES LOGS"`, `"SUIVI DEPOT"`, `"JOURNAL D'ACTIVITE"`) : mêmes boutons en dur sur le tableau de bord IT.
   - Méthode : `grep -rn "à\|é\|è\|ê\|ç" portal-shared/js/*.js` pour repérer d'autres chaînes françaises non traduites au-delà de cette liste (attention aux faux positifs dans les commentaires de code).

5. **Badges HELK/Velociraptor bloqués sur "HELK status…" / "Velociraptor status…" sur la page Upload Evidences** (CERT, `?tab=upload`).
   - Ces badges se rafraîchissent correctement sur la page HELK Hunting mais pas sur Upload — trouver la fonction de rafraîchissement (probablement `refreshHelkBadges()`/équivalent Velociraptor dans `cert-app.js` ou `helk-integration.js`/`velociraptor-integration.js`) et vérifier qu'elle cible bien les IDs `#helk-status-badge`/`#vr-status-badge` présents sur la page Upload, et qu'elle est bien appelée au chargement de cet onglet (`tab === 'upload'` dans le dispatcher de `cert-app.js`).

### Priorité 3 — structure/robustesse

6. **Panneau "SOC Assistant" : bouton de fermeture peu fiable au clic**, et **mélange de langue dans ses onglets** (Query/Règle/Tableau/Actif/Événement/Règle Σ/Correlation/Investigation — mêmes anglais/français mélangés qu'au point 4).
   - Vérifier la zone cliquable réelle de `#portal-ai-close` vs sa position visuelle (probable désalignement CSS entre l'élément et sa zone de clic effective).
   - Passer ses onglets par i18n comme au point 4.

7. **Verrou anti-réentrance HELK manquant** (`portal-shared/js/helk-integration.js`, fonction `loadHelkHuntingPage()`) — risque de gel de l'onglet navigateur en cas de clics rapides répétés entre Overview et HELK Hunting (non reproduit systématiquement dans les tests, mais le code ne s'en protège pas).
   - Ajouter un flag module-level `let helkPageLoading = false;` : si déjà `true` au moment de l'appel, `return` immédiatement ; sinon poser `true`, exécuter, remettre `false` dans un `finally`.

8. **Overview CERT, Centre d'accès, Incidents : toujours des tableaux bruts, pas de vraie hiérarchie visuelle** (détail complet dans les deux audits). Ce point est le plus gros chantier — à faire en dernier, et **par petits incréments testés un par un** (pas de refonte totale en un seul commit) :
   - Overview : le tableau "OUTILS SOC — ACCÈS DIRECTS" ne doit pas être le premier contenu visible ; les vraies métriques (santé, incidents, ingestion, CTI) doivent apparaître avant.
   - Centre d'accès : grouper les outils par domaine (SIEM/Hunting, DFIR, CTI, Stockage, Observabilité, Portails) plutôt qu'une seule grande table.
   - Incidents : vue liste + détail (colonne gauche = cartes cliquables, colonne droite = détail de l'incident sélectionné avec pivots TheHive/Timesketch/HELK), tableau complet gardé en accordéon repliable plus bas — ne rien supprimer, juste réorganiser la présentation par défaut.

## Validation obligatoire après chaque lot de correctifs

1. Rebuild/recreate `cert-portal`/`it-portal` uniquement (commande ci-dessus).
2. `curl -sk https://localhost:8443/api/health/global` → doit rester 16/16 OK.
3. Se connecter (`admin` / mot de passe dans `.env` → `PORTAL_ADMIN_PASSWORD`), naviguer manuellement dans le navigateur sur : Overview, Santé, Centre d'accès, Threat Intel, Ingestion, HELK Hunting, Velociraptor DFIR, Incidents, Upload Evidences, Jetons IT — en **anglais ET en français** (bouton FR/EN du header) pour vérifier qu'aucun texte ne reste dans la mauvaise langue et qu'aucune clé i18n brute n'apparaît.
4. Générer un token IT depuis "Jetons IT", ouvrir le lien `/it/?token=...` généré, vérifier le déverrouillage, faire un upload réel de fichier test (`tests/fixtures/sample-upload.log` si présent, sinon n'importe quel petit fichier).
5. Tester le responsive à 1440×900 et 390×844 sur Overview CERT et sur IT (avec et sans token) — aucun scroll horizontal, aucun texte tronqué de façon abrupte (une ellipse `…` est acceptable, une coupure brute comme "C." ne l'est pas).
6. Lancer les tests Playwright ciblés s'ils existent : `cd tests && npx playwright test --project=ui-integration playwright/ui-integration/ui-cert.spec.ts playwright/ui-integration/ui-it.spec.ts playwright/ui-integration/ui-it-layout.spec.ts playwright/ui-integration/ui-helk.spec.ts`.
7. Vérifier dans le HTML rendu (`document.body.innerText` en console navigateur, ou capture d'écran) l'absence de : `??`, `�`, `soc-icon`, `svg viewBox`, toute clé du style `msg.xxx_yyy` ou `ui.xxx_yyy` affichée telle quelle.

## Rapport attendu de Cursor à la fin

- Liste des fichiers modifiés.
- Pour chaque point de la liste ci-dessus : corrigé / partiellement corrigé / non traité (avec raison).
- Résultat de la validation (santé, tests, captures avant/après si possible).
- Confirmation qu'aucun push Git n'a été fait et que les containers `scada-ics-unified-*` sont intacts.
