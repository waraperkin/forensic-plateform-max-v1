# Prompt MASTER Cursor — CERT/IT, passe 3 (sans régression)

Copie-colle ce fichier entier dans Cursor. Il remplace/complète les deux prompts précédents (`CURSOR-PROMPT-FIX-CERT-IT-UI.md`, `CURSOR-PROMPT-UI-POLISH-MAX.md`) — les correctifs qu'ils ont déjà produits et qui fonctionnent (voir §0) doivent être **préservés**, pas refaits.

---

## 0. Ce qui fonctionne déjà et ne doit PAS être touché/régresser

Vérifié en navigateur réel à l'instant :
- Icônes sidebar : toutes correctes maintenant (clé pour Jetons IT, cadenas/bouclier pour CTI, etc.).
- Titre "CERT CYBERCORP" lisible en desktop et mobile.
- Page **Santé** : grille de 16 cartes avec badge coloré par service (abréviation type "OS", "HK", "VR"...), c'est un **bon modèle de carte** — sers-t'en de référence pour le reste du travail demandé ci-dessous.
- Page **Overview** : bandeau santé + actions rapides (cartes Upload/Tokens/Incidents) + KPI.
- **Access Center** : groupé par domaine (SIEM & Hunting, DFIR, CTI...), table Credentials présente (mots de passe masqués par défaut — comportement de sécurité voulu, ne pas le supprimer).
- **Incidents** : vue liste (cartes) + détail qui se met à jour au clic, fonctionne.
- Flux token IT (génération → `/it/?token=...` → upload réel) : fonctionnel, à retester après chaque lot.
- `/api/health/global` : 16/16 OK.

## 1. Règles absolues (non négociables, identiques aux passes précédentes)

- Ne supprime aucune donnée, fonctionnalité, endpoint API.
- Ne casse aucun lien/proxy Nginx sauf preuve absolue, et demande confirmation avant tout changement Nginx.
- Ne touche jamais aux containers `scada-ics-unified-*`.
- Ne push rien sur Git sans validation explicite de l'utilisateur.
- Ne fais pas de nettoyage CSS/JS massif à l'aveugle — vérifie par `grep` qu'un fichier n'est chargé nulle part avant de le supprimer.
- Reteste le flux token IT + upload réel après CHAQUE lot, pas seulement à la fin.
- `/api/health/global` doit rester 16/16 OK après CHAQUE lot.
- Rebuild/recreate uniquement `cert-portal`/`it-portal` après chaque lot (`docker compose build cert-portal it-portal && docker compose --env-file .env --env-file config/local-ports.env up -d --no-deps cert-portal it-portal`), jamais un `docker compose up` global.
- Reteste en FR **et** EN à chaque lot.
- **Travaille lot par lot dans l'ordre ci-dessous, valide chaque lot avant de passer au suivant.** Ne mélange pas plusieurs lots dans le même changement — c'est ce qui a causé des régressions lors des passes précédentes (des correctifs validés ont été écrasés par des changements suivants non coordonnés).
- Avant de commencer, fais un `git status`/`git diff --stat` pour voir l'état actuel exact et repartir de là, pas d'une supposition.

## 2. BLOQUANT — bug critique à corriger EN PREMIER, avant tout le reste

**Plusieurs pages restent bloquées sur "Chargement..." indéfiniment**, confirmé en navigateur réel sur :
- `?tab=threat-intel` (Renseignement menace / CTI)
- `?tab=kb` (Base de connaissances)

L'appel réseau sous-jacent réussit pourtant (`GET /api/master/kb` → 200, `GET` équivalent pour CTI → 200) : **le problème est côté rendu front, pas côté API.** Le JS reçoit les données mais n'affiche jamais le résultat — probablement une fonction de rendu qui plante silencieusement après le fetch (vérifier la console navigateur pour une exception avalée, ou une fonction de rendu appelée avec un nom/signature qui ne correspond plus après un refactor récent).

**Avant de faire quoi que ce soit d'autre** :
1. Vérifie si **Ingestion & Evidences**, **Opérations CERT**, **Opérations IT** ont le même symptôme (l'utilisateur les a citées comme "modèle de carte qui ne plaît pas" — il est possible qu'elles soient en fait bloquées sur "Chargement..." comme CTI/KB, pas juste "mal stylées". Vérifie avant de conclure.).
2. Identifie la fonction JS responsable du rendu de chacune de ces pages (`portal-shared/js/cybercorp-hub.js`, `portal-shared/js/portal-master-zones.js`, ou équivalent) et trouve pourquoi le rendu ne se déclenche pas après la réception des données.
3. Corrige, revérifie en navigateur réel (pas juste en lisant le code) que chaque page affiche vraiment son contenu.
4. Note aussi : sur `?tab=threat-intel`, l'item sidebar actif reste "Vue d'ensemble" au lieu de "Renseignement menace (CTI)" — bug de synchronisation de l'état actif de la sidebar, à corriger dans la même passe si la cause est proche (sinon, à traiter au lot 5).

**Ne passe au lot suivant que lorsque ce point est vérifié résolu par une capture d'écran montrant un contenu réel (pas "Chargement...") sur les 5 pages citées.**

## 3. Lot 1 — Supprimer la duplication Santé / Vue d'ensemble

Constat utilisateur confirmé : la grille des 16 services de santé apparaît identique sur **Overview** ET sur **Santé**.
- Sur **Overview**, remplace la grille complète de 16 cartes par un résumé compact (ex. les 3-4 services les plus critiques ou juste le bandeau "16 OK / 0 DEGRADED / 0 DOWN" déjà présent, sans répéter les 16 cartes détaillées) avec un lien/bouton clair "Voir la santé détaillée →" qui mène à l'onglet Santé.
- La page **Santé** reste l'endroit unique où les 16 cartes détaillées s'affichent — ne change rien à cette page (déjà validée au §0).
- Ne supprime pas les données/API sous-jacentes, seulement la duplication d'affichage sur Overview.

## 4. Lot 2 — Centre d'accès : réorganisation + credentials complets

Deux demandes explicites de l'utilisateur :

**a) Réorganisation ergonomique.** Actuellement : lead text + boutons de raccourci + 3 gros boutons d'action + une succession de tableaux "SOC URLS" (groupés par domaine, correct) puis "CREDENTIALS" (table plate) puis "Endpoints API" puis "Ports". Propose une hiérarchie plus claire, par exemple :
   - Une seule zone d'actions rapides en haut (garder, c'est déjà bien).
   - Les groupes d'outils par domaine (déjà bons) — envisage de les présenter en cartes cliquables (nom outil + statut live + Ouvrir/Copier/Pivot) plutôt qu'en lignes de tableau, en cohérence avec le modèle de carte de la page Santé (§0), MAIS seulement si ça n'alourdit pas la page — teste avant/après pour juger.
   - Une section Credentials clairement séparée visuellement (elle l'est déjà par un titre, mais vérifie l'espacement/la lisibilité des mots de passe masqués).
   - Endpoints API et Ports peuvent être regroupés dans un accordéon "Avancé / technique" replié par défaut, car ce sont des informations moins prioritaires pour un usage quotidien.

**b) Credentials complets pour TOUS les outils.** L'utilisateur veut voir les identifiants de **tous** les outils, pas un sous-ensemble. Vérifie la liste actuelle retournée par `/api/credentials` (route dans `portal-cert/server.js`) et la compare à la liste complète des outils réellement déployés (`docker-compose.yml`) : OpenSearch Dashboards, Timesketch, Grafana, OpenCTI, MISP, TheHive, Cortex, MinIO, Velociraptor, Logstash/HELK, Portail CERT, Portail IT, Redis, PostgreSQL, Portainer si présent. Ajoute les entrées manquantes dans le tableau retourné par le backend (avec la même logique de masquage/fallback déjà en place dans `lib/platform-secrets.js`/`getCredential()` — ne réinvente pas ce mécanisme).
   - **Sécurité à conserver absolument** : les mots de passe restent masqués par défaut (comportement déjà en place et voulu). Ajoute (ou restaure si elle a disparu) un bouton explicite "Révéler les mots de passe" qui recharge la table avec `?reveal=1` — ne mets JAMAIS `reveal=1` par défaut au chargement de la page.

## 5. Lot 3 — Uniformiser le modèle de carte

Une fois le bug bloquant du §2 résolu, applique le modèle de carte de la page **Santé** (badge coloré + libellé + statut + meta, cf. `portal-shared/js/cert-overview.js` fonction `renderServiceGrid`/`svcMeta` comme référence de pattern) aux pages suivantes, **en gardant leurs données et actions actuelles** :
- Renseignement menace (CTI)
- Ingestion & Evidences
- Opérations CERT
- Opérations IT
- Base de connaissances

Ne copie pas le code de `renderServiceGrid` tel quel (il est spécifique aux statuts de service up/down) — inspire-toi de sa structure visuelle (carte avec icône/badge coloré à gauche, titre, valeur clé, meta en dessous) pour l'adapter aux données propres à chaque page (ex. pour KB : catégorie de document au lieu d'un statut UP/DOWN).

## 6. Lot 4 — Incidents, Rapports d'investigation, Base de connaissances : priorité maximale

L'utilisateur est explicite : **c'est la partie que les managers/directeurs CERT consulteront en premier** — elle doit être la plus soignée et la plus complète en information technique.

### Incidents
- Garder la vue liste (gauche) + détail (droite) déjà en place.
- Enrichir le panneau de détail : s'assurer que sévérité, statut, assigné, case ID, timeline d'événements, ET les boutons de pivot (Discover/Timesketch/TheHive/HELK) sont TOUS visibles sans avoir à chercher — vérifie que rien n'est coupé/caché par un scroll interne trop petit (défaut déjà identifié dans la passe précédente).
- Vérifie si un bouton "Générer le rapport d'investigation" est proposé directement depuis le détail d'un incident (une fonctionnalité "Rapports forensic" existe déjà dans la sidebar — connecte les deux si ce n'est pas déjà fait : depuis le détail d'un incident, un lien direct vers son rapport associé).

### Rapports forensic (Investigation Reports)
- Vérifie l'état actuel de cette page (sidebar "Rapports forensic") : contenu, actions disponibles, lisibilité.
- Elle doit permettre de : lister les rapports existants par cas, en générer un nouveau, et l'ouvrir/télécharger — vérifie que ces trois actions existent et fonctionnent réellement (clique dessus, ne te fie pas qu'au code).

### Base de connaissances
- **D'abord corriger le bug bloquant du §2** (page actuellement inutilisable, restée sur "Chargement...").
- Une fois corrigée : présenter les fiches/procédures/playbooks de façon exploitable pour un analyste en pleine investigation (recherche/filtre par catégorie, accès rapide au contenu d'une fiche sans navigation complexe).

## 7. Validation obligatoire après CHAQUE lot (1 à 4)

1. Rebuild/recreate `cert-portal`/`it-portal`.
2. `curl -sk https://localhost:8443/api/health/global` → 16/16 OK.
3. Navigation réelle en navigateur sur la page concernée par le lot, EN et FR, capture d'écran desktop 1440×900.
4. Pour les lots touchant Incidents/CTI/KB/Ingestion/Ops : capture mobile 390×844 (DevTools responsive) également.
5. Retest complet du flux token IT + upload réel.
6. Playwright ciblé (`ui-cert`, `ui-it`, `ui-it-layout`, `ui-helk`) : doit rester vert.
7. Vérifier absence de `??`, `�`, clé i18n brute, `soc-icon`, `svg viewBox`, et surtout absence de "Chargement..." qui ne se résout jamais.
8. Sauvegarder les captures dans `tests/artifacts/ui-master-v3/<nom-du-lot>/`.

## 8. Rapport attendu à la fin de chaque lot (pas seulement à la toute fin)

Pour CHAQUE lot livré, avant de passer au suivant :
- Fichiers modifiés dans ce lot.
- Bug(s) corrigé(s) avec preuve (capture avant/après ou description précise de ce qui a changé visuellement).
- Résultat de la validation (§7).
- Confirmation : aucun push Git, `scada-ics-unified-*` intact, uniquement `cert-portal`/`it-portal` reconstruits.

Ne déclare jamais un lot "terminé" seulement sur la base d'une relecture de code — la vérification navigateur réelle est obligatoire, comme le bug du §2 (bloquant, invisible à la simple lecture de code puisque l'API répond 200) le démontre.
