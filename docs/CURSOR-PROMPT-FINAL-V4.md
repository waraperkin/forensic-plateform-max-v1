# Prompt FINAL Cursor — CERT/IT, passe 4 (dernière passe ciblée)

Copie-colle ce fichier entier dans Cursor. C'est la suite directe de la passe 3 (voir rapport dans la conversation / `docs/CURSOR-PROMPT-MASTER-V3.md`). Les correctifs de la passe 3 qui fonctionnent (bug "Chargement…" traité, Overview sans duplication santé, Access Center enrichi avec HELK Kibana/Logstash/Velociraptor, bouton Révéler credentials) **doivent être conservés**.

L'utilisateur n'est **pas satisfait** du résultat visuel de la passe 3 malgré le rapport positif de Cursor. Cette passe doit livrer un résultat **visible et incontestable**, vérifié en navigateur réel à chaque étape — pas seulement en lisant le code.

---

## Règles absolues (identiques à toutes les passes précédentes)

- Ne supprime aucune donnée, fonctionnalité, endpoint API.
- Ne casse aucun lien/proxy Nginx sauf preuve absolue, demande confirmation avant tout changement Nginx.
- Ne touche jamais aux containers `scada-ics-unified-*`.
- Ne push rien sur Git sans validation explicite.
- Ne fais pas de nettoyage CSS/JS massif à l'aveugle.
- Reteste le flux token IT + upload réel après CHAQUE lot.
- `/api/health/global` doit rester 16/16 OK après CHAQUE lot.
- Rebuild/recreate uniquement `cert-portal`/`it-portal` après chaque lot.
- **Vérification obligatoire en navigateur réel après chaque lot — pas de "corrigé" basé sur la seule lecture de code.** La passe précédente a rapporté des correctifs qui, testés en direct, ne satisfont pas l'utilisateur (Centre d'accès toujours en tableaux, cartes non cliquables, thème clair cassé). Ne répète pas cette erreur : ouvre réellement la page, clique, et compare au résultat attendu avant de passer au point suivant.
- Travaille point par point dans l'ordre ci-dessous. Ne déclare un point "fait" qu'après capture d'écran + clic réel prouvant le résultat.

## Preuves de constat (vérifié en direct à l'instant, pour ne pas repartir de zéro)

1. **Polices mélangées — cause identifiée précisément** : `getComputedStyle(el).fontFamily` sur les éléments de la page renvoie 3 valeurs différentes : `"Inter, Roboto, system-ui, -apple-system, \"Segoe UI\", sans-serif"` (widgets normaux), `"JetBrains Mono, ui-monospace, monospace"` (code/console, voulu), et **`"Arial"` brut** sur plusieurs `<button>` (`#menu-toggle`, `#cc-user-menu-btn`, `#theme-toggle`, boutons de menu utilisateur sans classe, etc.). Cause : les boutons ne récupèrent pas la police globale car aucune règle CSS ne force `font-family: inherit` sur l'élément `button` — le navigateur applique sa police par défaut (Arial) à tous les `<button>` non stylés explicitement.
2. **Mode clair cassé — confirmé** : cliquer sur le bouton thème (`#theme-toggle`, icône ☀️/🌙) ne change ni `document.documentElement.getAttribute('data-theme')` (reste `"dark"`) ni la valeur en `localStorage` (`fp-theme-cert` reste `"dark"`). Le clic ne déclenche pas (ou échoue silencieusement dans) la fonction de bascule de thème.
3. **Centre d'accès toujours en tableaux**, malgré le rapport de la passe 3 indiquant l'ajout de nouveaux outils aux groupes — la structure reste `<table>` par domaine, pas des cartes cliquables.

## Point 1 — Police d'écriture unique et cohérente (prioritaire, rapide, faible risque)

- Ajoute une règle CSS globale (dans le fichier de variables/thème central, ou à défaut dans `cert-shell.css` et `it-shell.css`) : `button, input, select, textarea { font-family: inherit; }` — c'est la cause identifiée en §Preuves.
- Après correction, revérifie avec le même type de script que celui utilisé pour le constat (`getComputedStyle` sur tous les `h1,h2,h3,p,span,div,button,td,th,a,label,input`) qu'il ne reste que 2 valeurs de `font-family` dans toute la page (la police principale + la police monospace pour le code/console) — zéro `"Arial"` ou toute autre police non voulue.
- Vérifie CERT **et** IT.

## Point 2 — Réparer le bouton de thème clair/sombre

- Localise la fonction bindée sur `#theme-toggle` (`forensic-ui.js` ou équivalent — chercher `theme-toggle` et `fp-theme-cert`/`data-theme`).
- Corrige pour qu'un clic bascule réellement `document.documentElement.setAttribute('data-theme', ...)` et persiste la valeur en `localStorage`.
- Si un vrai thème clair n'existe pas encore en CSS (variables couleur inversées), il faut le construire a minima : fond clair, texte sombre, cartes/bordures avec un contraste correct — pas juste inverser bêtement (vérifie la lisibilité des badges de statut vert/orange/rouge sur fond clair).
- Teste dans les deux portails (CERT et IT ont chacun leur propre bouton/état de thème d'après le code vu précédemment — `fp-theme-cert` vs équivalent IT).

## Point 3 — Langue : éliminer les fuites de texte dans la mauvaise langue

- L'utilisateur constate qu'en session anglaise, des mots français apparaissent encore (et probablement l'inverse aussi). Les passes précédentes ont corrigé des cas ponctuels (Velociraptor, Ingestion hub) mais pas la totalité.
- Méthode systématique : écrit un petit script qui, dans le navigateur, bascule la langue en EN, parcourt **toutes** les pages de la sidebar CERT et IT une par une, et détecte les mots français résiduels (regex sur les caractères accentués `[àâäéèêëïîôöùûüç]` dans `document.body.innerText`, en excluant les données de démonstration légitimement en français comme les titres d'incidents seedés — à distinguer des libellés d'interface).
- Corrige chaque occurrence trouvée (remplacer par `i18n.t()` avec clé ajoutée dans les deux fichiers `fr.json`/`en.json`, jamais de texte en dur).
- Refais le test en session française pour vérifier qu'aucun mot anglais ne traîne non plus (même méthode, inversée).
- Vérifie aussi le panneau "SOC Assistant" et le sélecteur de thème/langue eux-mêmes (le bouton de langue affiche-t-il bien "FR"/"EN" de façon cohérente selon l'état actuel, pas l'inverse ?).

## Point 4 — Centre d'accès : réorganisation complète + credentials exhaustifs (non négociable sur le fond, flexible sur la forme)

L'utilisateur a redemandé explicitement ce point car la passe 3 n'a fait qu'ajouter des lignes aux tableaux existants, sans changer la structure.

- **Transforme réellement les tableaux "SOC URLS" par domaine en grille de cartes cliquables**, sur le modèle visuel des cartes de la page Santé (badge coloré + nom + statut + URL + actions Ouvrir/Copier). Ne garde pas de `<table>` pour cette section — c'est le cœur de la demande.
- **Credentials complets** : vérifie une dernière fois la liste retournée par `/api/credentials` contre la liste réelle de tous les services dans `docker-compose.yml` (OpenSearch, OpenSearch Dashboards, Timesketch, Grafana, OpenCTI, MISP, TheHive, Cortex, MinIO, Velociraptor, HELK/Logstash, RabbitMQ, Redis, PostgreSQL, Portail CERT, Portail IT, Portainer si présent) — zéro outil manquant. Présente cette section aussi en cartes (une carte par outil : nom, login, mot de passe masqué + bouton copier chacun, rôle), cohérent avec le reste de la page.
- Garde le bouton "Révéler les mots de passe" explicite (acquis de la passe 3, ne pas repasser en révélation par défaut).
- Endpoints API / Ports réseau : accordéon replié par défaut (acquis de la passe 3, à conserver).

## Point 5 — Modèle de carte uniforme et cliquable partout (non négociable)

Sur **Renseignement menace (CTI)**, **Ingestion & Evidences**, **Opérations CERT**, **Opérations IT**, **Incidents**, **Base de connaissances** : remplace le modèle de carte actuel par une carte visuellement identique (ou très proche) à celle utilisée sur **Vue d'ensemble** et **Santé** :
- Même couleur de fond, même bordure/rayon, même badge coloré à gauche, même hiérarchie titre/valeur/meta.
- **Chaque carte doit être cliquable** (toute la surface de la carte, pas juste un bouton "Voir plus" séparé en dessous) et mener à l'action/détail attendu.
- Vérifie que le composant de carte utilisé sur Santé (`fp-ds-card`/`fp-svc-card` dans `cert-overview.js`) est bien réutilisé (import de la même classe CSS / du même gabarit HTML), pas un composant visuellement approchant mais distinct — c'est ce qui a produit l'écart perçu par l'utilisateur à la passe 3 malgré l'ajout d'un badge coloré.
- Teste sur les 6 pages listées + confirme par capture d'écran côte à côte avec Santé/Overview que le rendu est bien cohérent (mêmes couleurs de fond, même taille de carte, même typographie).

## Point 6 — Incidents / Rapports d'investigation / Base de connaissances : amélioration maximale (priorité absolue, non négociable)

Ces trois pages sont ce que les managers/directeurs CERT consultent en premier — elles doivent être les plus abouties de tout le portail, avec le maximum de détail technique clair.

### Incidents
- Vue liste (gauche, cartes cliquables) + détail (droite) déjà en place — enrichis le contenu du détail : timeline complète des événements liés, sévérité/statut/assigné bien visibles en en-tête de carte de détail, tous les boutons de pivot (Discover, Timesketch, TheHive, HELK) accessibles sans scroll caché.
- Le bouton "Générer rapport" doit ouvrir/générer un vrai rapport exploitable (voir point suivant) — vérifie le lien réel entre un incident et son rapport, pas juste un bouton qui ne fait rien de vérifiable.
- Si des données techniques supplémentaires existent en base pour un incident (IOC associés, hôtes touchés, hash de fichiers, chronologie d'attaque) et ne sont pas encore affichées, ajoute-les au panneau de détail — c'est exactement le type d'information qu'un directeur CERT veut voir en un coup d'œil.

### Rapports d'investigation (Rapports forensic)
- Vérifie et améliore la présentation : liste des rapports existants par cas, statut de génération, aperçu/téléchargement, lien retour vers l'incident source.
- Le rapport lui-même (déjà généré en HTML pour au moins un cas de test) doit être complet : identifiants du cas, chronologie, IOC, actions de réponse, conclusion — vérifie son contenu actuel et complète ce qui manque pour qu'il soit présentable à un directeur.

### Base de connaissances
- Une fois le modèle de carte uniforme appliqué (point 5) et le bug de chargement définitivement vérifié réglé (point §2 de la passe 3 — reteste-le une dernière fois en conditions réelles, pas juste "non reproduit"), enrichis la présentation : filtrage par catégorie, recherche, accès direct au contenu d'une fiche/playbook sans navigation complexe.

## Validation obligatoire après CHAQUE point (1 à 6)

1. Rebuild/recreate `cert-portal`/`it-portal`.
2. `curl -sk https://localhost:8443/api/health/global` → 16/16 OK.
3. **Navigation et clics réels en navigateur** (pas de simulation/lecture de code) sur la page concernée, en FR et EN, en thème sombre ET clair une fois le point 2 traité.
4. Capture d'écran desktop 1440×900 et mobile 390×844.
5. Retest complet token IT + upload réel.
6. Playwright ciblé (`ui-cert`, `ui-it`, `ui-it-layout`, `ui-helk`) au vert.
7. Absence de `??`, `�`, clé i18n brute, `soc-icon`, `svg viewBox`, "Chargement…" bloqué, texte dans la mauvaise langue.
8. Captures dans `tests/artifacts/ui-final-v4/<nom-du-point>/`.

## Rapport attendu (par point, pas seulement à la fin)

Pour chaque point 1 à 6 : fichiers modifiés, preuve visuelle avant/après (capture ou description précise de l'interaction testée), résultat de validation, confirmation aucun push Git et `scada-ics-unified-*` intact.

**Ne déclare un point terminé que si tu peux décrire précisément ce que tu as vu à l'écran après l'action (ex. "j'ai cliqué sur le bouton thème, `data-theme` est passé de dark à light, la page est devenue claire, capture jointe") — pas une déduction à partir du code.**
