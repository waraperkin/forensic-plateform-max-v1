# Prompt Cursor — Finition visuelle maximale CERT/IT (passe 2)

Copie-colle ce fichier tel quel dans Cursor.

## Contexte

Repo local : `C:\Users\siaka\forensic-minimal`, plateforme sur Docker Desktop (`docker-compose.yml`). Une première passe de corrections vient d'être appliquée (voir `docs/CURSOR-PROMPT-FIX-CERT-IT-UI.md` pour l'historique) : icônes sidebar réparées, titre mobile corrigé, i18n complété, HELK ne freeze plus, Access Center groupé par domaine, Incidents en vue liste+détail. **Ces correctifs fonctionnent et sont vérifiés en navigateur réel — ne les défais pas.**

Ce qui reste : le portail est maintenant **fonctionnellement propre mais visuellement générique**. Objectif de cette passe : le rendre pro, moderne, agréable — sans rien casser de ce qui vient d'être stabilisé.

## Règles absolues (identiques à la passe précédente, toujours valables)

- Ne supprime aucune donnée, fonctionnalité, endpoint.
- Ne casse aucun lien/proxy Nginx sauf preuve absolue.
- Ne touche jamais aux containers `scada-ics-unified-*`.
- Ne push rien sur Git sans validation explicite.
- Ne fais pas de nettoyage CSS/JS massif sans preuve qu'un fichier n'est chargé nulle part.
- Le flux token IT (génération → `/it/?token=...` → upload réel) doit rester fonctionnel après chaque changement.
- `/api/health/global` doit rester 16/16 OK après chaque changement.
- Rebuild/recreate uniquement `cert-portal`/`it-portal` après chaque lot, jamais un `docker compose up` global.
- Reteste en **FR et EN** à chaque lot (bascule déjà fonctionnelle, ne pas la casser).

## Constat visuel (inspection navigateur réelle, 2026-07-13, desktop 1440×900)

Ce qui fonctionne déjà et doit être **préservé tel quel dans sa structure** (juste habillé visuellement) :
- Overview : bandeau santé (16 OK/0 DEGRADED/0 DOWN) + grille de cartes services + onglets d'action (Upload/Tokens/Incidents) + rangée de KPI en dessous.
- Access Center : groupé par domaine (SIEM & HUNTING, DFIR, CTI, Stockage, Portails), chaque groupe = un tableau avec Ouvrir/Copier.
- Incidents : colonne gauche liste de cartes cliquables (sévérité colorée en bordure), colonne droite panneau de détail qui se met à jour au clic.
- HELK Hunting / Velociraptor DFIR : tableau de liens + rangée de boutons d'action + bloc pivots (Host/IOC) + zone de résultats.

Ce qui manque de finition (constat visuel précis) :

1. **Cartes de santé/KPI toutes identiques et plates** : même gris uni, même bordure, aucune hiérarchie visuelle entre "OpenSearch" (infra critique) et "Nginx" (proxy) — tout a le même poids visuel. Pas d'icône par service, juste un texte + badge "OK" vert. Comparé à un vrai cockpit SOC (Splunk, Elastic Security, Microsoft Sentinel), c'est plat.
2. **Typographie sans hiérarchie** : tous les titres de page (`CERT OVERVIEW`, `ACCESS CENTER`, `INCIDENTS`, `HELK HUNTING`) sont en majuscules grasses de même taille/poids que les sous-titres de section (`SOC URLS`, `PIVOTS HELK`). Un lecteur ne distingue pas visuellement le niveau H1/H2/H3.
3. **Onglets d'action (Upload Evidence / Tokens IT / Incidents) sur Overview** ressemblent à des onglets de navigation plats (pill grise/bleue), pas à des actions rapides invitantes — pas d'icône, pas de description courte, pas de hover engageant.
4. **Incidents — colonne liste trop dense/étroite** : les cartes de cas sont compressées avec un scroll interne qui apparaît immédiatement (scrollbar visible dès le chargement), peu d'espace de respiration entre sévérité/statut/titre. Le panneau de détail à droite a le même défaut : contenu collé, ID/Case/Sévérité/Statut en texte brut sans grille visuelle claire.
5. **Icônes sidebar incohérentes sémantiquement** : "Access Center" a maintenant une icône de crayon/stylo (✏️-like), ce qui n'évoque pas "accès/outils". À vérifier une par une : chaque icône doit correspondre à ce qu'elle représente (clé/cadenas pour accès, bouclier pour CTI, etc. — cohérence avec les icônes déjà correctes comme le cœur pour Santé).
6. **Boutons "Open" à deux styles différents sur la même page** (HELK Hunting : "Kibana HELK" et "Grafana" ont un Open bleu plein, "HELK API" et "OpenSearch" ont un Open gris/blanc) — semble non intentionnel, à uniformiser ou à justifier par un vrai statut (actif/inactif).
7. **Doublon de texte** : sur HELK Hunting, la phrase "HELK sidecar stack — Kibana, hunts, Sigma detections, Timesketch exports and OpenSearch findings." apparaît **deux fois** à la suite. Bug d'affichage à corriger (probablement un `<p>` dupliqué dans le template ou un appel de rendu exécuté deux fois).
8. **Pas de design system central documenté** : les couleurs (vert OK, bleu accent, gris cartes), rayons de bordure, ombres, espacements semblent cohérents visuellement mais sont probablement dispersés dans plusieurs fichiers CSS (`cert-shell.css`, `cybercorp-theme.css`, `portal-v6.css`, etc.) sans variables centralisées claires — risque de dérive à chaque nouvelle page.
9. **Mobile 390×844 non re-vérifiable dans cette session** (limitation d'outil) — à revalider explicitement par Cursor avec les DevTools en mode responsive après chaque changement, en particulier sur Overview, Incidents (la vue 2 colonnes doit repasser en 1 colonne empilée) et le panneau SOC Assistant.
10. **Le panneau "SOC Assistant"** (drawer en bas d'écran) reste visuellement un bloc générique sombre sans traitement particulier — vérifier sa cohérence avec le reste du design system une fois celui-ci consolidé.

## Travail demandé — dans cet ordre

### Étape 1 — Fonder un design system minimal explicite

Avant de retoucher chaque page, crée (ou consolide s'il en existe déjà un embryon) un fichier de variables CSS unique servant de source de vérité pour :
- Palette : fond, fond élevé (cartes), bordures, texte principal/secondaire/muted, accent (bleu actuel), succès/avertissement/danger (vert/orange/rouge déjà utilisés pour OK/DEGRADED/DOWN).
- Échelle typographique : définir explicitement 4-5 niveaux (titre de page, titre de section, corps, label/meta, code) avec taille/poids/letter-spacing cohérents — les titres de page doivent visuellement dominer les titres de section.
- Rayon de bordure, ombre de carte, espacement de base (grille 4/8px).
- Documenter ce fichier en commentaire en tête (à quoi sert chaque variable) pour que la prochaine personne n'en recrée pas un autre.
- Vérifier qu'aucun fichier existant ne redéfinit ces mêmes valeurs en dur ailleurs (`grep` les couleurs hexadécimales/rgba répétées dans `cert-shell.css`, `it-shell.css`, `cybercorp-theme.css` pour repérer les divergences à corriger).

### Étape 2 — Cartes de santé/services (Overview, Health, HELK, Velociraptor)

- Ajouter une icône ou un indicateur visuel par service (à minima une pastille de couleur plus marquée, idéalement une icône représentant le type de service — SIEM, stockage, proxy, etc.).
- Distinguer visuellement les services "cœur de plateforme" (OpenSearch, Redis, MinIO) des services périphériques (Nginx) si c'est pertinent pour la lecture opérationnelle — sinon, au minimum uniformiser tailles/espacements pour que la grille soit visuellement équilibrée quel que soit le nombre de cartes (actuellement la dernière ligne avec une seule carte "Nginx" isolée casse la grille).
- Ajouter un état de survol (hover) cohérent sur les cartes cliquables.

### Étape 3 — Hiérarchie typographique globale

- Redéfinir `h2.fp-section-title` (titre de page) vs les sous-titres de section (`fp-section-sub` ou équivalent) pour qu'ils soient visuellement distincts (taille, poids, ou couleur d'accent sur le titre principal).
- Vérifier la cohérence sur toutes les pages listées dans le constat (Overview, Access Center, Incidents, HELK, Velociraptor, Upload, Tokens, Santé, CTI, Ingestion).

### Étape 4 — Actions rapides Overview

- Transformer les onglets "Upload Evidence / Tokens IT / Incidents" en vraies cartes/boutons d'action : icône + libellé + micro-description optionnelle, avec un style de bouton secondaire net (pas juste un onglet de navigation plat).

### Étape 5 — Incidents : respiration visuelle

- Augmenter l'espacement interne des cartes de la liste (colonne gauche) et du panneau de détail (colonne droite).
- Le panneau de détail doit présenter ID/Case/Sévérité/Statut/Assigné dans une mini-grille visuelle claire (pas du texte brut ligne par ligne), avec la sévérité mise en valeur par une couleur/badge cohérent avec la bordure de la carte sélectionnée.
- Vérifier qu'un scroll interne n'apparaît que si le contenu dépasse réellement la hauteur disponible (pas par défaut dès le chargement à cause d'une hauteur fixe trop petite).

### Étape 6 — Icônes sidebar : cohérence sémantique

- Revoir chaque icône de la sidebar CERT et IT une par une, vérifier qu'elle correspond au sens de l'entrée (particulièrement "Access Center" actuellement en icône crayon).

### Étape 7 — Corriger le texte dupliqué HELK Hunting

- Localiser et corriger le doublon "HELK sidecar stack — ..." affiché deux fois d'affilée sur la page HELK Hunting.
- Uniformiser le style des boutons "Open" du tableau de liens HELK (actuellement 2 styles différents sans raison apparente).

### Étape 8 — Vérification mobile explicite

- Pour chaque page retouchée, ouvrir les DevTools en mode responsive à 390×844 et confirmer : pas de scroll horizontal, pas de texte tronqué abruptement, la vue Incidents 2-colonnes repasse bien en 1 colonne empilée, les cartes de santé s'empilent proprement.

## Validation obligatoire après chaque étape

1. Rebuild/recreate `cert-portal`/`it-portal` uniquement.
2. `curl -sk https://localhost:8443/api/health/global` → 16/16 OK.
3. Navigation manuelle réelle (pas seulement lecture de code) sur toutes les pages listées dans le constat, en FR et en EN.
4. Génération d'un token IT + ouverture `/it/?token=...` + upload réel d'un fichier test.
5. Capture d'écran desktop 1440×900 ET mobile 390×844 (DevTools responsive) pour chaque page significativement modifiée, sauvegardées dans `tests/artifacts/ui-polish-max/`.
6. Tests Playwright ciblés existants (`ui-cert`, `ui-it`, `ui-it-layout`, `ui-helk`) : doivent rester au vert.
7. Vérifier l'absence de `??`, `�`, clé i18n brute (`msg.xxx`, `ui.xxx`), `soc-icon`, `svg viewBox` visible dans le texte de la page.

## Rapport attendu de Cursor à la fin

- Liste des fichiers modifiés.
- Avant/après pour chaque étape (description ou capture).
- Résultat de la validation (santé, tests, captures).
- Ce qui n'a pas pu être traité et pourquoi.
- Confirmation : aucun push Git, containers `scada-ics-unified-*` intacts, uniquement `cert-portal`/`it-portal` reconstruits.
