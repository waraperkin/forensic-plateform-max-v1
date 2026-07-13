# Prompt QA TOTALE — dernière étape avant push vers GitHub (waraperkin/forensic-minimal)

Copie-colle ce fichier entier dans Cursor. C'est la dernière étape avant de pousser la version corrigée vers `https://github.com/waraperkin/forensic-minimal`. Aucune limite de temps : si ça prend 10 heures, c'est acceptable et attendu. L'objectif est zéro bug, zéro régression, testé comme un vrai testeur produit / analyste CERT-SOC, pas en lisant du code.

---

## Contexte

Repo local : `C:\Users\siaka\forensic-minimal`, plateforme sur Docker Desktop. Quatre passes de corrections UI ont déjà été faites sur les portails CERT/IT (voir `docs/CURSOR-PROMPT-FIX-CERT-IT-UI.md`, `docs/CURSOR-PROMPT-UI-POLISH-MAX.md`, `docs/CURSOR-PROMPT-MASTER-V3.md`, `docs/CURSOR-PROMPT-FINAL-V4.md`). Cette passe n'est **pas** une passe de correction supplémentaire de fonctionnalités — c'est une **passe de test exhaustif** pour vérifier que tout ce qui a été construit/corrigé fonctionne vraiment, en conditions réelles, avant mise à jour du dépôt public.

## Règles absolues (valables jusqu'au bout, y compris pendant les tests)

- Ne supprime aucune donnée, fonctionnalité, endpoint API.
- Ne touche jamais aux containers `scada-ics-unified-*` — vérifie `docker ps` avant et après chaque session de test pour confirmer qu'ils sont toujours up et inchangés.
- Ne modifie Nginx/les proxys que si un bug est prouvé et localisé précisément là, avec confirmation avant de le faire.
- **Ne push rien sur Git tant que le rapport de QA final n'a pas été présenté à l'utilisateur et validé explicitement par lui.** Cette passe se termine par un rapport, pas par un push automatique — le push est une action distincte, à faire seulement après feu vert explicite.
- Si un bug est trouvé et corrigé pendant cette passe QA, la correction doit elle-même être revalidée en navigateur réel avant de continuer les tests (ne pas juste corriger et supposer que ça marche).
- Rebuild/recreate uniquement `cert-portal`/`it-portal` si un correctif est appliqué à ces services ; ne relance jamais les autres containers sans raison précise et justifiée dans le rapport.

## Méthodologie obligatoire

- **Navigateur réel, pas de lecture de code seule.** Chaque page/fonctionnalité listée ci-dessous doit être ouverte, cliquée, remplie, scrollée — comme le ferait un analyste SOC qui découvre l'outil pour la première fois et qui cherche activement à le faire planter ou à trouver ce qui ne marche pas.
- Teste en **desktop 1440×900 ET mobile 390×844** pour les portails CERT/IT (les outils tiers proxifiés — OpenSearch, Grafana, etc. — peuvent être testés en desktop uniquement, ce sont des produits externes déjà matures, sauf si un lien vers eux est cassé depuis le portail).
- Teste en **français ET anglais** pour les portails CERT/IT.
- Teste en **thème sombre ET clair** une fois que le thème clair fonctionne (cf. passe précédente) pour les portails CERT/IT.
- Pour chaque page : ouvre-la, attends le chargement complet, scroll jusqu'en bas, clique sur CHAQUE bouton/lien/carte/onglet visible, remplis chaque champ de formulaire avec des données de test réalistes, teste les cas limites (champ vide, valeur invalide, très long texte) là où c'est pertinent, vérifie la console navigateur (0 erreur JS tolérée sauf erreurs réseau attendues comme un 401 volontaire), vérifie le réseau (pas d'appel qui boucle, pas de 500 silencieux).
- Note tout ce qui est visuellement anormal même si "ça marche techniquement" (texte tronqué, chevauchement, couleur illisible, incohérence de style).

## Partie A — Portail CERT (exhaustif, page par page)

Pour chaque page de la sidebar CERT, sans exception :

1. **Vue d'ensemble** : bandeau santé, KPI, actions rapides, chaque carte cliquable, lien "Voir la santé détaillée".
2. **Santé** : les 16 cartes de service, bouton Rafraîchir, clic sur chaque carte.
3. **Centre d'accès** : chaque groupe d'outils, chaque bouton Ouvrir/Copier (vérifier que Copier met vraiment l'URL dans le presse-papiers), la section Credentials complète (bouton Révéler, Copier sur chaque login/mot de passe), l'accordéon Endpoints API/Ports, les 3 boutons d'action globaux (Ouvrir tous les outils SOC, Copier toutes les URLs, Copier endpoints API).
4. **Renseignement menace (CTI)** : toutes les cartes, données affichées cohérentes avec la réalité (IOC total, connecteurs), clic sur chaque carte pour vérifier la navigation/le détail.
5. **Ingestion & Evidences** : cartes, volumes, historique, jetons de dépôt, clic sur chaque carte, vérifier les chiffres affichés face à la réalité des uploads existants.
6. **HELK Hunting** : tableau de liens (chaque Ouvrir), boutons d'action (Envoyer vers HELK, Export timeline, Sync findings, Export IOC, Overview), pivots Host/IOC (remplir et soumettre), zone de résultats. **Test de non-régression obligatoire** : navigue rapidement entre Overview et HELK Hunting au moins 10 fois de suite pour confirmer qu'aucun freeze ne se reproduit (bug historique).
7. **Velociraptor DFIR** : idem HELK — tableau de liens, boutons de collecte (Collecte DFIR complète, Voir artefacts, Timeline Timesketch, Export complet, Collecter live), sélecteurs Playbook/Client/Artefact, pivots.
8. **Jetons IT** : génération d'un token (case ID, description, expiration, usages, analyste), vérifier l'URL générée (`https://localhost:8443/it/?token=...`, avec le bon port), le fingerprint SHA-256 affiché proprement, la liste des tokens actifs (Copier, Supprimer — tester une suppression réelle sur un token de test), les filtres/recherche s'ils existent.
9. **Upload Evidences** : dépôt réel d'un fichier de test, remplissage Case ID/Analyste/Priorité/OS Source, case à cocher HELK, badges de statut HELK/Velociraptor (doivent résoudre vers un vrai statut, pas rester bloqués), bouton Upload, barre de progression, stats temps réel à droite (doivent se mettre à jour après l'upload), console de log.
10. **Opérations CERT** : toutes les cartes/données, clic sur chacune.
11. **Opérations IT** : idem.
12. **Incidents** : liste complète des cas (scroll jusqu'au dernier), clic sur chaque carte pour vérifier que le panneau de détail se met à jour correctement à chaque fois (pas de contenu resté de l'incident précédent), tous les boutons de pivot (Discover, Timesketch, TheHive, HELK) — vérifie qu'ils ouvrent bien la bonne URL avec le bon contexte (host/case_id), bouton Générer rapport.
13. **Rapports forensic** : liste des rapports existants, génération d'un nouveau rapport depuis un incident, ouverture/téléchargement d'un rapport, vérifier le contenu réel du rapport généré (pas un template vide).
14. **Base de connaissances** : catalogue complet, filtres/recherche, ouverture du détail d'une fiche/playbook, vérifier qu'aucune page ne reste bloquée sur "Chargement…".
15. **Journal d'activité** : filtres (utilisateur, service, dates), recherche, pagination/scroll sur la liste complète des événements.
16. **Documentation portail** : navigation dans les différentes pages de doc (FR et EN).
17. **Comptes portail** (admin) : liste des comptes, création d'un compte de test, modification, suppression du compte de test créé.
18. **Administration** : paramètres du portail (titre, bannière), sauvegarde, configuration MFA.
19. **Panneau "SOC Assistant"** : ouverture, tous les onglets (Query/Rule/Table/Asset/Event/Correlation/Investigation ou équivalents traduits), fermeture (bouton ET clic en dehors), re-ouverture.
20. Header global : bascule langue (vérifier IMMÉDIATEMENT après bascule qu'aucun texte ne reste dans l'autre langue sur la page actuellement affichée), bascule thème, horloge, menu utilisateur (déconnexion — tester puis se reconnecter), menu hamburger en mobile.

## Partie B — Portail IT (exhaustif)

1. **Sans token** : état verrouillé, santé compacte, message clair, aucune interaction d'upload possible (vérifier que le formulaire est vraiment désactivé, pas juste visuellement grisé).
2. **Avec token valide fraîchement généré** : bandeau investigation (case, expiration, usages), checklist, dropzone, remplissage formulaire (nom, email, notes), case HELK, badges statut, upload réel d'un fichier de test, résultat affiché fichier par fichier, historique des opérations mis à jour.
3. **Avec token expiré/épuisé** : vérifier le message d'erreur affiché est clair et compréhensible (pas de clé i18n brute).
4. **Avec token invalide** (modifié à la main dans l'URL) : vérifier la gestion d'erreur.
5. Navigation sidebar IT complète : Overview, Santé, Opérations IT, Agents, Evidence, Journal d'activité, Documentation, Admin.
6. Mobile 390×844 : sans token puis avec token — le parcours (pas juste la grille santé) doit être visible directement.

## Partie C — Outils tiers accessibles depuis les portails (vérification des liens/proxys, pas un audit complet de chaque produit)

Pour chacun des liens suivants ouverts DEPUIS le Centre d'accès (bouton Ouvrir) : vérifie qu'il s'ouvre réellement, que la page n'est pas une erreur 502/504/blanche, et — si des identifiants sont fournis par le Centre d'accès — tente une connexion réelle pour confirmer que les credentials affichés sont corrects :
- OpenSearch Dashboards
- Grafana
- Timesketch
- OpenCTI
- MISP
- TheHive
- Cortex
- MinIO (console)
- Velociraptor (UI web)
- HELK Kibana
- (Logstash/RabbitMQ si un lien web existe, sinon note "pas d'UI web" et passe)

Pour chaque connexion réussie, ne modifie rien dans l'outil tiers lui-même (pas de suppression/désactivation), contente-toi de vérifier l'accès et, si pertinent rapidement, qu'un pivot envoyé depuis CERT (ex. "Ouvrir dans HELK" avec un host donné) arrive bien avec le bon contexte pré-rempli dans l'outil cible.

## Partie D — Tests de non-régression explicites (bugs déjà corrigés dans les passes précédentes — RETESTER CHACUN)

1. Icônes sidebar : aucune ne doit être un carré gris.
2. Aucun `??`, `�`, clé i18n brute (`msg.xxx`, `ui.xxx`), `soc-icon`, `svg viewBox` visible nulle part, sur aucune page, dans aucune langue.
3. Aucune page bloquée sur "Chargement…".
4. Titre "CERT CYBERCORP" et "IT CYBERCORP" lisibles en entier, desktop et mobile.
5. Aucun débordement horizontal sur mobile 390px, sur aucune page.
6. Police d'écriture unique et cohérente partout (vérifier par script `getComputedStyle` sur un échantillon large d'éléments de chaque page — pas seulement Access Center).
7. Thème clair fonctionnel (bouton bascule réellement `data-theme` et l'apparence).
8. Bascule de langue ne laisse aucun résidu dans l'autre langue.
9. HELK Hunting ne freeze pas après navigation rapide répétée.
10. Token IT → upload réel → résultat visible, de bout en bout, plusieurs fois avec des tokens différents.

## Format de suivi des bugs trouvés

Pour chaque bug trouvé pendant cette passe, consigne dans le rapport final : page/outil concerné, action exacte qui déclenche le bug, comportement observé vs attendu, capture d'écran, sévérité (bloquant / majeur / mineur / cosmétique), et si corrigé : fichier(s) modifié(s) + preuve de revalidation.

## Rapport final attendu (avant toute question de push)

1. Tableau récapitulatif : page/fonctionnalité testée → statut (OK / bug trouvé et corrigé / bug trouvé non corrigé avec raison) → preuve (capture).
2. Liste de tous les bugs trouvés, corrigés ou non, avec sévérité.
3. Résultat des tests de non-régression (Partie D) un par un.
4. Résultat `/api/health/global` (16/16 attendu).
5. Résultat des tests Playwright existants.
6. Captures organisées dans `tests/artifacts/qa-final/<partie>/<page>/`.
7. Confirmation : containers `scada-ics-unified-*` intacts (avant/après comparés).
8. Liste complète des fichiers modifiés pendant cette passe QA (corrections trouvées en testant), avec diff résumé.
9. **Recommandation explicite** : "prêt pour push" ou "NON prêt, points bloquants restants : [liste]".

**Le push vers `https://github.com/waraperkin/forensic-minimal` ne doit pas être fait automatiquement à la fin de cette passe — attends la validation explicite de l'utilisateur sur ce rapport avant de proposer/exécuter les commandes Git.**
