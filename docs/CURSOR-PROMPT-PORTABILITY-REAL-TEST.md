# Prompt Cursor — Test réel de portabilité (libération des ports) + validation finale avant push vers forensic-minimal-v2

Copie-colle ce fichier entier dans Cursor. Ceci fait suite au rapport QA (`tests/artifacts/qa-final/RAPPORT-QA-FINAL.md`) qui indiquait le test de portabilité "sans `config/local-ports.env`" comme **non exécutable** (port 80 occupé) et remplacé par une analyse de code. Cette passe doit lever ce point une fois pour toutes, avec une preuve réelle, avant que le projet soit considéré prêt à être commité dans le nouveau dépôt `https://github.com/waraperkin/forensic-minimal-v2`.

---

## Règles absolues (ne pas déroger)

- **Ne jamais toucher aux containers `scada-ics-unified-*`** — ne pas les arrêter, ne pas les recréer, ne pas modifier leur configuration. Vérifie leur nombre et leur statut AVANT et APRÈS toute action (`docker ps --filter "name=scada-ics-unified" | wc -l` ou équivalent) et inclus les deux comptes dans le rapport final.
- **Ne modifie aucun code applicatif** des autres projets/containers qui tournent sur la machine. L'objectif est uniquement de **libérer temporairement les ports 80/443** (ou les ports concernés) pour pouvoir tester `forensic-minimal` dans sa configuration par défaut (sans `config/local-ports.env`).
- Avant d'arrêter quoi que ce soit, **identifie précisément ce qui occupe réellement les ports 80 et 443** :
  - `netstat -ano | findstr :80` et `netstat -ano | findstr :443` (ou équivalent PowerShell `Get-NetTCPConnection -LocalPort 80,443`) pour obtenir les PID.
  - Si le port 80 est tenu par un service Windows natif (ex. `HTTP.sys`, IIS, un service Windows système) plutôt qu'un container Docker, **ne le touche pas** sans lister précisément quel service ce serait et demander confirmation avant tout arrêt de service système (c'est un changement de config système, pas juste "arrêter un container").
  - Si le port est tenu par un **autre container Docker** (projet différent de `forensic-minimal` et différent de `scada-ics-unified-*`), tu peux l'arrêter temporairement (`docker stop <container>`, pas `docker rm`) le temps du test, puis le **redémarrer à l'identique** (`docker start <container>`) immédiatement après le test, sans modifier son code, son image, ni sa configuration.
  - Liste dans le rapport final : quels containers/services ont été arrêtés, pourquoi, et confirmation qu'ils ont bien été relancés dans leur état initial après le test.
- Ne push rien sur Git, ne fais aucun commit, sans validation explicite de l'utilisateur — ce prompt sert uniquement à produire un rapport de validation.

## Étape 1 — Libération des ports

1. Identifier ce qui occupe les ports 80 et 443 (voir méthode ci-dessus).
2. Arrêter uniquement ce qui est sûr à arrêter (containers Docker d'autres projets, hors `scada-ics-unified-*` et hors `forensic-minimal`), en notant précisément quoi et pourquoi.
3. Si un service Windows système (pas Docker) bloque le port 80/443 et ne peut pas être arrêté sans risque, documenter précisément lequel et utiliser une alternative : tester avec des ports non-privilégiés explicitement définis via variables d'environnement standard du projet (pas `config/local-ports.env`), en s'assurant que ça reste representatif du mécanisme de production (`PUBLIC_HOST`/`FP_HTTPS_PORT`), et documenter clairement cette limitation dans le rapport si le test port 80/443 strict reste impossible.

## Étape 2 — Test réel de démarrage "portable" (sans `config/local-ports.env`)

1. Arrêter et recréer les containers `cert-portal` / `it-portal` (et uniquement ceux nécessaires au test, jamais scada) **sans** charger `config/local-ports.env` :
   ```
   docker compose --env-file .env up -d --no-deps cert-portal it-portal
   ```
   (ou la séquence complète documentée dans le `README.md` si possible : `./scripts/preflight-full-start.sh` puis `./forensic.sh -full-start`, en conditions aussi proches que possible d'un vrai `git clone` frais).
2. Vérifier que `PUBLIC_HOST` / `FP_HTTPS_PORT` sont bien résolus automatiquement (auto-détection ou valeurs par défaut de production), sans dépendre d'une valeur qui n'existerait que grâce à `config/local-ports.env`.
3. Ouvrir un vrai navigateur sur l'URL résultante (port par défaut, pas 8443/13000) et vérifier que le portail CERT et le portail IT se chargent correctement, que `/api/health/global` répond 16/16 OK, et qu'au moins une navigation basique (Overview, Santé, Centre d'accès) fonctionne sans erreur console.
4. Capture d'écran + logs à l'appui (pas une simple déduction de code).
5. Remettre `config/local-ports.env` en place et refaire un rebuild normal `cert-portal`/`it-portal` avec, pour revenir à l'état de travail habituel une fois le test terminé.

## Étape 3 — Revalidation du test non rejoué précédemment

Le rapport QA précédent indiquait "Token IT → upload E2E : Non rejoué (historique OK)" — ce test doit être **rejoué réellement maintenant**, pas invoqué comme acquis historique :
1. Générer un jeton IT frais depuis le portail CERT (`Jetons IT`).
2. Ouvrir l'URL `/it/?token=...` dans un navigateur réel, vérifier le déverrouillage de l'upload.
3. Uploader un fichier de test réel, vérifier la confirmation d'upload côté portail IT et la trace/preuve côté CERT (journal, ingestion, etc.).
4. Capture d'écran de chaque étape.

## Étape 4 — Rapport final consolidé

Produire un rapport final unique (`tests/artifacts/qa-final/RAPPORT-PORTABILITE-REELLE.md`) qui :
- Confirme, avec preuve réelle (pas analyse de code), que le démarrage fonctionne sans `config/local-ports.env`.
- Confirme le retest réel du flux token IT → upload.
- Liste les containers/services tiers arrêtés puis redémarrés pour libérer les ports, avec confirmation qu'ils sont revenus à l'identique.
- Reconfirme `scada-ics-unified-*` : compte avant/après identique, aucun arrêt/modification.
- Reconfirme `/api/health/global` 16/16 OK à la fin.
- Scan de secrets : confirme qu'aucun mot de passe, token, clé API, ou donnée sensible réelle n'est en dur dans un fichier suivi par Git (grep sur patterns courants : `password`, `secret`, `api_key`, `token=`, adresses IP internes, etc. — hors `.env.example` avec placeholders).
- Conclusion explicite : **prêt / non prêt** pour un commit complet du répertoire dans le nouveau dépôt vide `https://github.com/waraperkin/forensic-minimal-v2`.
- Rappel explicite en fin de rapport : **aucun commit, aucun push, aucune création de remote Git n'a été effectué** — ces actions restent conditionnées à la validation explicite de l'utilisateur, qui les exécutera lui-même ou donnera une confirmation dédiée avant toute exécution.

Ne déclare "prêt" que si chaque point ci-dessus est appuyé par une preuve concrète (capture, log, sortie de commande), pas une déduction.
