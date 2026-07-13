# Prompt Cursor — Étape 1 (scan secrets/IP) + Étape 2 (préparation, SANS push) avant commit vers forensic-minimal-v2

Copie-colle ce fichier entier dans Cursor. Ceci fait suite au `RAPPORT-PORTABILITE-REELLE.md` qui notait un point non vérifié : la présence éventuelle d'une IP interne de lab (`192.0.2.9`) ou d'autres secrets dans des fichiers suivis par Git. Ce prompt doit lever ce doute et préparer (sans exécuter) le commit vers le nouveau dépôt vide `https://github.com/waraperkin/forensic-minimal-v2`.

---

## Règles absolues

- **N'exécute AUCUN `git remote add`, `git push`, ni `git commit`** dans ce prompt. Tout doit rester en préparation/rapport.
- Ne modifie ni les containers `scada-ics-unified-*`, ni aucun autre projet sur la machine.
- Si un correctif est nécessaire (secret trouvé en dur, fichier à ignorer), applique-le uniquement sur les fichiers du projet `forensic-minimal`, avec description précise dans le rapport.

## Étape 1 — Scan exhaustif secrets / données sensibles / IP internes

Travaille uniquement sur les fichiers **suivis par Git** (`git ls-files`), pas sur les fichiers ignorés (ceux-là ne seront de toute façon pas commités).

1. **IP internes de lab** : cherche `192.0.2.9` et plus généralement tout pattern d'IP privée codée en dur (`10.\d+\.\d+\.\d+`, `192.168.\d+\.\d+`, `172.(1[6-9]|2\d|3[01])\.\d+\.\d+`) dans tous les fichiers suivis, en excluant les faux positifs légitimes (exemples dans commentaires/doc générique, adresses de test bidon type `203.0.113.99`/`192.0.2.x` qui sont des plages documentaires RFC 5737 valides à garder). Pour chaque occurrence réelle trouvée : indique fichier + ligne, et corrige en la remplaçant par une variable d'environnement ou un exemple RFC 5737/placeholder si c'était en dur par erreur.
2. **Secrets/mots de passe/tokens/clés API en dur** : grep sur `password\s*[:=]`, `secret`, `api[_-]?key`, `token\s*[:=]`, `Bearer `, `-----BEGIN`, chaînes hexadécimales/base64 suspectes de longueur clé, dans tous les fichiers suivis (JS, JSON, YAML, conf, .env.example inclus — vérifie que `.env.example` ne contient que des placeholders, jamais de vraie valeur).
3. **`lib/platform-secrets.js`** : confirme explicitement que les valeurs par défaut labo (`F0r3ns1c_*_2024!` etc.) sont bien documentées comme fallback de démonstration et non des identifiants réels de production, et que le README/doc explique clairement qu'elles doivent être changées via `.env` en déploiement réel. Si ce n'est pas déjà écrit clairement, ajoute une note explicite dans le README ou le fichier concerné.
4. **`.gitignore`** : vérifie que `config/local-ports.env`, `.env`, tout fichier de credentials local, certificats privés (`*.key`, `*.pem` sauf ceux explicitement destinés à être publics), dumps de base de données, et tout répertoire de données runtime (volumes, logs contenant des données de cas réels) sont bien exclus. Liste tout fichier suivi par Git qui ne devrait probablement pas l'être (ex. certificat privé, dump, gros binaire).
5. Vérifie aussi les fichiers `tests/artifacts/**`, `tests/fixtures/**`, `docs/**` générés pendant les passes QA précédentes : confirme qu'aucun ne contient de token/URL réel exploitable (les tokens IT générés pendant les tests QA expirent et sont à usage unique, mais vérifie qu'aucune vraie donnée de production n'a été capturée par erreur dans les captures d'écran ou JSON).

## Étape 2 — Préparation du commit (sans exécution de push)

1. Génère la liste finale des fichiers qui seraient commités (`git status`, `git ls-files` en excluant les fichiers `.gitignore`), et signale s'il y a des fichiers volumineux/inhabituels qui ne devraient pas être versionnés (node_modules, dossiers de build, dumps, gros binaires).
2. Confirme que le dépôt local (`C:\Users\siaka\forensic-minimal`) est dans un état cohérent pour un commit initial propre : pas de fichiers en conflit, pas de fichiers temporaires de test oubliés (ex. `portability-upload-test.txt` s'il ne doit pas être conservé de façon permanente — à ta discrétion, propose s'il doit rester en fixture de test ou être retiré).
3. Rédige — sans l'exécuter — la séquence exacte de commandes qui sera nécessaire pour committer et pousser vers le nouveau dépôt (ex. `git remote add v2 https://github.com/waraperkin/forensic-minimal-v2.git`, `git push v2 <branche>:main`), en précisant clairement qu'aucune de ces commandes n'a été lancée.
4. Ne touche pas au remote `origin` existant (`forensic-minimal`) — le rapport doit confirmer explicitement qu'aucune modification n'a été faite sur ce remote ni sur ce dépôt.

## Rapport attendu

Produit `tests/artifacts/qa-final/RAPPORT-PRE-PUSH-V2.md` avec :
- Résultat détaillé du scan (IP internes, secrets, `.gitignore`), avec correctifs appliqués le cas échéant.
- Liste des fichiers qui seraient commités, et tout fichier suspect à exclure.
- La séquence de commandes proposée pour le commit/push vers `forensic-minimal-v2` (non exécutée).
- Confirmation explicite : aucun commit, aucun push, aucun remote ajouté, `origin`/`forensic-minimal` non touché, `scada-ics-unified-*` non touché.
- Conclusion : **prêt / non prêt** pour que l'utilisateur donne le feu vert final d'exécution des commandes de commit/push.
