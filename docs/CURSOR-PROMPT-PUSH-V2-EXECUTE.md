# Prompt Cursor — Exécution du commit orphelin + push vers forensic-minimal-v2

Copie-colle ce fichier entier dans Cursor. L'utilisateur a validé explicitement : dépôt `https://github.com/waraperkin/forensic-minimal-v2` confirmé vide sur GitHub, scan secrets/IP fait (`RAPPORT-PRE-PUSH-V2.md`), choix confirmé : **un commit orphelin unique (snapshot propre, sans historique)**.

---

## Règles absolues

- **Ne touche pas au remote `origin`** (`https://github.com/waraperkin/forensic-minimal`) — aucune commande ne doit le modifier, le supprimer, ou pousser dessus. Ce prompt ne concerne que le nouveau remote `v2`.
- Ne touche pas aux containers `scada-ics-unified-*`.
- Avant de commencer, exécute `git status` pour vérifier l'état actuel et t'assurer qu'il n'y a rien d'inattendu à écraser (la branche de travail habituelle doit être retrouvée intacte à la fin).

## Étape 1 — Commit orphelin propre

```bash
git checkout --orphan v2-clean
git add -A
git commit -m "Initial snapshot — forensic-minimal-v2"
```

Avant de committer, vérifie une dernière fois qu'aucun fichier sensible non voulu n'est stagé (`git status`, comparer avec le rapport `RAPPORT-PRE-PUSH-V2.md` — mêmes ~6899+ fichiers attendus, pas de surprise comme un `.env` réel ou une clé privée).

## Étape 2 — Ajout du remote v2 et push

```bash
git remote add v2 https://github.com/waraperkin/forensic-minimal-v2.git
git push v2 v2-clean:main
```

Si `git remote add v2` échoue parce qu'un remote `v2` existe déjà localement d'une tentative précédente, utilise `git remote set-url v2 <url>` au lieu d'ajouter, mais ne touche jamais `origin`.

## Étape 3 — Retour à l'état de travail habituel

```bash
git checkout codex/renovation-cert-it-platform
```

Vérifie que tu es bien revenu sur la branche de travail habituelle et que rien n'a été perdu localement. La branche locale `v2-clean` peut rester en local (elle ne gêne rien) sauf si l'utilisateur demande de la supprimer.

## Étape 4 — Mise en place du flux de mise à jour futur pour v2

L'utilisateur veut qu'à l'avenir, **toute modification faite sur `C:\Users\siaka\forensic-minimal\` puisse être poussée vers `forensic-minimal-v2`** sans jamais toucher `origin`/`forensic-minimal`. Mets en place et documente clairement la procédure suivante (ne l'exécute pas maintenant, juste documente-la dans le rapport) :

- Le remote `v2` reste configuré en local après cette passe (`git remote -v` doit lister `origin` ET `v2`).
- Pour une mise à jour future simple (pas besoin de rester en historique orphelin à chaque fois) : depuis la branche de travail habituelle, un commit normal peut être poussé vers `v2` avec `git push v2 <branche-locale>:main` — mais note bien que cela **ajoutera de l'historique** sur `main` de v2 à partir de ce point (le premier commit orphelin reste la racine, les suivants s'enchaînent normalement dessus). Si l'utilisateur veut à nouveau un snapshot propre sans historique à un moment donné, il faudra refaire un nouveau commit orphelin et un `push --force` sur `v2/main` (à ne faire qu'avec validation explicite, un force-push écrase l'historique distant).
- Documente cette procédure dans un court fichier `docs/MAJ-FORENSIC-MINIMAL-V2.md` : comment pousser une mise à jour normale, comment refaire un snapshot propre si nécessaire, et le rappel que `origin` reste totalement indépendant et non affecté par ces opérations.

## Rapport attendu

Produit `tests/artifacts/qa-final/RAPPORT-PUSH-V2-EXECUTE.md` avec :
- Confirmation de chaque commande exécutée (sortie brute des commandes clés : `git log --oneline -1` sur v2-clean, `git push` output, `git remote -v` final).
- URL finale du commit poussé sur GitHub (lien vers `https://github.com/waraperkin/forensic-minimal-v2/commit/<sha>`).
- Confirmation explicite : `origin`/`forensic-minimal` non touché (aucun push, aucune modification), `scada-ics-unified-*` intact (compte avant/après).
- Confirmation que la branche de travail habituelle (`codex/renovation-cert-it-platform`) est bien restaurée localement, rien de perdu.
- Contenu du nouveau fichier `docs/MAJ-FORENSIC-MINIMAL-V2.md` créé à l'étape 4.

Ne déclare pas terminé sans la preuve de la sortie réelle de `git push` (pas de push simulé).
