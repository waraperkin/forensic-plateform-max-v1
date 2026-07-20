# Mise à jour du dépôt `forensic-minimal-v2`

Ce document décrit comment pousser des modifications locales vers le dépôt public **v2** sans jamais toucher le remote `origin` (`forensic-minimal`).

## Remotes configurés

Après la passe initiale, votre clone local expose deux remotes indépendants :

```bash
git remote -v
# origin  https://github.com/waraperkin/forensic-minimal.git
# v2      https://github.com/waraperkin/forensic-minimal-v2.git
```

**Règle :** toutes les opérations de publication vers le nouveau dépôt passent par `v2`. Ne jamais `git push origin` sauf intention explicite de mettre à jour l'ancien dépôt.

---

## Mise à jour normale (historique incrémental)

Depuis la branche de travail habituelle (`renovation/cert-it-platform` ou autre) :

```bash
cd C:\Users\siaka\forensic-minimal

# 1. Vérifier qu'aucun fichier sensible n'est inclus
git status
# Ne pas committer : .env, config/local-ports.env, reports/, tests/artifacts/

# 2. Commit local classique
git add <fichiers>
git commit -m "feat: description du changement"

# 3. Pousser vers v2 uniquement
git push v2 <branche-locale>:main
```

Exemple :

```bash
git push v2 renovation/cert-it-platform:main
```

Les commits s'ajoutent **au-dessus** du snapshot orphelin initial (`Initial snapshot — forensic-minimal-v2`). L'historique distant `main` de v2 grandit normalement.

---

## Nouveau snapshot propre (sans historique)

Si vous souhaitez **remplacer entièrement** le contenu distant par un snapshot unique (comme au premier push) :

```bash
git checkout --orphan v2-clean-YYYYMMDD
git add -A
git reset HEAD .env config/local-ports.env reports/ tests/artifacts/
git commit -m "Initial snapshot — forensic-minimal-v2 (refresh)"
git push --force v2 v2-clean-YYYYMMDD:main   # ⚠️ ÉCRASE l'historique distant
git checkout renovation/cert-it-platform
```

**Attention :** `git push --force` sur `v2/main` supprime l'historique précédent sur GitHub. À n'utiliser qu'avec validation explicite.

---

## Fichiers à ne jamais versionner

| Fichier / dossier | Raison |
|-------------------|--------|
| `.env` | Secrets runtime |
| `config/local-ports.env` | Surcharge ports locaux |
| `reports/` (racine) | Tokens E2E, rapports locaux |
| `tests/artifacts/` | Captures QA locales |

Ces chemins sont listés dans `.gitignore`.

---

## Rappel indépendance `origin`

- `git push v2 ...` n'affecte **pas** `https://github.com/waraperkin/forensic-minimal`
- `origin` reste configuré pour référence ou synchronisation manuelle séparée
- Aucune commande de ce flux ne modifie ni ne supprime `origin`

---

## Vérification rapide avant push

```bash
git diff --cached --name-only | grep -E '^\.env$|local-ports\.env|\.pem$|\.key$'
# → doit être vide

curl -sk https://localhost:8443/api/health/global | jq .summary
# → 16/16 OK (optionnel, post-modif portails)
```
