# Addendum critique — portabilité 100% avant push (à lire AVANT et PENDANT le prompt QA)

Ce fichier complète `docs/CURSOR-PROMPT-QA-COMPLETE-FINAL.md`. Il ajoute une exigence de la plus haute importance, non négociable, qui doit être validée **avant** de considérer la plateforme prête à être poussée sur `https://github.com/waraperkin/forensic-minimal`.

## Exigence

La plateforme doit rester **100% portable et déployable sur n'importe quelle machine** (VM on-premise, AWS, Azure, GCP, machine physique) par la seule séquence documentée dans le `README.md` du dépôt :

```
git clone https://github.com/waraperkin/forensic-minimal.git
./scripts/preflight-full-start.sh
./forensic.sh -full-start
```

Aucune étape manuelle supplémentaire, aucun fichier de config local à créer à la main, aucune adresse codée en dur — le `README.md` (déjà présent dans le repo, section bootstrap réseau) décrit un mécanisme d'auto-détection de l'IP publique/hôte qui remplit `PUBLIC_HOST` et les URLs dérivées automatiquement au premier `-full-start`.

## Pourquoi ce point est critique maintenant

Pendant les passes de correctifs UI précédentes (locales, sur cette machine Windows avec Docker Desktop), les commandes de rebuild ont systématiquement utilisé :

```
docker compose --env-file .env --env-file config/local-ports.env up -d --no-deps cert-portal it-portal
```

Or `config/local-ports.env` est **exclu du dépôt Git** (`.gitignore` ligne 53) — c'est un fichier de confort strictement local à cette machine de développement (ports alternatifs 8443/13000/etc. pour éviter les conflits avec d'autres projets Docker locaux). **Il n'existera pas** sur une machine fraîchement clonée en AWS/Azure/VM/physique, et le `README.md` explique que le vrai mécanisme de production est l'auto-détection d'IP + `PUBLIC_HOST` rempli par le bootstrap, pas ce fichier local.

**Risque concret** : si un correctif des passes précédentes s'appuie sur une valeur qui n'existe que grâce à `config/local-ports.env` (par exemple un port `8443` supposé fixe, une IP `localhost` supposée fixe, ou toute logique conditionnelle qui ne serait testée qu'avec ce fichier chargé), ce correctif peut très bien fonctionner ici et **casser silencieusement** sur un déploiement réel ailleurs. C'est exactement le genre de régression invisible en local qu'il faut éliminer avant de mettre à jour le dépôt public.

## Ce que Cursor doit vérifier avant de considérer que le résultat est prêt à pousser

1. **Relire `README.md` en entier** (section bootstrap réseau / variables d'environnement / `PUBLIC_HOST` / `-full-start`) pour bien comprendre le mécanisme de déploiement réel documenté, avant de juger si un correctif le respecte.
2. **Vérifier chaque fichier modifié pendant les 4 passes précédentes** (`docker-compose.yml`, `portal-cert/server.js`, tout ce qui touche `PUBLIC_HOST`, `FP_HTTPS_PORT`, construction d'URLs publiques via `lib/service-registry.js`/`publicUrl()`) pour confirmer qu'aucun ne dépend d'une valeur codée en dur spécifique à cette machine locale (`localhost`, `8443` en dur, `13000`, etc.) — tout doit continuer à passer par les variables d'environnement (`PUBLIC_HOST`, `FP_HTTPS_PORT`) avec leurs valeurs par défaut de production (443, IP auto-détectée), `config/local-ports.env` ne devant être qu'une **surcharge optionnelle** de confort local, jamais une dépendance.
3. **Simuler un déploiement propre si possible** : à défaut de cloner réellement sur une autre machine (ce qui serait l'idéal mais peut ne pas être faisable dans cet environnement), au minimum reconstruire et relancer les containers **sans** `--env-file config/local-ports.env` (avec seulement `.env` généré/rempli comme le ferait le bootstrap réel) et vérifier que la plateforme démarre et fonctionne quand même — quitte à utiliser les ports par défaut (443/80) s'ils sont libres, ou documenter précisément si un vrai conflit de port local empêche ce test (auquel cas, analyser le code plutôt que de conclure "ça marche" sans preuve).
4. **Revalider que `./forensic.sh -full-start` (ou au minimum les phases qu'il orchestre : build, health check global, `verify-platform-ready`) reste cohérent avec les changements faits sur les portails CERT/IT** — si l'orchestrateur fait des vérifications de contenu HTML/JS spécifiques (grep de version, de fichiers attendus, etc.), confirme qu'aucun renommage/déplacement de fichier fait pendant les passes UI ne casse ces vérifications.
5. Vérifier qu'aucun secret, mot de passe réel, ou donnée sensible propre à cette machine n'a été introduit en dur dans un fichier suivi par Git (les credentials doivent toujours passer par `.env`/les variables d'environnement, jamais en dur dans le JS/HTML).

## Intégration au rapport final du prompt QA

Ajoute une section dédiée dans le rapport final (`docs/CURSOR-PROMPT-QA-COMPLETE-FINAL.md`, §Rapport final) :

- **Portabilité** : résultat de la vérification ci-dessus, point par point, avec preuve (extrait de config, résultat du test sans `local-ports.env`, ou analyse de code si un test réel n'était pas possible).
- Si un problème de portabilité est trouvé : **c'est un point bloquant au même titre qu'un bug fonctionnel** — la recommandation finale "prêt pour push" ne doit être donnée que si ce point est réglé, pas seulement les bugs visuels/UI.

Le push vers `https://github.com/waraperkin/forensic-minimal` reste conditionné à la validation explicite de l'utilisateur sur le rapport complet (QA + portabilité), comme précisé dans le prompt QA.
