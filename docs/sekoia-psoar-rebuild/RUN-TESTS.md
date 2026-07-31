# Exécuter les suites de tests

Les tests ne sont **pas** embarqués dans les images de production : elles restent
minimales. On les exécute en les copiant dans le conteneur.

## Tests unitaires Python — control-plane Sekoia (115 tests)

```bash
cd /opt/forensic-plateform-max-v1/connectors/sekoia-controlplane
docker exec -u root forensic-sekoia-controlplane pip install -q pytest pytest-asyncio
for f in test_app.py test_analytics.py test_sol.py test_sep_modules.py; do
  docker cp $f forensic-sekoia-controlplane:/tmp/$f
done
docker exec -u root -w /app forensic-sekoia-controlplane \
  python -m pytest /tmp/test_app.py /tmp/test_analytics.py /tmp/test_sol.py /tmp/test_sep_modules.py -q
```

`-w /app` est indispensable : lancés depuis `/tmp`, les modules ne sont pas sur
le chemin d'import.

Après la campagne, recréer le conteneur pour retrouver une image propre :
`docker compose up -d --no-deps --force-recreate sekoia-controlplane`

## Tests unitaires JavaScript — PSOAR (20 tests)

```bash
cd /opt/forensic-plateform-max-v1
docker exec forensic-cert-portal mkdir -p /app/test
docker cp portal-cert/test/psoar.test.js forensic-cert-portal:/app/test/psoar.test.js
docker exec -w /app forensic-cert-portal node --test test/
```

`express` n'étant présent que dans le conteneur, ces tests ne s'exécutent pas
depuis l'hôte.

## Suites d'interface (Playwright)

Depuis `/opt/forensic-sekoia-psoar-rebuild/` :

| Script | Périmètre |
|---|---|
| `legacy.mjs` | les 8 écrans Sekoia historiques |
| `wb.mjs` | les 9 vues du workbench |
| `validate-ui.mjs` | parcours transverse portail |
| `psoar-ui.mjs` | file, dossier, candidats corrélés, enrichissement |
| `pbo-ui.mjs` | orchestrateur et file d'exécution |
| `designer.mjs` | concepteur de workflow |
| `psoar-async.mjs` | file d'exécution asynchrone et reprise |
| `core.mjs` | assignation, passation, escalade SLA |
| `intake.mjs` | corrélation d'alertes et promotion |
| `enrich.mjs` | enrichissement CTI |
| `case.mjs` | artefacts, chaîne de possession, stockage |
| `hub.mjs` | connecteurs et rapports |

```bash
cd /opt/forensic-sekoia-psoar-rebuild && sudo timeout 500 node <script>.mjs
```

**Les lancer un par un.** Enchaînés dans une boucle, ils se disputent les
ressources du navigateur et échouent de façon trompeuse.
