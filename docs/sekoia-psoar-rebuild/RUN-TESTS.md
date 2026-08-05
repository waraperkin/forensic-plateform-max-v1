# Exécuter les suites de tests

Les tests ne sont **pas** embarqués dans les images de production. On les
exécute depuis le dépôt, contre les conteneurs déjà déployés.

## Tests unitaires Python — control-plane Sekoia

```bash
cd /opt/forensic-plateform-max-v1
docker run --rm -v "$PWD/connectors/sekoia-controlplane:/w" -w /w --entrypoint sh \
  python:3.12-slim -c \
  "pip install -q -r requirements.txt pytest pytest-asyncio >/dev/null && python -m pytest -q"
```

## Tests unitaires JavaScript — PSOAR

```bash
cd /opt/forensic-plateform-max-v1
docker exec forensic-cert-portal mkdir -p /app/test
docker cp portal-cert/test/psoar.test.js forensic-cert-portal:/app/test/psoar.test.js
docker exec -w /app forensic-cert-portal node --test test/
```

## Suites d'interface (Playwright)

Depuis `tests/` — un script à la fois (ils se disputent le navigateur) :

| Script | Périmètre |
|---|---|
| `sep-ui.mjs` | console Cas d'usage CERT (96 cas, dashboards, gestion) |
| `sekoia-tool.mjs` | outil dédié `/sekoia` |
| `analyst-ui.mjs` | poste de travail analyste |
| `audit-ui.mjs` / `audit-fine.mjs` | journal des modifications |
| `legacy.mjs` | non-régression des écrans Sekoia historiques |
| `sagf-tab.mjs` / `sagf-all.mjs` | gouvernance SAGF |
| `stale-response.mjs` | réponses périmées / annulation |

```bash
cd /opt/forensic-plateform-max-v1
sudo node tests/sep-ui.mjs
```

## Gates statiques (sans navigateur)

| Script | Périmètre |
|---|---|
| `tests/scripts/i18n-keys-check.mjs` | clés i18n manquantes / orphelines |
| `tests/scripts/portability-gate-check.mjs` | aucune dépendance à des ports locaux |
| `tests/scripts/forensic-report-engine-smoke.js` | moteur de rapports forensic |
