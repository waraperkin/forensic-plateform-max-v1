# Captures d'écran — portails & outils

Images de référence pour la documentation (`README.md`, `docs/PORTAL/`).

## Régénération

Prérequis : stack démarrée, Playwright installé dans `tests/`.

```bash
cd tests && npm install && npx playwright install chromium
cd ..
BASE_URL=https://localhost:8443 node scripts/capture-portal-screenshots.mjs
```

Sur VM AWS, remplacez `localhost:8443` par l'IP publique (`./forensic.sh urls`).

Les fichiers sont écrits dans :

| Dossier | Contenu |
|---------|---------|
| `portals/` | Onglets portail CERT + sections portail IT |
| `tools/` | Écrans de connexion / accueil des outils SOC (Grafana, MISP, HELK, etc.) |

Le manifeste machine-readable est `manifest.json` (horodatage, URLs, chemins relatifs).

## Index visuel

Voir [docs/PORTAL/SCREENS.md](../PORTAL/SCREENS.md) pour la galerie commentée.
