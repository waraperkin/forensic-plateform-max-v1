# Artefacts officiels Velociraptor

Répertoire pour les définitions YAML upstream (Velocidex/velociraptor).

## Import (une fois, réseau requis)

```bash
cd /home/debian/Téléchargements/forensic-minimal/velociraptor
./scripts/import-official-artifacts.sh
```

Le script clone le dépôt Velociraptor (shallow) et copie les définitions depuis :

- `artifacts/definitions/` (structure officielle v0.76+)
- `artifacts/pro_definitions/` (fallback)

## Montage Docker

Le sidecar charge `--definitions /artifacts/official` puis `--definitions /artifacts/custom`.

En lab **offline**, seuls les artefacts **custom** + simulateur `lab_collect.py` sont requis ; l’import officiel enrichit l’UI Velociraptor (Hunt Manager) sans agent live.
