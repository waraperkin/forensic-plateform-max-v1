# Restructuration monorepo — 2026-06-11

## Backup (Phase 1)

**Emplacement :** `/home/debian/Téléchargements/forensic-minimal-backup-20260611-105442/`

| Source | Fichiers | Vérification |
|--------|----------|--------------|
| `forensic-minimal/` | 2795 | OK (match 100 %) |
| `helk/` (sibling) | 5506 | OK (match 100 %) |
| `docker-volumes.txt` | inventaire volumes | inclus |
| `docker-containers.txt` | état conteneurs | inclus |
| `forensic-minimal.env` | copie `.env` | inclus |
| `INVENTORY-PHASE2.md` | inventaire dossiers | inclus |

## Inventaire (Phase 2)

Seul dossier stack **hors** `forensic-minimal/` : **`helk/`** (sibling).

Déjà dans `forensic-minimal/` : `velociraptor/`, `config/` (timesketch, opencti, misp, cortex, thehive, grafana, nginx…), `dashboards/`, scripts, portails, tests.

**Non touché :** `fp-final2/`, `plaso-20260512/`, archives zip.

## Restructuration (Phase 3)

```bash
mv /home/debian/Téléchargements/helk /home/debian/Téléchargements/forensic-minimal/helk
```

## Chemins mis à jour (Phase 4)

| Fichier | Changement |
|---------|------------|
| `docker-compose.yml` | `../helk/*` → `./helk/*` |
| `scripts/helk_velociraptor_master_setup.sh` | `HELK_ROOT="$ROOT/helk"` |
| `scripts/helk_full_config_verify.py` | `HELK = ROOT / "helk"` |
| `helk/scripts/setup-helk-full.sh` | `FM="$(dirname "$ROOT")"` |
| `helk/scripts/setup-helk-analyst.sh` | idem |
| Docs `docs/PORTAL/*`, inventaire portail | `../helk/` → `helk/` |

**Non modifiés :** APIs, backends Node, pivots SOC (`soc-pivot-links.js`), tests Playwright, `fp-final2`.

## Validation post-rebuild

- `/api/health/global` : **0 DOWN**, 1 DEGRADED (OpenSearch cluster)
- `helk_full_config_verify.py` : OK (chemins `helk/` résolus)
- Nginx : healthy après démarrage stack HELK + bridges
- Playwright : **180/189** pass (échecs transitoires nginx/HELK pendant rebuild long)

## Restauration depuis backup

```bash
./forensic.sh stop
rm -rf /home/debian/Téléchargements/forensic-minimal/helk
rsync -a /home/debian/Téléchargements/forensic-minimal-backup-20260611-105442/helk/ /home/debian/Téléchargements/helk/
# Restaurer forensic-minimal depuis backup si nécessaire
```
