# Velociraptor — configuration DFIR complète (offline lab)

Plateforme : `https://192.0.2.9` · UI VR : `/velociraptor/app/` · Portail : `/?tab=velociraptor-dfir`

## Mode offline (lab)

Aucun agent live requis. Le simulateur `lab_collect.py` lit les jeux de données sous `velociraptor/lab-data/` et pousse les événements via le bridge (`/lab/collect`, `/lab/collect-full`) vers :

| Cible | Script | Index / destination |
|-------|--------|---------------------|
| CERT | `export_to_cert.py` | `forensic-uploads*` |
| IT | `export_to_it.py` | `velociraptor-endpoints` |
| OpenSearch | `export_to_opensearch.py` | `velociraptor-*` |
| Timesketch | `export_to_timesketch.py` | timeline sketch |
| HELK | `export_to_helk.py` | Logstash `:8080` |

## Phase 1 — Artefacts

### Officiels

```bash
cd velociraptor
./scripts/import-official-artifacts.sh
```

Copie les YAML upstream dans `artifacts/official/`. Le sidecar charge `--definitions /artifacts/official` puis `/artifacts/custom`.

### Custom ForensicFull

| Artefact | Données lab |
|----------|-------------|
| `Custom.Windows.Sysmon.ForensicFull` | `lab-data/windows/sysmon-full.jsonl` |
| `Custom.Windows.Registry.ForensicFull` | `lab-data/windows/registry-full.jsonl` |
| `Custom.Windows.Memory.Volatility` | `lab-data/windows/memory-volatility.json` |
| `Custom.Linux.Auth.ForensicFull` | `lab-data/linux/auth-full.jsonl` |
| `Custom.Linux.Network.ForensicFull` | `lab-data/linux/network-full.jsonl` |
| `Custom.Network.PCAP.ForensicFull` | `lab-data/network/pcap-summary.json` |

Artefacts **Minimal** conservés pour compatibilité.

## Phase 2 — Collecteur offline

```bash
# Un artefact
python3 velociraptor/scripts/lab_collect.py --artifact Custom.Windows.Sysmon.ForensicFull --case-id CASE-001

# Playbook complet (offline)
python3 velociraptor/scripts/lab_collect.py --playbook windows-triage-full --case-id CASE-001

# Via bridge (stack Docker)
python3 velociraptor/scripts/lab_collect.py --playbook ioc-sweeping --bridge http://127.0.0.1:8097
```

Collections persistées : `velociraptor/lab-collections/`.

Setup orchestré :

```bash
bash velociraptor/scripts/setup-full-config.sh
```

## Phase 3 — Playbooks

Voir [VELOCIRAPTOR-PLAYBOOKS.md](./VELOCIRAPTOR-PLAYBOOKS.md).

| ID playbook | Usage |
|-------------|--------|
| `windows-triage-full` | Sysmon + Registry + Memory |
| `linux-triage-full` | Auth + Network |
| `memory-forensics` | Volatility lab |
| `ioc-sweeping` | Multi-OS + PCAP |
| `network-forensics` | PCAP + Linux netstat |
| `persistence-hunting` | Registry + Sysmon |

Portail CERT : bouton **Collecte DFIR complète (offline)** + sélecteur playbook.

## Phase 4 — Exports

Bridge endpoints :

- `POST /export/full` — pipeline complet
- `POST /export/cert|it|opensearch|timesketch` — cible unique
- `POST /lab/collect` — un artefact offline + export
- `POST /lab/collect-full` — playbook offline + export

Proxy nginx : `/velociraptor/api/export/`, `/velociraptor/api/lab/`.

## Phase 5 — Dashboards

### Grafana (endpoint full)

- `/grafana/d/vraptor-windows-full/velociraptor-windows-full`
- `/grafana/d/vraptor-linux-full/velociraptor-linux-full`
- `/grafana/d/vraptor-network-full/velociraptor-network-full`
- `/grafana/d/vraptor-endpoint-full/velociraptor-endpoint-full`

### OpenSearch Discover

`_index:velociraptor-*`

## Phase 6 — Interconnexions

| Portail | Action | API |
|---------|--------|-----|
| CERT | Collecte DFIR complète | `POST /api/velociraptor/lab/collect-full` |
| CERT | Voir artefacts | `GET /api/velociraptor/lab/artifacts` + UI VR Artifacts |
| IT | Endpoint → artefacts VR | `GET /api/endpoints/velociraptor-artifacts?hostname=` |
| HELK | Export auto | via `export_to_helk` dans pipeline full |
| Timesketch | Timeline | via `export_to_timesketch` |

## Phase 7 — Tests

```bash
cd tests
BASE_URL=https://192.0.2.9 npx playwright test ui-integration/velociraptor-full-config.spec.ts
python3 ../scripts/velociraptor_full_config_verify.py
```

## Pivots analyste

1. CERT → Velociraptor DFIR → **Collecte DFIR complète**
2. OpenSearch `velociraptor-*` ↔ HELK `helk-*` (hostname / IP)
3. Timesketch timeline (export bouton ou auto_export)
4. Grafana dashboard `-full` par OS

## Rebuild stack

```bash
docker compose build velociraptor-bridge cert-portal it-portal
docker compose up -d velociraptor-bridge cert-portal it-portal nginx
cd velociraptor && docker compose -f docker-compose.velociraptor.yml up -d --build
```
