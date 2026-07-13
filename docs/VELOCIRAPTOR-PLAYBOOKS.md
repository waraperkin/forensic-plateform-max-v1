# Velociraptor — Playbooks DFIR complets (offline lab)

Accès UI : `https://192.0.2.9/velociraptor/app/` · portail : `/?tab=velociraptor-dfir`

> Configuration complète : [VELOCIRAPTOR-FULL-CONFIG.md](./VELOCIRAPTOR-FULL-CONFIG.md)

## Contraintes lab

- **Aucune collecte live obligatoire** — utiliser le simulateur offline.
- Agents réels optionnels (VM lab) ; sans agent → playbooks via `lab_collect.py` ou bouton portail.

## Artefacts

### ForensicFull (offline + live)

| Artefact | OS | Contenu |
|----------|-----|---------|
| `Custom.Windows.Sysmon.ForensicFull` | Windows | Sysmon EID 1,3,7,8,10,11,13,22 + lab JSONL |
| `Custom.Windows.Registry.ForensicFull` | Windows | Run keys, services, Winlogon |
| `Custom.Windows.Memory.Volatility` | Windows | pslist, netscan, malfind (lab) |
| `Custom.Linux.Auth.ForensicFull` | Linux | auth.log, secure, journald |
| `Custom.Linux.Network.ForensicFull` | Linux | connexions enrichies |
| `Custom.Network.PCAP.ForensicFull` | Tous | flux PCAP, alertes DNS |

### ForensicMinimal (legacy)

| Artefact | OS |
|----------|-----|
| `Custom.Windows.Sysmon.ForensicMinimal` | Windows |
| `Custom.Windows.EventLogs.ForensicMinimal` | Windows |
| `Custom.Linux.Logs.ForensicMinimal` | Linux |
| `Custom.Network.PCAP.ForensicMinimal` | Tous |

---

## Playbook 1 — Windows triage complet

**ID** : `windows-triage-full`  
**Objectif** : processus, persistance registry, mémoire, Sysmon.

1. Portail CERT → **Velociraptor DFIR** → playbook **Windows triage complet**.
2. **Collecte DFIR complète (offline)** — export auto vers CERT/IT/OS/TS/HELK.
3. Pivots :
   - Grafana `vraptor-windows-full`
   - OpenSearch `_index:velociraptor-windows-*`
   - HELK (Sysmon host lab-win01)
   - Timesketch timeline

**CLI** :

```bash
python3 velociraptor/scripts/lab_collect.py --playbook windows-triage-full --case-id CASE-WIN-001
```

Artefacts live (si agent Windows) : `Windows.Sys.Pslist`, `Windows.Network.NetstatEnriched`.

---

## Playbook 2 — Linux triage complet

**ID** : `linux-triage-full`  
**Objectif** : auth, sudo, connexions réseau.

1. Playbook **Linux triage complet** → offline lab `lab-linux01`.
2. Dashboard Grafana `vraptor-linux-full`.
3. IT portail → **Voir artefacts Velociraptor** (hostname endpoint).

**CLI** :

```bash
python3 velociraptor/scripts/lab_collect.py --playbook linux-triage-full --case-id CASE-LIN-001
```

Compléments live : `Linux.Sys.Pslist`, `Linux.Sys.Crontab`, `Linux.Ssh.AuthorizedKeys`.

---

## Playbook 3 — Memory forensics

**ID** : `memory-forensics`  
**Objectif** : analyse mémoire Volatility (lab dump simulé).

1. Artefact `Custom.Windows.Memory.Volatility`.
2. Corréler processus injectés (malfind) avec Sysmon EID 8/10.
3. Export Timesketch pour timeline processus.

```bash
python3 velociraptor/scripts/lab_collect.py --playbook memory-forensics --case-id CASE-MEM-001
```

---

## Playbook 4 — IOC sweeping

**ID** : `ioc-sweeping`  
**Objectif** : balayer IOC multi-plateforme (Sysmon, auth, PCAP DNS).

1. Playbook **IOC sweeping** (3 artefacts cross-OS).
2. OpenSearch : `velociraptor-* AND malicious.lab.local`
3. HELK + Zeek si lab-zeek01 actif.

```bash
curl -sk -X POST https://192.0.2.9/api/velociraptor/lab/collect-full \
  -H 'Content-Type: application/json' \
  -d '{"playbook":"ioc-sweeping","case_id":"CASE-IOC-001"}'
```

---

## Playbook 5 — Network forensics

**ID** : `network-forensics`  
**Objectif** : PCAP lab, flux TCP/UDP, alertes IDS.

1. `Custom.Network.PCAP.ForensicFull` + `Custom.Linux.Network.ForensicFull`.
2. Grafana `vraptor-network-full`.
3. Corrélation HELK Zeek : `_index:helk-zeek-* OR velociraptor-network-*`.

---

## Playbook 6 — Persistence hunting

**ID** : `persistence-hunting`  
**Objectif** : clés Run, services, événements Sysmon registry (EID 13).

1. Registry Full + Sysmon Full.
2. Filtrer `Updater`, `SuspiciousSvc` dans OpenSearch.
3. Pivot TheHive/Cortex via export full si cas IR ouvert.

---

## Exports plateforme

| Destination | Endpoint | Index |
|-------------|----------|-------|
| CERT | `/velociraptor/api/export/cert` | `forensic-uploads*` |
| IT | `/export/it` | `velociraptor-endpoints` |
| OpenSearch | `/export/opensearch` | `velociraptor-*` |
| Timesketch | `/export/timesketch` | sketch |
| HELK | pipeline `export/full` | Logstash |

**Export complet offline** :

```bash
curl -sk -X POST https://192.0.2.9/velociraptor/api/lab/collect-full \
  -H 'Content-Type: application/json' \
  -d '{"playbook":"windows-triage-full","case_id":"CASE-001","auto_export":true}'
```

---

## Grafana & OpenSearch

| Dashboard | URL |
|-----------|-----|
| Windows Full | `/grafana/d/vraptor-windows-full/velociraptor-windows-full` |
| Linux Full | `/grafana/d/vraptor-linux-full/velociraptor-linux-full` |
| Network Full | `/grafana/d/vraptor-network-full/velociraptor-network-full` |
| Endpoint Full | `/grafana/d/vraptor-endpoint-full/velociraptor-endpoint-full` |

OpenSearch : `_index:velociraptor-*`

---

## Vérification

```bash
python3 scripts/velociraptor_full_config_verify.py
bash velociraptor/scripts/setup-full-config.sh
```
