# Lab endpoints — HELK + Velociraptor

Plateforme : `https://192.0.2.9` · réseau lab `10.78.0.0/16`

## Vue d'ensemble

| VM | Rôle | IP suggérée | Agent | Logs vers HELK |
|----|------|-------------|-------|----------------|
| **lab-win01** | Windows 10/11 lab | 192.0.2.21 | Velociraptor + Sysmon | Winlogbeat → Logstash `:15514` |
| **lab-linux01** | Debian/Ubuntu lab | 10.78.0.22 | Velociraptor | Filebeat → Logstash `:15514` |
| **lab-zeek01** *(optionnel)* | Zeek / réseau | 10.78.0.23 | — | Zeek logs → Kafka/Logstash |

## Prérequis plateforme

```bash
cd /home/debian/Téléchargements/forensic-minimal
./scripts/helk_velociraptor_master_setup.sh
python3 scripts/helk_velociraptor_master_verify.py
```

HELK ES : `http://127.0.0.1:19200` · Kibana : `https://192.0.2.9/helk/kibana/`  
Velociraptor UI : `https://192.0.2.9/velociraptor/` · clients `:8001`

---

## VM Windows — lab-win01

### Sysmon

1. Copier `helk/config/lab/sysmon-config.xml` sur la VM.
2. Installer Sysmon (SwiftOnSecurity ou config lab) :

```powershell
sysmon64.exe -accepteula -i C:\lab\sysmon-config.xml
```

### Winlogbeat → HELK

1. Installer [Winlogbeat 7.x](https://www.elastic.co/downloads/beats/winlogbeat).
2. Copier `helk/config/lab/winlogbeat-lab.yml` → `C:\Program Files\Winlogbeat\winlogbeat.yml`.
3. Adapter `output.logstash.hosts` si l'IP publique diffère (`192.0.2.9:15514`).
4. Démarrer le service Winlogbeat.

**Vérification** : Kibana HELK → Discover → index `helk-sysmon-*` ou `helk-logs-*`.

### Agent Velociraptor

1. Copier `forensic-minimal/velociraptor/clients/client.config.yaml` sur la VM.
2. Télécharger le client Windows depuis l'UI Velociraptor (Build Windows MSI) ou binaire officiel.
3. Installer :

```powershell
.\velociraptor.exe --config client.config.yaml service install
.\velociraptor.exe --config client.config.yaml service start
```

4. Vérifier dans l'UI : client **online**, OS **windows**.

---

## VM Linux — lab-linux01

### Filebeat → HELK

1. Installer Filebeat 7.x.
2. Copier `helk/config/lab/filebeat-lab.yml` → `/etc/filebeat/filebeat.yml`.
3. `sudo systemctl enable --now filebeat`

Collecte : `/var/log/auth.log`, `/var/log/syslog`, journald.

**Vérification** : index `helk-linux-*` dans Kibana HELK.

### Agent Velociraptor

```bash
sudo cp client.config.yaml /etc/velociraptor.client.config.yaml
sudo ./velociraptor-*-linux-amd64 --config /etc/velociraptor.client.config.yaml service install
sudo systemctl start velociraptor_client
```

---

## VM Zeek (optionnel) — lab-zeek01

1. Déployer Zeek sur le segment lab.
2. Configurer l'envoi vers Kafka HELK (`helk-kafka:9092`) ou HTTP Logstash `:18080`.
3. Pipeline Logstash : `0050-zeek.conf` → index `helk-zeek-*`.

Fichier lab local : `helk/lab-sources/zeek-sample-conn.log` (ingestion simulateur).

---

## Collections planifiées (lab)

Sur le serveur Velociraptor :

```bash
cd forensic-minimal/velociraptor
bash scripts/setup-lab-scheduled-collections.sh
```

Artefact serveur : `Custom.Server.Lab.ScheduledCollections` — collecte toutes les **15 min** sur les clients lab.

---

## Pivots analyste (sans CLI)

| Action | Où |
|--------|-----|
| HELK hunting + MITRE | CERT → **HELK Hunting** → pivots |
| Collecte Velociraptor | CERT → **Velociraptor DFIR** → client + **Collecter** |
| Endpoint IT → HELK | IT → dashboard → **Voir endpoint dans HELK** |
| Export post-collecte | `./velociraptor/scripts/post-collection-export.sh CASE-001 Custom.Windows.Sysmon.ForensicMinimal` |

---

## Indices attendus

| Source | Index HELK / OpenSearch |
|--------|-------------------------|
| Sysmon Windows | `helk-sysmon-*` |
| Linux auth/syslog | `helk-linux-*` |
| Zeek | `helk-zeek-*` |
| Sigma détections | `helk-detections-*` |
| Sync portail | `helk-findings`, `helk-hunts` |
| Velociraptor export | `velociraptor-*` |

## Dépannage

| Symptôme | Action |
|----------|--------|
| Pas de logs HELK | `curl http://127.0.0.1:19200/_cat/indices/helk-*` · vérifier Logstash `:15514` |
| Client VR offline | pare-feu VM → `192.0.2.9:8001` · certificat client.config.yaml |
| Sigma vide | `docker logs helk-sigma-runner` · relancer `helk/scripts/setup-helk-full.sh sigma` |
