# HELK lab sources (safe — pas d'ingestion live)

Fichiers d'exemple pour le simulateur `scripts/lab_ingest.py`.

| Fichier | Type | Index cible |
|---------|------|-------------|
| `sysmon-sample.jsonl` | Sysmon (JSON lab) | `helk-sysmon-*` |
| `windows-security.jsonl` | Windows Security | `helk-windows-*` |
| `linux-auth.log` | Auth SSH | `helk-linux-*` |
| `linux-syslog` | Syslog | `helk-linux-*` |
| `zeek-sample-conn.log` | Zeek conn JSON | `helk-zeek-*` |

Les fichiers `.evtx` réels ne sont pas requis : le simulateur envoie des événements JSON pré-parsés via HTTP Logstash (port **18080** uniquement).

```bash
python3 scripts/lab_ingest.py
# ou depuis forensic-minimal :
./forensic.sh helk-lab-ingest
```
