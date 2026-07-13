# Scénarios analyste

Parcours opérationnels pour la plateforme FP-Master minimaliste. Cas lab par défaut : **CASE-001**, hosts : `lab-win01`, `lab-linux01`.

> **Livraison CERT — 7 scénarios validés E2E** : voir [FORENSIC-INVESTIGATION-GUIDE.md](./FORENSIC-INVESTIGATION-GUIDE.md) (`CASE-UC01-RANSOM` … `CASE-UC07-NETWORK`). Validation : `python scripts/cert_forensic_use_cases_e2e.py` — captures navigateur : `tests/artifacts/cert-analyst-7uc/`.

---

## 1. Incident 360°

**Objectif :** Traiter un incident de bout en bout (création → investigation → clôture).

### Étapes

1. **CERT** → **Incidents** → créer incident `CASE-001`, priorité High.
2. **Ingestion & Evidences** → upload EVTX/logs, case `CASE-001`, OS Windows.
3. Cocher **Envoyer vers HELK (hunting)** si hunting immédiat.
4. **HELK Hunting** → **Sync findings → OpenSearch** → vérifier détections.
5. **Velociraptor DFIR** → collecte offline ou live sur host concerné.
6. **Timeline Timesketch** → consolider chronologie.
7. **CTI** → export IOC (`Export IOC → CTI/IR`) → valider dans OpenCTI/MISP.
8. **TheHive** → créer/mettre à jour cas IR, joindre observables.
9. Clôturer incident master + article KB si procédure nouvelle.

### Fichiers / APIs

- `POST /api/master/incidents`
- `POST /api/upload`
- `POST /api/helk/sync`, `POST /api/helk/export-cti`
- `POST /api/velociraptor/lab/collect-full`

### Résultat attendu

- Indices `forensic-*`, `helk-*`, `velociraptor-*` peuplés
- Sketch Timesketch actif
- IOC dans OpenCTI
- Incident master status `closed`

---

## 2. Endpoint 360°

**Objectif :** Investigation complète d'un poste (`lab-win01`).

### Étapes

1. **HELK Hunting** → Host `lab-win01` → **Ouvrir dans HELK**.
2. Grafana → `helk-sysmon` — activité Sysmon 24h.
3. **Velociraptor DFIR** :
   - Playbook : `windows-triage-full`
   - **Collecte DFIR complète (offline)**
4. OpenSearch Dashboards : `_index:velociraptor-* AND host.name:lab-win01`.
5. Pivots → **MITRE / Sigma** pour techniques associées.
6. **Grafana** → `vraptor-windows-full`.

### APIs

- `GET /api/helk/hunt-url?host=lab-win01`
- `POST /api/velociraptor/lab/collect-full`

---

## 3. Threat 360°

**Objectif :** Traquer une menace via IOC (IP `203.0.113.50` exemple lab).

### Étapes

1. **CTI** → OpenCTI : rechercher IOC, contexte campagne.
2. **MISP** → corréler événements partagés.
3. **HELK** → champ IOC → **Ouvrir dans HELK**.
4. OpenSearch : corrélation sur `fp-ti-*` et `helk-detections`.
5. **Cortex** → analyser hash/IP via TheHive observable.
6. **Export IOC → CTI/IR** pour enrichir le graphe.

### Indices

- `fp-ti-opencti-*`, `fp-ti-misp-*`
- `helk-detections`

---

## 4. Hunting HELK

**Objectif :** Campagne hunting Sigma / MITRE sur données lab.

### Étapes

1. **HELK Hunting** → **Envoyer vers HELK (hunting)** (ingest lab).
2. Attendre fin ingest (`GET /api/helk/lab/status`).
3. Kibana HELK → dashboards MITRE / Sysmon.
4. **Sync findings → OpenSearch**.
5. Grafana : `helk-overview`, `helk-mitre`, `helk-detections`.
6. Affiner avec pivots host/IOC.

### Validation

```bash
python3 scripts/helk_full_config_verify.py
```

---

## 5. DFIR Velociraptor

**Objectif :** Collecte forensic structurée sans agent live (mode lab).

### Étapes

1. **Velociraptor DFIR** → sélectionner playbook `memory-forensics` ou `windows-triage-full`.
2. **Collecte DFIR complète (offline)**.
3. **Voir artefacts** → liste YAML custom.
4. **Export complet plateforme** → OpenSearch + MinIO.
5. **Créer timeline Timesketch depuis Velociraptor**.
6. GUI VR : `/velociraptor/` pour revue collections.

### APIs

- `GET /api/velociraptor/lab/artifacts`
- `POST /api/velociraptor/lab/collect-full`
- `POST /api/velociraptor/export/full`

---

## 6. Timeline Timesketch

**Objectif :** Construire et partager une timeline d'investigation.

### Étapes

1. Upload logs avec case `CASE-001` (import auto ingest-worker).
2. Ou export HELK : **Export HELK timeline vers Timesketch**.
3. Ou export VR : **Créer timeline Timesketch depuis Velociraptor**.
4. Ouvrir `/timesketch/` → sketch `CASE-001`.
5. Appliquer playbooks Timesketch (`config/timesketch/playbooks.json`).
6. Partager lien sketch à l'équipe IR.

### Fichiers

- `ingest-worker/timesketch_io.py`
- `helk_bridge.py` → `/export/timesketch`
- `velociraptor/export/export_to_timesketch.py`

---

## Matrice outils par scénario

| Scénario | CERT | HELK | VR | OS | TS | Grafana | CTI | TheHive |
|----------|------|------|----|----|----|---------| ----|---------|
| Incident 360° | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Endpoint 360° | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | — |
| Threat 360° | ✓ | ✓ | — | ✓ | — | ✓ | ✓ | ✓ |
| Hunting HELK | ✓ | ✓ | — | ✓ | — | ✓ | — | — |
| DFIR VR | ✓ | — | ✓ | ✓ | ✓ | ✓ | — | — |
| Timeline TS | ✓ | ✓ | ✓ | — | ✓ | — | — | — |

Documentation complémentaire : [`docs/SOC-SCENARIOS-HELK-VEL.md`](../SOC-SCENARIOS-HELK-VEL.md).
