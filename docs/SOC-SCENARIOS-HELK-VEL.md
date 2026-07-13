# Scénarios analyste — HELK + Velociraptor

Plateforme : `https://192.0.2.9` · cas lab par défaut : **CASE-001**

---

## Scénario 1 — Suspicion host Windows

**Contexte** : alerte EDR / ticket IT sur `lab-win01`, exfiltration suspecte.

### Étapes analyste (UI uniquement)

1. **CERT** → onglet Upload / cas → `CASE-001`, OS `windows`, host `lab-win01`.
2. **Velociraptor DFIR** :
   - Client : `C.xxxx` (lab-win01)
   - Artefact : `Custom.Windows.Sysmon.ForensicMinimal`
   - **Collecter via Velociraptor** (export auto)
3. **HELK Hunting** :
   - Host : `lab-win01` → **Ouvrir dans HELK**
   - **MITRE / Sigma** → dashboard détections
4. **Timeline Timesketch** → pivot depuis HELK ou VR export.
5. **Grafana** → `vraptor-windows` + `helk-hunts`.

### Résultat attendu

- Index `velociraptor-windows-*` peuplé
- Index `helk-sysmon-*` avec events host `lab-win01`
- Timeline Timesketch `CASE-001`
- Détections Sigma visibles (`helk-detections-*`)

---

## Scénario 2 — Suspicion Linux

**Contexte** : connexions SSH anormales sur `lab-linux01`.

1. **IT** → token cas → upload preuves (optionnel).
2. **IT dashboard** → **Voir endpoint dans HELK** → hostname `lab-linux01`.
3. **Velociraptor DFIR** → `Custom.Linux.Logs.ForensicMinimal` + collecte.
4. **OpenSearch Dashboards** → `_index:velociraptor-* AND host.name:lab-linux01`.
5. **Grafana** → `vraptor-linux`.

### Résultat attendu

- Logs auth/syslog dans HELK (`helk-linux-*`)
- Collecte VR indexée OpenSearch
- Pas d'erreur UI (Global Error Handler actif)

---

## Scénario 3 — Hunting global Sysmon

**Contexte** : campagne hunting Sigma / MITRE sur tout le lab.

1. **CERT** → **HELK Hunting** → **Hunting Overview** (Grafana).
2. Kibana HELK → dashboard MITRE / Sysmon (import `helk-full-dashboards.ndjson`).
3. **Sync OpenSearch** → bouton sync (bridge `helk-findings`, `helk-detections`).
4. Pivots :
   - IOC dans barre pivot → HELK Discover
   - Cas TheHive / OpenCTI si export CTI activé

### Vérification technique

```bash
python3 scripts/helk_velociraptor_analyst_verify.py
cd tests && BASE_URL=https://192.0.2.9 npx playwright test --config=playwright.config.ts \
  --project=ui-integration ui-helk.spec.ts ui-velociraptor.spec.ts ui-pivots.spec.ts
```

---

## Checklist analyste (sans CLI)

- [ ] Global Health : HELK + Velociraptor **OK**
- [ ] Onglet HELK Hunting : badge actif, pivots visibles
- [ ] Onglet Velociraptor DFIR : au moins 1 client lab online
- [ ] Collecte + export Timesketch testés sur CASE-001
- [ ] Grafana endpoint dashboards avec données
- [ ] Aucune erreur `[object Object]` / toast rouge non expliqué
