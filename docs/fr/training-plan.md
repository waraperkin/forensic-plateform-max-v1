# Plan de formation — Forensic Minimal v2

---

## 1. Publics et objectifs

| Public | Objectif |
|--------|----------|
| Analystes SOC L1 | Naviguer portail, triage, pivots SIEM/CTI |
| Analystes DFIR | Velociraptor, Timesketch, evidences |
| Ingénieurs plateforme | Deploy, verify, maintenance |
| Équipe CERT | Cases TheHive, jetons IT, rapports |
| Management | Lire executive-summary + delivery-report |

---

## 2. Formation analystes SOC (1 jour)

| Module | Durée | Contenu |
|--------|-------|---------|
| Portail CERT | 1 h | Login, 16/16, overview, deep-links |
| OpenSearch / Grafana | 2 h | Recherche, dashboards TI, IOC matches |
| MISP / OpenCTI | 1,5 h | Event, indicator, sync SIEM |
| TheHive / Cortex | 1,5 h | Case, observable, analyzer |
| Exercice A | 1 h | Alerte → case → enrichissement |
| Debrief | 0,5 h | Bonnes pratiques |

Supports : `analyst-guide.md`, `docs/PORTAL/SCENARIOS.md`.

---

## 3. Formation ingénieurs (1–2 jours)

| Module | Contenu |
|--------|---------|
| Architecture Docker | Compose, sidecars, nginx |
| Full-start | Preflight, logs, troubleshoot |
| Verify & QA | Scripts masters, cron health |
| Backup / restore | MinIO, OS, Postgres |
| Durcissement | hardening-plan (P0/P1) |
| Migration | dry-run staging |

Supports : `deployment-guide.md`, `operations-guide.md`, `maintenance-guide.md`.

---

## 4. Formation SOC (processus, ½ journée)

- Escalade L1→L2→Ops.
- KPIs monitoring.
- Playbooks Grafana / OpenSearch.
- Communication incident (TLP).

---

## 5. Formation CERT (½–1 jour)

- Jetons IT et chaîne IT→CERT.
- Upload evidences et Case ID.
- Rapports forensic portail.
- Coordination TheHive + MISP.
- Scénarios HELK/Velociraptor (`SOC-SCENARIOS-HELK-VEL.md`).

---

## 6. Exercices pratiques

### EX-01 — Smoke analyste

1. Login CERT.  
2. Upload fichier texte IOC.  
3. Ouvrir MISP, créer event avec l’IP.  
4. Créer case TheHive + observable.  
5. Job Cortex.  
6. Indicator OpenCTI.  
7. Vérifier présence docs TI dans OpenSearch.

### EX-02 — Timeline

1. Créer sketch Timesketch.  
2. Importer CSV lab.  
3. Rechercher IOC.  
4. Documenter finding.

### EX-03 — Endpoint

1. Ouvrir Velociraptor.  
2. Lancer collect / artifact custom.  
3. Vérifier dashboard Grafana `vraptor-endpoint`.

### EX-04 — Ops

1. Stopper nginx.  
2. Constater health.  
3. Remonter + verify PASS.

---

## 7. Scénarios d’incident (table-top + lab)

| Scénario | Outils |
|----------|--------|
| Phishing → malware hash | MISP, OpenCTI, TheHive, OS |
| Latéralisation Windows | HELK, VR, Timesketch |
| Exfil DNS | OS dashboards, Cortex |
| Evidence IT hors bande | Jetons IT, MinIO, CERT |
| Campagne APT IOC | OpenCTI connectors, TI sync |

Détails étendus : `docs/PORTAL/FORENSIC-INVESTIGATION-GUIDE.md`.

---

## 8. Évaluation

- Checklist EX-01 réussie sans aide.
- Verify script compris (ops).
- Rapport d’1 page rédigé après EX-01.

---

## 9. Planning type (équipe 6 personnes)

| Jour | Matin | Après-midi |
|------|-------|------------|
| J1 | SOC analystes | Exercices A/B |
| J2 | CERT + DFIR | EX-02 / EX-03 |
| J3 | Ingénieurs | Backup + EX-04 |

---

## 10. Matériel fourni

- `analyst-guide.md`
- `operations-guide.md`
- `full-manual.md`
- Captures `docs/PORTAL/SCREENS.md`
- Compte lab + Case ID d’entraînement

---

## Documentation associée

- [Résumé exécutif](executive-summary.md)
- [Message de livraison](delivery-message.md)
- [Guide analyste](analyst-guide.md)
- [Guide d'exploitation](operations-guide.md)
- [Guide de déploiement](deployment-guide.md)
- [Guide de maintenance](maintenance-guide.md)
- [Plan de QA continu](qa-continuous.md)
- [Plan de durcissement](hardening-plan.md)
- [Plan de monitoring](monitoring-plan.md)
- [Plan de migration](migration-plan.md)
- [Plan de formation](training-plan.md)
- [Manuel complet](full-manual.md)
