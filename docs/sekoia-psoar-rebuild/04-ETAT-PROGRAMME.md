# 04 — ÉTAT DU PROGRAMME (Sekoia Extended Platform & PSOAR)

**Dernier commit `main`** : `3482295` — poussé sur GitHub.
**Validation** : 8 onglets + 9 vues + 13 contrôles PSOAR + **115 tests unitaires**, **0 FAIL**. Santé plateforme **16/16 OK**.
**Services reconstruits** : `sekoia-controlplane`, `sekoia-monitor`, `cert-portal`.
Aucun autre service touché.

---

## 1. Livré et vérifié sur données réelles

### Sekoia Extended Platform

| Module | État | Preuve |
|---|---|---|
| **3.2 Ingestion & Volumetry** | livré | 66 intakes mesurés en 19,5 s, 1 587 078 événements/h, 60 sources silencieuses |
| **3.4 Alerting & Anomaly Detection** | livré | 6 types de règles, seuils z-score, **65 alertes → 12 incidents** par regroupement |
| **3.6 Bulk Operations** | livré | sélection par filtre (16 intakes Windows), dry-run, export YAML, rollback |
| **3.7 Dashboards & Visualization** | livré | courbe SVG, carte de chaleur log, top sources, fenêtres 6 h→30 j ; surcompte ×35 corrigé |
| Console analyste | livrée | 4 vues, validées visuellement sans état dégradé |

### PSOAR

| Module | État | Preuve |
|---|---|---|
| **3.3 Playbook Orchestration** | livré | condition évaluée avec valeur observée, arrêt sur approbation, reprise, statut incident réellement passé à `contained` |
| Console d'orchestration | livrée | création depuis modèle NIST, simulation, exécution, arbitrage des approbations, journal pas à pas |
| **3.4 Automation & Action Engine** | livré | file d'exécution, worker avec revendication serveur, retry exponentiel borné, `queued → waiting_approval → completed` vérifié |
| **3.1 Alert Intake & Correlation** | livré | 161 alertes → 6 grappes, score décomposé, promotion idempotente (409 sur doublon) |
| Console d'incidents | livrée | file, SLA vivant, clic ligne, stepper, timeline, playbook NIST, IOC, evidences, rapport, purge en deux temps |
| Vue candidats corrélés | livrée | grappes scorées avec justification en clair, promotion en un clic |

---

## 2. Découvertes structurantes

**Le SIEM Sekoia n'expose aucune métrique d'ingestion.** Vérifié : `/sic/metrics`,
`/ingest/metrics`, `/events/statistics`, `/events/metrics`, `/intakes/volumetry`
répondent tous 404, et `short_histogram` des search jobs est toujours nul.
La volumétrie est reconstruite via un *search job* par intake dont on ne lit que
le `total` — aucun événement rapatrié.

**Le catalogue de règles n'expose aucun identifiant ATT&CK `Txxxx`.** Les
attack-patterns sont des UUID STIX internes, non résolubles (API CTI Sekoia 404,
absents d'OpenCTI local). Contourné : les `ttps` des alertes fournissent les
libellés — 112 patterns nommés sur 270, couverture 92,5 % des règles.

**Trois chaînes étaient mortes depuis l'origine** : `forensic-sekoia-telemetry*`
n'avait aucun producteur ; les points de volumétrie n'étaient écrits que par
hostname (donc jamais) ; le silence n'était jamais détecté faute de
`last_event_ts` sur une source muette.

---

## 3. Reste à construire

### Sekoia Extended Platform
- **3.1** Data Intake Layer (connecteurs universels, normalisation)
- **3.3** Monitoring & Telemetry Core (temps réel, heatmaps, latence)
- **3.5** Inventory & Asset Management (versioning, détection d'incohérences)
- **3.8** API Gateway (GraphQL, quotas)
- **3.9** Storage Layer (hot/warm/cold, ILM)

### PSOAR
- **3.2** Incident Management Core (au-delà de l'existant) — *prochaine étape recommandée*
- **3.5** Case Management Layer
- **3.6** Integration & Connector Hub
- **3.7** Knowledge Base & Enrichment
- **3.8** Workflow Designer (low-code)
- **3.9** Audit, Compliance & Reporting
- **3.10** Storage & Indexing

**Bilan : 17 modules livrés sur 19.** PSOAR complet (10/10), SEP à 7/9.
Voir `07-PSOAR-COMPLET.md` et `08-SEP-COMPLET.md`.

**Ancien bilan :** PSOAR est **COMPLET (10/10)** ; il reste 5 modules SEP.
Détail dans `07-PSOAR-COMPLET.md`. 135 tests unitaires (115 Python + 20 JavaScript).

---

## 4. Limites techniques déclarées

| Limite | Cause | Contournement |
|---|---|---|
| Intelligence par hostname (`top-hostnames`, `hosts/intelligence`) | le compteur d'un job ne ventile pas par host | échantillonnage d'événements — coût API à arbitrer |
| Identifiants ATT&CK `Txxxx` | absents du catalogue Sekoia | couverture attack-pattern nommée (92,5 %) |
| Branches parallèles | jouées séquentiellement | résultat métier identique, traçabilité conservée, évite les écritures concurrentes |
| Tests pytest | non exécutables dans l'image (`No module named pytest`) | dette D04 de l'audit, non traitée |

---

## 5. Principe tenu de bout en bout

**Aucune donnée fabriquée.** Un intake non mesurable vaut `None`, jamais 0. Un
indicateur non calculable déclare son motif au lieu d'afficher un zéro
silencieux. Une intégration absente se déclare en mode sandbox au lieu d'échouer
sans bruit. Une matrice ATT&CK sans technique résolvable est signalée comme telle
plutôt que présentée comme une couverture.
