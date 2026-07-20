# Guide analyste SOC / DFIR — Forensic Minimal v2

**Public :** analystes SOC L1/L2, investigateurs DFIR, opérateurs CERT  
**Prérequis :** compte portail CERT (ou comptes outils) fournis par l’admin plateforme  
**Accès :** `https://<PUBLIC_HOST>/`

Les identifiants par défaut de lab sont dans `.env` / message de fin de `-full-start` (à changer hors lab).

---

## 1. Portail CERT — point d’entrée

### Connexion

1. Ouvrir `https://<PUBLIC_HOST>/login.html`.
2. S’authentifier (admin ou compte analyste).
3. Vérifier le bandeau santé : **16 OK / 0 DEGRADED / 0 DOWN**.

### Usages quotidiens

| Action | Où |
|--------|-----|
| Vue d’ensemble SOC | **Vue d’ensemble** |
| Déposer des evidences | **Upload evidences** / **Ingestion & Evidences** |
| Générer un lien IT | **Jetons IT** |
| Ouvrir un outil | **Centre d’accès** ou cartes deep-link |
| Suivre les incidents | **Incidents** |
| Consulter CTI agrégé | **Renseignement menace (CTI)** |
| Hunting HELK / VR | menus **HELK Hunting**, **Velociraptor DFIR** |

### Bonnes pratiques

- Toujours renseigner un **Case ID** à l’upload.
- Préférer les formats supportés (EVTX, Plaso, PCAP, CSV, JSONL, STIX…).
- Utiliser les deep-links plutôt que des URLs mémorisées hors portail (cohérence proxy).

---

## 2. Velociraptor — collecte endpoint

**URL :** `https://<PUBLIC_HOST>/velociraptor/`

### Parcours type

1. Se connecter (admin lab).
2. Vérifier les clients (ou mode lab sans client).
3. Ouvrir un **Artifact** (ex. custom `Custom.Linux.Logs.ForensicMinimal`).
4. Lancer une **collect** ou un **Hunt**.
5. Exporter / vérifier l’arrivée dans OpenSearch / Timesketch (selon pipelines lab).

### Fallback sans client

En lab, la collecte serveur / CLI reste valide pour valider la chaîne :

```bash
docker exec velociraptor-server \
  velociraptor --config /config/server.config.yaml \
  artifacts collect Generic.Client.Info --output /tmp/collect.zip
```

Voir aussi : `docs/VELOCIRAPTOR-PLAYBOOKS.md`, `docs/PORTAL/VELOCIRAPTOR.md`.

---

## 3. Timesketch — timelines

**URL :** `https://<PUBLIC_HOST>/timesketch/` (ou port dédié selon config)

### Parcours type

1. Login admin Timesketch.
2. Créer un **sketch** (nommer avec le Case ID).
3. Importer une timeline (CSV / Plaso / upload plateforme).
4. Rechercher un IOC (`ip`, `hash`, mot-clé).
5. Lancer analyzers (Sigma, MISP, etc.) si disponibles.
6. Documenter les findings dans le sketch / story.

---

## 4. MISP — partage CTI

**URL :** `https://<PUBLIC_HOST>/misp/`

### Parcours type

1. Login admin MISP.
2. **Event** → Nouveau (info = case / campagne).
3. Ajouter attributs : `ip-dst`, `sha256`, `url` (to_ids selon politique).
4. Vérifier corrélations / galaxies.
5. Exporter JSON / STIX pour pivot OpenCTI ou SIEM.

### API (analyste / automation)

```bash
curl -sk -H "Authorization: $MISP_ADMIN_API_KEY" -H "Accept: application/json" \
  "https://<HOST>/misp/servers/getVersion"
```

---

## 5. TheHive — cases IR

**URL :** `https://<PUBLIC_HOST>/thehive/`

### Parcours type

1. Login (analyste org `cert` recommandé pour créer des cases).
2. Créer un **Case** (titre, sévérité, TLP, tags).
3. Ajouter un **Observable** (IP, hash, domaine…).
4. Lier tâches / templates FP-Master.
5. Pivoter vers Cortex pour analyse, MISP/OpenCTI pour enrichissement.

> Sur TheHive 5, le préfixe applicatif `/thehive` est obligatoire derrière le proxy.

---

## 6. Cortex — analyzers / responders

**URL :** `https://<PUBLIC_HOST>/cortex/` (ou port admin selon config)

### Parcours type

1. Login admin / orgadmin.
2. Lister les **analyzers** disponibles.
3. Lancer un job (ex. IP publique) depuis Cortex ou depuis TheHive.
4. Relire le rapport et rattacher au case.

---

## 7. OpenCTI — graphe CTI

**URL :** `https://<PUBLIC_HOST>/cti/`

### Parcours type

1. Login admin OpenCTI.
2. Vérifier les **connectors** (actifs / erreurs).
3. Créer un **Indicator** (pattern STIX) ou importer STIX.
4. Naviguer entités / relations.
5. Contrôler la sync SIEM (`forensic-ti-opencti-*` dans OpenSearch).

GraphQL lab (chemin `/cti/graphql`) :

```bash
curl -sk -H "Authorization: Bearer $OPENCTI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ about { version } }"}' \
  "https://<HOST>/cti/graphql"
```

---

## 8. Workflows analystes typiques

### A. Alerte SIEM → case IR

1. OpenSearch Dashboards / Grafana : identifier l’alerte.
2. Extraire IOC.
3. Créer case TheHive + observables.
4. Enrichir MISP / OpenCTI.
5. Hunt Velociraptor / HELK si endpoints concernés.
6. Timeline Timesketch.
7. Rapport via portail (**Rapports forensic**).

### B. Evidence déposée par l’IT

1. Générer jeton IT depuis CERT.
2. IT upload via portail IT.
3. CERT voit l’ingest / case.
4. Parsing → OpenSearch / Timesketch.
5. Investigation + pivots CTI.

### C. Campagne CTI

1. Indicator OpenCTI / Event MISP.
2. Vérifier sync `forensic-ti-*`.
3. Dashboards TI (IOC matches, threat map).
4. Déclencher hunts / searches sur les IOC.

---

## 9. Exemple d’investigation (lab Shadow Ops)

**IOC :** `203.0.113.77`

1. MISP : event avec IP + hash + URL.
2. TheHive : case + observable IP.
3. Cortex : job analyzer sur IP.
4. OpenCTI : indicator STIX IPv4.
5. CERT : upload evidence liée au case.
6. Timesketch : recherche `SHADOW_IOC` / IP.
7. Grafana : dashboard Velociraptor Endpoint.

---

## 10. Bonnes pratiques

- Nommer cases / sketches / events avec le **même Case ID**.
- Respecter TLP / PAP.
- Ne jamais coller de secrets dans les tickets publics.
- Vérifier le proxy (`/misp`, `/thehive`, `/cti`, `/velociraptor`) avant de déclarer un outil « down ».
- Documenter les pivots (lien Timesketch, event MISP, case TheHive) dans le rapport final.

Documents liés : `docs/PORTAL/FORENSIC-INVESTIGATION-GUIDE.md`, `docs/PORTAL/SCENARIOS.md`, `docs/SOC-SCENARIOS-HELK-VEL.md`.

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
