# 07 — PSOAR : implémentation complète (10 modules sur 10)

**Commit `main`** : `5603c18` · **Santé plateforme** : 16/16 · **Cluster** : green

## Couverture des modules

| Module de la spécification | État | Preuve |
|---|---|---|
| 3.1 Alert Intake & Correlation | livré | 161 alertes → 6 grappes, score décomposé, promotion idempotente (409) |
| 3.2 Incident Management Core | livré | escalade par 3 paliers idempotente, handoff avec consignes exigées, @mentions |
| 3.3 Playbook Orchestration | livré | branches, approbations bloquantes, journal, versioning |
| 3.4 Automation & Action Engine | livré | file, worker avec revendication serveur, retry exponentiel borné |
| 3.5 Case Management Layer | livré | artefacts typés, TLP, chaîne de possession non réécrivable |
| 3.6 Integration & Connector Hub | livré | 6 connecteurs sondés, capacités bloquées nommées |
| 3.7 Knowledge Base & Enrichment | livré | verdict CTI agrégé sur 4 référentiels |
| 3.8 Workflow Designer | livré | construction sans code, validation continue, 12 contrôles |
| 3.9 Audit, Compliance & Reporting | livré | conformité mesurée, export MD/CSV/JSON |
| 3.10 Storage & Indexing Layer | livré | mappings explicites, rétention bornée aux traces |

## Validation

| Suite | Résultat |
|---|---|
| 8 écrans Sekoia historiques | 0 FAIL |
| 9 vues du workbench | 0 FAIL |
| Console PSOAR (23 contrôles) | 0 FAIL |
| Orchestrateur | 0 FAIL |
| Concepteur de workflow (12 contrôles) | 0 FAIL |
| API : async, core, intake, enrich, case, hub | 52 contrôles OK |
| Tests unitaires Python | 115 passés |
| Tests unitaires JavaScript | 20 passés |

## Décisions de conception assumées

**La promotion automatique d'incidents est désactivée par défaut.** Un système
qui ouvre des dossiers sans qu'on le lui ait demandé noie l'équipe et perd sa
confiance. On propose, l'analyste dispose — sauf activation explicite avec seuil.

**L'escalade ne clôture ni ne réassigne jamais.** Elle élève la sévérité, trace
et notifie. Décider reste humain. La garantie est écrite dans le code et affichée
à l'écran.

**La chaîne de possession ne se réécrit pas.** Aucune route ne permet de
supprimer une entrée : une chaîne réécrivable n'a aucune valeur probante.

**Le handoff exige des consignes.** Un changement de propriétaire sans contexte
transmis n'est pas une passation, c'est un abandon.

**Absence de renseignement ≠ innocuité.** Un IOC inconnu répond « inconnu », avec
la mention explicite. Jamais « sain ».

**Pas de glisser-déposer dans le concepteur.** Sur un graphe d'exécution la
précision prime sur le geste : une cible mal reliée casse un run, un formulaire
explicite se relit et s'explique.

**La rétention ne touche ni les incidents ni les artefacts.** Seules les traces
d'exécution vieillissent. L'effacement d'un dossier relève de la purge gouvernée,
avec simulation puis confirmation.

## Constats réels remontés par la plateforme

- **TheHive et Cortex rejettent les identifiants fournis** (HTTP 401). Deux clés
  à renouveler. Le hub nomme les capacités bloquées : action playbook
  `thehive.case`, analyseurs Cortex dans l'enrichissement CTI.
- Le contrôle de conformité SLA est en échec : 1 incident ouvert hors délai.

## Défauts corrigés en cours de route

| Défaut | Nature |
|---|---|
| Snapshots Sekoia capturant 0 intake | mauvaise clé (`inventory.items` au lieu de `main_inventory`) — **reste ouvert, hors périmètre PSOAR** |
| IOC présent dans le TI local non trouvé | `ioc_value` mappé en keyword direct, l'inverse de la convention `sekoia-*` |
| Import circulaire `alerting` ↔ `app` | masqué en production, révélé à l'import direct |
| Test encodant l'ancien endpoint 404 | le test protégeait le bug |
| Fixture utilisant `payload` au lieu de `rule_payload` | même confusion de clés que le bug MITRE |

## Reste à faire hors PSOAR

Cinq modules de la Sekoia Extended Platform : 3.1 Data Intake, 3.3 Monitoring
temps réel, **3.5 Inventory & versioning** (les snapshots existants sont cassés,
diagnostic déjà posé), 3.8 API Gateway, 3.9 Storage tiers.

## Moteur de similarité et de récurrence

### La question à laquelle aucun outil ne répond
Devant un incident, un analyste se demande d'abord : **« est-ce déjà arrivé ? »**
XSOAR, TheHive et Resilient savent lier deux cas quand quelqu'un le fait à la
main. Aucun ne dit spontanément : ce schéma s'est produit trois fois, voici
comment il s'était terminé, et combien de temps il avait pris.

### Quatre signaux, de force décroissante

| Signal | Poids | Pourquoi ce rang |
|---|---|---|
| IOC partagé | 50 | seul signal désignant un objet du monde réel |
| Machine partagée | 25 | même périmètre |
| Étiquette partagée | 15 | même classification décidée par l'équipe |
| Intitulé proche | 10 | deux titres peuvent se ressembler sans rapport |

La courbe des IOC s'aplatit (logarithmique) : vingt indicateurs communs ne
valent pas vingt fois un seul, sinon un incident écraserait tous les autres.

Le rapprochement par titre exige **au moins deux termes significatifs**, après
retrait des mots vides du domaine — sans quoi « alerte », « suspect » et
« détection » rapprocheraient tout de tout.

### Ce que le moteur refuse de faire
Fabriquer une ressemblance. Un score n'est rendu que si un signal a **réellement
joué**, et il est toujours accompagné de ses raisons en clair. Un pourcentage
sans justification pousse un analyste à fermer un incident parce qu'un chiffre
le lui a suggéré.

La durée de résolution n'est calculée que sur un incident **clos** : sur un
incident ouvert, elle mesurerait l'âge et non le temps de traitement.

### Deux bugs trouvés sur le tenant réel
1. **Faux rapprochement par machine.** Le champ `host` vaut `{}` quand aucune
   machine n'est renseignée. Passé à `String()`, il donnait « [object Object] »
   — et **deux incidents sans machine étaient rapprochés au motif qu'ils
   partageaient la même**, avec un score de 25 affiché. Un faux rapprochement
   présenté avec un score est pire que pas de rapprochement du tout. Extraction
   corrigée pour toutes les formes du champ (chaîne, objet nommé, liste mixte).
2. **Collision de routes.** `/api/incidents/clusters` était capté par
   `/api/incidents/:id/...` enregistré plus tôt, qui traitait « clusters » comme
   un identifiant d'incident. Même piège que `/rules/{id}` côté control-plane.
   Route déplacée sur `/api/incident-clusters`.

Un troisième défaut relevait du **Dockerfile** : le nouveau module n'était pas
dans la liste des `COPY`, exactement le précédent documenté pour `volumetry.py`.
Le garde-fou en commentaire a été ajouté au Dockerfile du portail.

### Résultat sur le tenant
Trois incidents seulement, dont deux partagent des étiquettes. Le moteur les
rapproche avec ses raisons (« Étiquette(s) partagée(s) : auto-correlation,
sep-ingestion » · « Intitulés proches : intake, silent, alertes ») et **refuse**
de rapprocher le troisième, qui n'a rien en commun.

La démonstration reste modeste faute de corpus : sa valeur croîtra avec le
nombre d'incidents traités. La logique, elle, est vérifiée par 18 tests
unitaires portant autant sur ce que le moteur doit trouver que sur ce qu'il doit
refuser.
