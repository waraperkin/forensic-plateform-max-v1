# 08 — Sekoia Extended Platform : état après les modules restants

**Commit `main`** : `0b143b8` · **Santé** : 16/16 · **Cluster** : green

## Modules livrés dans cette session

| Module | Preuve mesurée |
|---|---|
| **3.5 Inventory & Asset Management** | 161 incohérences détectées sur 66 sources, dérive à 0 changement fantôme, 6 instantanés, chronologie à 5 points |
| **3.9 Storage Layer** | 977 Ko sur 4 index, croissance réelle 847 Ko/j, équilibre projeté 65,7 Mo, rétention 3 paliers |
| **3.8 API Gateway** | 101 routes cataloguées en 34 groupes, quota 600 u/60 s, webhooks signés HMAC |

## Bugs corrigés

| Défaut | Impact réel |
|---|---|
| Snapshots lisant `inventory.items` | **0 intake capturé** dans chaque instantané → diffs vides, restauration sans objet. Après : 66 |
| Snapshots lisant `payload` au lieu de `rule_payload` | empreinte toujours nulle → aucune modification de règle détectable |
| Schémas de snapshot divergents entre mes deux écrivains | 5 « modifications » fantômes ; l'inventaire était pourtant stable sur trois passes |
| Dérive comparée au plus ancien instantané | affichait **1 246 changements** qui étaient l'artefact du bug ci-dessus. Après : 0 |
| Baselines empilées sans identifiant | **1 122 documents pour 66 intakes** ; le lecteur retenait un document arbitraire, potentiellement périmé. Après : 66 |
| `events_unattributed` négatif | « −6 événements non attribués » n'a aucun sens ; borné à 0, écart brut exposé à part |

## Constats remontés par la plateforme

**161 incohérences de configuration**, chacune avec l'action attendue :

- **61 intakes actifs sans connecteur** — ils donnent l'illusion d'une couverture
  qui n'existe pas et ne recevront jamais d'événement ;
- **29 formats ingérés sans aucune règle** — la donnée entre, rien ne la surveille ;
- **71 règles de détection désactivées**.

## Décisions assumées

**`sekoia-baselines` est protégé de toute expiration.** C'est un état courant
réécrit en place, pas une série temporelle : l'expirer ferait perdre les
références qui servent à détecter les dérives.

**La rétention supprime des index entiers, jamais des documents.** Sur des index
datés c'est immédiat et sans coût de merge, là où un `delete_by_query` laisserait
des documents marqués et un index de même taille.

**La dérive compare les deux instantanés les plus récents.** C'est la question
opérationnelle, et cela évite de comparer à un instantané dont le format a pu
changer — un champ apparu depuis se lirait comme un changement qui n'a jamais eu lieu.

**Les routes lourdes coûtent 5 unités de quota.** Une collecte volumétrique lance
66 jobs Sekoia : la facturer comme un GET de configuration serait mentir sur son coût.

**`/health` reste hors quota.** Une limite qui bloque la sonde de santé
transformerait une surcharge en panne déclarée.

**Le secret d'un webhook n'est restitué qu'à la création.** Ensuite il est masqué,
y compris pour son propriétaire.

## Validation

| Suite | Résultat |
|---|---|
| 10 vues du workbench | 0 FAIL |
| 8 écrans Sekoia historiques | 0 FAIL |
| 10 contrôles API des modules SEP | 0 FAIL |
| Tests unitaires Python | 115 passés |
| Tests unitaires JavaScript | 20 passés |

## Reste à faire

Deux modules SEP, dont l'essentiel est déjà couvert ailleurs :

- **3.1 Data Intake Layer** — les connecteurs et la normalisation relèvent de
  Sekoia lui-même ; ce que la plateforme pourrait ajouter est la détection de
  dérive de format et la remontée des erreurs de parsing.
- **3.3 Monitoring & Telemetry Core** — la supervision temps réel, les heatmaps
  et le suivi des sources sont déjà rendus par le tableau de bord et la vue
  Ingestion. Ce qui manque réellement est le suivi de LATENCE de livraison,
  qui exige une donnée que le SIEM n'expose pas encore.
