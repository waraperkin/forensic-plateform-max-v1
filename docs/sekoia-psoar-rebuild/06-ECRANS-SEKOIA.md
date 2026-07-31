# 06 — Refonte des huit écrans Sekoia

**Commit** : `b12fbd8` sur `main`.
**Validation** : 9 vues workbench + 8 onglets historiques + 4 contrôles d'interaction — **0 FAIL**, 0 erreur console. Santé **16/16**.

## Décision d'architecture

Les huit entrées de la barre latérale étaient servies par du code hérité :
un monolithe de 2 386 lignes (Control Center), 1 771 lignes (Threat Platforms)
et cinq satellites, sans système commun.

Plutôt que de repolir huit écrans séparément — ce qui aurait produit huit écrans
un peu moins mauvais, toujours sans cohérence — **chaque entrée monte désormais
le socle premium sur sa mission**.

| Entrée de la barre latérale | Vue du socle |
|---|---|
| Sekoia Control Center | `overview` |
| Sekoia.IO — Ingest logs & Volumétrie | `ingestion` *(nouvelle)* |
| Sekoia.IO — Assets & Sources | `sources` |
| Sekoia.IO — Rules & Detections | `detections` |
| Sekoia.IO — On-demand Telemetry | `telemetry` |
| Sekoia.IO — API Keys | `apikeys` |
| Centre d'audit | `audit` |
| Configuration plateformes | `config` |

Les onglets Sekoia étant des panneaux exclusifs, un **socle unique se remonte**
dans le conteneur actif plutôt que d'instancier neuf consoles concurrentes.
La barre de navigation interne n'apparaît que sur l'onglet Sekoia Extended
Platform : ailleurs, la barre latérale joue déjà ce rôle.

## Vue Ingestion — nouvelle

- Volume, **part du total**, tendance en sparkline et **écart à la baseline**,
  source par source, triables par colonne.
- Indicateur de **concentration** (part de la première source) : signale une
  dépendance excessive à une seule origine.
- Deux blocs distincts pour les sources sans trafic (voir ci-dessous).

## Contradiction levée

La première capture montrait `CERT - Forensic-Plateform - AWS` **en tête du
volume avec 1 091 716 événements ET dans les sources muettes**.

Les deux mesures étaient justes : `silent` porte sur le **dernier relevé**, le
volume sur **toute la fenêtre**. Leur juxtaposition muette ne l'était pas.

Désormais deux blocs séparés :

| Bloc | Signification | Lecture opérationnelle |
|---|---|---|
| **Collecte interrompue** | a émis sur la fenêtre, muette au dernier relevé | signal le plus urgent — une source qui produisait vient de se taire |
| **Sources sans aucun volume** | rien sur toute la fenêtre | intake configuré mais jamais alimenté, ou arrêté de longue date |

La colonne Écart affiche **« arrêtée »** plutôt que « −100 % » quand le relevé
courant est nul avec une baseline non nulle : −100 % se lit comme une baisse
ordinaire, un arrêt est autre chose. Une sparkline entièrement nulle affiche
**« aucun volume »** au lieu d'une ligne plate qui se confond avec une courbe.

## Incident de développement

Un retrait des chapeaux redondants par expression régulière a emporté des
éléments dont `cert-app.js` dépend (`renderQ` écrivait sur un nœud nul) et cassé
la page — 7 onglets en échec. Revert immédiat, puis correction ciblée sur le
seul nœud fautif (`sekoia-hub-root`, qui empilait l'ancien hub au-dessus du
socle). C'est la validation visuelle systématique qui l'a détecté.
