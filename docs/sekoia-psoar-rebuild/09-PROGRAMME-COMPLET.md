# 09 — Programme complet : 19 modules sur 19

**Commit `main`** : `7965c66` · **Santé plateforme** : 16/16 · **Cluster** : green

## Couverture

### Sekoia Extended Platform — 9/9

| Module | Preuve mesurée |
|---|---|
| 3.1 Data Intake Layer | parsing 100 % sur 500 événements, 3 dialectes, 0 mélange détecté |
| 3.2 Ingestion & Volumetry | 66 intakes mesurés en ~20 s, 61 silencieux identifiés |
| 3.3 Monitoring & Telemetry | latence p50 0,2 s · p90 0,9 s · p99 2,3 s, 0 source hors seuil |
| 3.4 Alerting & Anomaly Detection | 65 alertes → 12 incidents par regroupement |
| 3.5 Inventory & Asset Management | 161 incohérences, dérive à 0 changement fantôme |
| 3.6 Bulk Operations | sélection par filtre, dry-run, export YAML, rollback |
| 3.7 Dashboards & Visualization | courbes, heatmap logarithmique, fenêtres 6 h→30 j |
| 3.8 API Gateway | 101 routes cataloguées, quota, webhooks signés |
| 3.9 Storage Layer | 977 Ko sur 4 index, croissance 847 Ko/j, équilibre 65,7 Mo |

### PSOAR — 10/10

| Module | Preuve mesurée |
|---|---|
| 3.1 Alert Intake & Correlation | 161 alertes → 6 grappes, promotion idempotente (409) |
| 3.2 Incident Management Core | escalade 3 paliers idempotente, handoff avec consignes exigées |
| 3.3 Playbook Orchestration | branches, approbations bloquantes, journal, versioning |
| 3.4 Automation & Action Engine | file, worker à revendication serveur, retry exponentiel |
| 3.5 Case Management | artefacts typés, TLP, chaîne de possession non réécrivable |
| 3.6 Connector Hub | 6 connecteurs sondés, capacités bloquées nommées |
| 3.7 Knowledge Base & Enrichment | verdict CTI sur 4 référentiels |
| 3.8 Workflow Designer | construction sans code, validation continue |
| 3.9 Audit & Reporting | conformité mesurée, export MD/CSV/JSON |
| 3.10 Storage & Indexing | mappings explicites, rétention bornée aux traces |

## Interface

- **Sekoia Workbench** : 10 missions, montées sur les 8 écrans historiques.
- **PSOAR** : file d'incidents, dossier, candidats corrélés, orchestrateur,
  concepteur de workflow.
- Système de design commun, états dessinés, raccourcis clavier, volets latéraux.

## Validation

| Suite | Résultat |
|---|---|
| 10 vues du workbench | 0 FAIL |
| 8 écrans Sekoia historiques | 0 FAIL |
| Console PSOAR (23 contrôles) | 0 FAIL |
| Orchestrateur · concepteur | 0 FAIL |
| API SEP (10 contrôles) | 0 FAIL |
| API PSOAR (52 contrôles) | 0 FAIL |
| Tests unitaires Python | 115 passés |
| Tests unitaires JavaScript | 20 passés |

## Constats que la plateforme remonte sur votre tenant

| Constat | Où le voir |
|---|---|
| **61 intakes actifs sans connecteur** — couverture illusoire | Inventaire |
| **29 formats ingérés sans aucune règle** — la donnée entre, rien ne la surveille | Inventaire |
| **71 règles de détection désactivées** | Inventaire |
| **61 sources silencieuses sur 66** | Supervision |
| **TheHive et Cortex rejettent leurs identifiants** (HTTP 401) | Connector Hub |
| **1 incident ouvert hors délai** | Rapport de conformité |

## Bugs de fond corrigés au fil du programme

| Défaut | Impact réel |
|---|---|
| `forensic-sekoia-telemetry*` sans producteur | 6 moteurs analytiques vides depuis l'origine |
| `effectiveness` : `limit=1000` (max Sekoia 100) | 1 109 règles déclarées silencieuses à tort |
| SLO : agrégation `terms` sur champ `text` | HTTP 400 systématique |
| MITRE : lecture de `payload` au lieu de `rule_payload` | 0 technique détectée |
| `rule_detail` sur un endpoint inexistant | panneau de détail toujours vide |
| Snapshots lisant `inventory.items` | 0 intake capturé, diffs vides |
| Baselines sans identifiant | 1 122 documents pour 66 intakes, lecture arbitraire |
| Somme des volumétries > total global | « −6 événements non attribués » |
| Dictionnaire ATT&CK en mémoire seule | couverture à 0 après chaque redémarrage |
| `count_1h` sommé au lieu de maximisé | 61 M d'événements affichés au lieu de 1,7 M |

## Principes tenus de bout en bout

**Aucune donnée fabriquée.** Un intake non mesurable vaut `None`, jamais 0. Un
indicateur non calculable déclare son motif. Une source injoignable est annoncée.
Une absence de renseignement n'est jamais présentée comme une innocuité.

**Chaque automatisme dit ce qu'il ne fait pas.** L'escalade n'a jamais clôturé
ni réassigné. La promotion automatique d'incidents est désactivée par défaut.
La rétention ne touche ni les incidents ni les artefacts.

**Rien d'irréversible sans simulation préalable.** Opérations en lot, purge,
rétention, playbooks : tous se jouent à blanc d'abord.

## Reste ouvert

- **Clés TheHive et Cortex à renouveler** — deux capacités PSOAR bloquées.
- Identifiants ATT&CK `Txxxx` non résolubles : le catalogue Sekoia ne les expose
  pas, contourné par la couverture attack-pattern nommée à 92,5 %.
- Intelligence par hostname : le compteur d'un search job ne ventile pas par
  hôte ; nécessiterait un échantillonnage dédié.

## Surveillance par hôte et étiquetage en lot

### Pourquoi le niveau « hôte »
L'alerting existant raisonne par intake. Un intake porte souvent des dizaines de
machines — le relais `UFRPA4I004` en fronte jusqu'à vingt-cinq sur ce tenant.
Quand une seule cesse d'émettre, le total de l'intake bouge à peine et aucune
alerte ne part. C'est pourtant le cas qui compte : un serveur dont l'agent est
mort, ou qu'un attaquant a fait taire, disparaissait sans bruit.

### Méthode et sa limite
Sekoia n'expose aucun compteur par machine. On mesure une PART dans un
échantillon d'événements et on l'applique au total réel de l'intake, mesuré lui
par compteur. Le volume par hôte est donc une **estimation**, déclarée comme
telle dans chaque réponse et affichée avant les chiffres dans l'interface.

### Garde-fous
Un hôte absent d'un échantillon n'a pas cessé d'émettre : il n'a pas été tiré.
Quatre conditions doivent être réunies avant tout verdict de silence :

| Garde-fou | Raison |
|---|---|
| ≥ 3 relevés | sans historique, aucune normale à laquelle comparer |
| présent dans TOUS les relevés | sinon l'absence n'est pas un signal |
| ≥ 20 événements estimés | sous ce seuil, l'hôte est marginal |
| ≥ 15 tirages habituels | **le garde-fou décisif** |

Le dernier mérite d'être explicité. Le volume extrapolé peut être élevé alors
que l'échantillonnage ne voit l'hôte que six fois sur mille deux cents : ne pas
le tirer une fois est alors un événement de hasard ordinaire. La probabilité
d'une absence fortuite décroît avec le NOMBRE DE TIRAGES, pas avec le volume
qu'on en déduit. À quinze tirages, elle tombe à trois sur dix millions.

### Deux bugs trouvés en construisant ce module
1. **Fenêtres mélangées.** `_history()` ne filtrait pas sur la fenêtre. Un relevé
   de 30 min porte la moitié du volume d'un relevé d'1 h : le moteur a produit
   cinq « chutes de 70 % » qui n'étaient qu'un changement d'unité de mesure.
   Corrigé par un filtre sur `window`, et la cadence automatique fixe la fenêtre.
2. **Garde-fou fondé sur le mauvais chiffre.** Voir ci-dessus : la première
   version bornait sur le volume estimé, pas sur les tirages.

### Cadence
La surveillance tourne dans le poller à sa propre cadence (`HOST_INTERVAL_S`,
900 s par défaut) et non toutes les 60 s comme l'alerting par intake : chaque
passage lance un job de recherche Sekoia, là où l'alerting ne lit que des
compteurs déjà écrits. C'est ce cycle, et non l'ouverture d'un onglet, qui
construit l'historique.

### Étiquetage en lot
`tag_add`, `tag_remove` et `tag_set` sur les règles et les actifs (API v2, seule
version exposant `tags`). Les deux premiers sont **relatifs** : ils lisent les
étiquettes en place et n'écrasent pas celles qu'un autre outil aurait posées.
`tag_set` écrase, et porte ce nom pour qu'on sache ce qu'on fait en le
choisissant.

Un piège évité de peu : les lignes d'inventaire préfixent les champs — une règle
porte `rule_tags`, pas `tags`. Lire naïvement `tags` aurait renvoyé une liste
vide, et `tag_add` aurait alors écrit la seule étiquette demandée, **effaçant
toutes les autres** sur chaque règle du lot. La résolution d'alias est testée.

Les objets déjà conformes sont **ignorés sans appel API**, pour ne pas remplir le
journal d'audit Sekoia de modifications qui ne modifient rien ; ils sont comptés
séparément (`skipped`) et exclus du rollback, qui ne restaure que ce qui a
réellement changé.

Les actifs sont paginés jusqu'à `MAX_FETCH` (5 000) : s'arrêter à la première
page aurait donné une sélection silencieusement tronquée.

## Normalité horaire et corrélation avec les détections

### Calendrier de normalité
Comparer un lundi 14 h à un dimanche 3 h n'a pas de sens sur un parc à rythme
ouvré : la médiane globale d'un poste bureautique mélange ses heures de travail
et ses nuits, et toute nuit devient alors une « chute de 80 % ». La normale est
donc calculée par **créneau** — jour ouvré / week-end × heure, soit 48 cases.

Sept jours distincts auraient multiplié les cases par 3,5 sans rien apporter :
sur un parc d'entreprise, c'est l'opposition ouvré / week-end qui porte le
signal, pas le mardi contre le jeudi.

Échelle de repli, **toujours déclarée** dans la réponse et affichée dans l'UI :

| Niveau | Référence | Saisonnier |
|---|---|---|
| créneau | « jours ouvrés à 19 h » | oui |
| heure | « toutes journées à 19 h » | oui |
| globale | « profil horaire pas encore constitué » | **non** |

Un opérateur doit pouvoir distinguer « anormal par rapport aux lundis 14 h » de
« anormal par rapport à la moyenne de tout » — la seconde affirmation vaut
beaucoup moins. L'UI distingue aussi les *normales exploitables maintenant* des
*profils complets* (24 créneaux sur 48) : les confondre laissait lire « 0 profil
constitué » alors que six machines disposaient déjà d'une normale de créneau.

### Seuil de significativité adapté à chaque machine
Troisième bug de la même famille que les deux précédents, et le plus instructif.

La première version du détecteur de chute appliquait un seuil unique. Elle a
produit **neuf « chutes de 70 à 95 % »** sur des machines dont l'estimation
oscillait spontanément entre 544 et 3 707 sans qu'il se passe quoi que ce soit.

Cause : une estimation tirée de *n* échantillons porte une erreur relative de
l'ordre de 1/√n. Un hôte tiré 10 fois a ±32 % d'incertitude ; un hôte tiré 323
fois, ±6 %. Leur appliquer le même seuil revient à qualifier le bruit du premier
de panne.

Le moteur exige désormais que la chute dépasse **deux fois l'erreur
d'échantillonnage de la machine concernée**, en plus du ratio demandé. Le seuil
devient strict sur les hôtes peu tirés et sensible sur les hôtes bien tirés, et
chaque alerte porte son seuil de bruit pour être auditable.

Effet mesuré : **9 alertes → 4**, chacune concluante (par exemple 96,1 % de
chute pour un bruit de 28 %, sur 51 tirages habituels).

### Corrélation avec les détections
Une machine qui se tait le dimanche à 3 h est un rythme. La même machine qui se
tait vingt minutes après une alerte de détection la visant est le schéma d'un
attaquant qui coupe la journalisation. Le SIEM possède les deux informations et
ne les rapproche jamais.

La jointure se fait par **UUID d'actif**, jamais par nom : deux machines peuvent
porter le même nom court dans deux entités, et un rapprochement par nom
attribuerait à l'une l'alerte de l'autre. Le relevé par hôte conserve désormais
l'UUID de chaque machine (il ne gardait qu'un booléen, ce qui rendait la
corrélation impossible).

Trois verdicts distincts, et la distinction est le cœur du dispositif :

- **détection préalable** — une alerte a visé CETTE machine dans les 2 h ; au
  delà d'une urgence de 50, l'extinction est escaladée en `critical` : ce n'est
  plus un incident d'exploitation mais une piste d'investigation ;
- **même source** — une alerte a visé une AUTRE machine du même intake. Signal
  faible, nommé comme tel, et **il n'escalade pas** ;
- **non corrélable** — machine hors inventaire, donc sans UUID. Ce n'est pas
  l'absence d'alerte, c'est l'absence de moyen de la chercher, et les confondre
  laisserait croire à une machine tranquille.

### État sur le tenant
Le mécanisme est vérifié : les UUID des deux côtés se résolvent bien via la même
API d'actifs. Il n'y a **aucun recouvrement actuel** — les détections des
dernières 24 h visent d'autres actifs, dont des comptes utilisateurs
(`administrator`, `ssm-user`) et un lab distinct. Un diagnostic de joignabilité
est donc exposé en permanence, car « 0 corrélation » ne signifie pas « machines
tranquilles ».

La corrélation est validée par tests sur données construites, faute de pouvoir
l'être sur le tenant.

## Actionnabilité des vues et bascule FR/EN

### Le reproche : « une vitrine »
Les vues affichaient sans permettre d'agir. Toute opération d'écriture obligeait
à passer par l'onglet Opérations et à retrouver ses objets par filtre.

**Sélection de lignes** dans Sources et Détections, avec une barre d'actions :
activer, désactiver, ajouter ou retirer une étiquette. Le tout passe par le
**même moteur de lot** que l'onglet Opérations — simulation obligatoire,
historique, rollback. Une action lancée depuis un tableau ne doit pas être moins
sûre parce qu'elle est plus rapide d'accès.

La simulation est affichée avant l'application, avec l'état avant et après pour
chaque objet, et le nombre d'objets **déjà conformes** — sur lesquels aucune
écriture ne sera faite.

Détail qui compte : cocher une case ne doit pas ouvrir le volet de détail de la
ligne. Les cases sont donc traitées avant les actions de ligne, et c'est vérifié
par un test.

### La bascule FR/EN
Le workbench était **intégralement écrit en français dans le code**. Basculer en
anglais ne changeait donc rien : la traduction du portail (`translateDOM`) ne
sait agir que sur des attributs `data-i18n`, ce qui ne s'applique pas à du HTML
généré en JavaScript.

Deux mécanismes ont été ajoutés :

1. **Clés de dictionnaire** (`swb.*`) pour la navigation, les colonnes, les
   états et la barre de sélection — 68 clés, symétriques entre `fr.json` et
   `en.json`.
2. **Correspondance exacte** (`swbtx`, 124 entrées) pour les titres,
   sous-titres, libellés de KPI, filtres et champs de recherche, appliquée après
   rendu aux **seuls éléments de chrome**.

La correspondance est exacte et la table ne contient que des chaînes connues :
c'est ce qui garantit qu'aucune donnée du tenant — un nom de source, un hôte,
une entité — ne sera jamais réécrite par erreur. La passe ne descend jamais dans
les cellules de données.

Une chaîne interpolée (« Granularité {interval} ») échappe par nature à la
correspondance exacte et a reçu une clé à variable. C'est la limite de
l'approche, et elle se traite au cas par cas.

Le changement de langue **repeint sans recharger** : relancer les jeux de
données ferait repartir des jobs de recherche Sekoia pour un simple changement
de langue.

### Ce qui reste en français, et pourquoi
Le texte **analytique produit par le backend** — messages d'alerte, verdicts de
simulation, recommandations de couverture, notes de méthode — est rédigé en
français dans les modules Python. Il s'affiche donc en français même en mode
anglais.

Ce n'est pas un oubli : ces textes sont générés avec leurs variables et leur
nuance (« 247 règle(s) activée(s) sur 57 format(s) jamais ingéré(s) »), et les
traduire suppose de porter la génération elle-même, module par module. C'est un
chantier distinct, à décider.

Vérification : 8 vues contrôlées en anglais sur l'ensemble de leur chrome —
titres, sous-titres, panneaux, KPI, en-têtes et options de filtres.

## Satisfiabilité, valeur, et fin des « vitrines »

### Satisfiabilité — la question qu'aucun SIEM ne traite
La console dit quelles règles sont **activées**. Elle ne dit jamais lesquelles
peuvent **se déclencher**. Une règle Sigma teste des champs ; si aucune source
ingérée ne les produit, elle est verte, elle compte dans la couverture, et elle
ne tirera jamais.

Le moteur confronte les champs exigés par chaque règle aux champs réellement
observés dans les événements — schéma que Sekoia n'expose pas et qu'on établit
par échantillonnage.

**Sur ce tenant : 305 règles sont activées et ne peuvent pas se déclencher.**

La lecture inverse est plus actionnable : collecter `process.parent.name`
réactive 72 règles activées d'un coup.

| Discipline | Raison |
|---|---|
| ≥ 30 événements par format avant tout verdict négatif | sans volume, l'absence ne prouve rien |
| borne de fréquence rendue (règle de trois : < 3/n) | « absent de l'échantillon » n'est pas « absent du flux » |
| aucun verdict négatif dur sur une règle agnostique | un champ peut exister sur un format sans exister sur celui qui déclencherait la règle |

**Erreur trouvée et corrigée en construisant.** La première version déclarait
« non ingéré, confiance certaine » pour 319 règles dont les formats sont en
réalité collectés : un échantillon global est dominé par les sources bavardes.
Correction en deux temps — croisement avec l'inventaire des intakes, et
échantillonnage **ciblé** des formats que le tirage global ne voit pas.
Dialectes couverts 4 → 6, verdicts fermes 44,6 % → 52,3 %.

**Performance.** L'inventaire coûte 104 s ; il est mis en cache 30 min et
préchauffé par le poller — sans quoi le premier à le demander est l'écran, et il
expire. Cache vérifié iso-résultat (305 inertes dans les deux cas, 0,1 s).

### Volume contre valeur
Un SIEM compte les événements et les alertes, il ne les rapproche jamais.

- **2 sources ont produit 34 millions d'événements sans lever une seule
  alerte** — 54,9 % du volume ingéré.
- **Une seule règle produit 58 % de toutes les alertes** (concentration top 5 :
  66,4 %).

Mise en garde attachée au classement : « zéro alerte » ne veut pas dire
« inutile ». Une source d'accès peut ne jamais déclencher de règle et rester
indispensable à l'investigation. Le module classe, il ne recommande pas la
suppression.

### Fin des deux dernières « vitrines »
- **Alerting** : création et suppression de règles depuis l'interface. La
  suppression confirme en **nommant** la règle, plutôt qu'un « êtes-vous sûr ? »
  qu'on clique sans lire.
- **Inventaire** : chaque incohérence porte désormais une **remédiation
  exécutable** (61 intakes sans connecteur → désactivation ; 71 règles
  désactivées → réactivation), passant par le moteur de lot — donc simulée,
  historisée, annulable. La réserve du module est affichée **dans le volet**, à
  côté du bouton, pas en infobulle qu'on ne lit qu'après coup.

Là où l'automatisation n'a pas de sens, elle n'est pas proposée : rattacher un
connecteur suppose des identifiants propres à chaque source, et « activer des
règles » pour un format suppose de choisir lesquelles.

### Trois bugs de routage et de jointure
1. `/rules/satisfiability` était capté par la route dynamique `/rules/{id}`, qui
   partait interroger Sekoia avec l'identifiant « satisfiability ». Route
   déplacée hors de cet espace de noms.
2. Les alertes référencent l'uuid de l'**instance** de règle, pas celui du
   catalogue : ne chercher que par uuid renvoyait « 0 règle ayant tiré » sur
   3 000 alertes. Indexation par uuid **et** par nom.
3. Le formulaire de création lisait `types` alors que l'API renvoie `items` : la
   liste de types était vide et un type vide produisait un 400 opaque.

### Une anomalie que je n'ai pas su expliquer
Après création d'une règle, une relecture immédiate de la liste renvoie
parfois l'état antérieur — alors que le fichier et l'API directe concordent
(11/11 vérifié). Je n'ai pas isolé la cause dans le temps imparti.

L'affichage est donc rendu **autoritatif depuis la réponse de création**, qui
est la source la plus fiable dont on dispose à cet instant, et aucune relecture
n'est déclenchée derrière. Le symptôme visible par l'opérateur — croire que sa
création a échoué alors qu'elle a réussi — est supprimé. La cause reste ouverte
et mérite d'être reprise.

## Rejeu de règle et dérive de schéma

### Rejeu — la peur numéro un d'un SOC
Activer une règle, c'est parier. Personne ne sait combien d'alertes elle
produira avant de l'avoir activée, et découvrir le lendemain qu'elle en a levé
quatre mille est le scénario que tout le monde redoute. Résultat connu : on
n'active plus rien, et le catalogue se fige.

Le module traduit le motif Sigma en requête de recherche et le rejoue sur la
fenêtre demandée. **840 règles sur 1 180 (71,2 %) sont traduisibles.**

Le chiffre rendu compte des **événements**, pas des alertes : une règle de
corrélation regroupe, déduplique et applique une fenêtre, donc elle produira
moins d'alertes. C'est une **borne haute**, et chaque réponse le déclare —
présenter « 4 000 » comme un nombre d'alertes ferait renoncer à une règle qui
n'en aurait produit que douze.

Le traducteur **refuse** plutôt que d'approximer : regex, agrégations, seuils,
conditions non composables. Une traduction approximative silencieuse donnerait
un chiffre faux avec l'apparence d'un fait.

**Bug de mon analyseur, corrigé** : l'indentation des blocs était figée à deux
espaces. Des règles indentent autrement, leurs blocs étaient alors lus comme des
champs, et les « bloc de détection vide » ne venaient pas des règles mais de moi.

**Croisement avec la satisfiabilité**, et la distinction compte : la
satisfiabilité dit que les *champs* existent, le rejeu dit que les *valeurs* se
sont réellement produites. Une règle satisfiable peut rendre zéro au rejeu — elle
cherche `process.name: cmd.exe` sur un parc qui produit bien ce champ mais jamais
cette valeur. Le rejeu est le test le plus fort des deux, et les deux moteurs
concordent sur le tenant.

Mécanisme validé indépendamment : requête de contrôle `event.category:*` →
5 199 715 événements.

### Dérive de schéma — la panne qui ne prévient jamais
Une mise à jour de parseur, une option de journalisation décochée : un champ
cesse d'être peuplé. Les événements continuent d'arriver, la volumétrie ne bouge
pas, aucune alerte de collecte ne part — et les règles qui testaient ce champ
cessent de se déclencher. **La surveillance s'éteint sans que rien ne s'allume.**

Le module relève périodiquement le schéma réel de chaque format et compare. Quand
un champ disparaît, il **nomme les règles qui en dépendaient**.

Sur ce tenant, `process.command_line` est exigé par **84 règles activées** : sa
disparition les tuerait toutes d'un coup, aujourd'hui sans que personne le voie.

Trois garde-fous, les mêmes qu'ailleurs : aucun verdict sous 30 événements pour
un format ; présence exigée dans **tous** les relevés antérieurs ; champ couvrant
moins de 20 % des événements écarté. Une **baisse de couverture** est distinguée
d'une **disparition** : un champ qui passe de 100 % à 3 % n'a pas disparu, mais
les règles ne se déclencheront plus que trois fois sur cent.

### Une limite du tenant, découverte en testant
En validant ces moteurs, j'ai déclenché la **limitation de débit de l'API Sekoia
(HTTP 429)**. Chaque relevé lance des jobs de recherche qui comptent dans le
quota partagé du tenant — la même ressource que celle des analystes.

Deux conséquences intégrées au produit :
- en cas de 429, un inventaire **périmé est servi plutôt que rien**, avec son âge
  affiché : un schéma d'il y a deux heures vaut mieux qu'une page vide ;
- un inventaire périmé n'est **jamais persisté** comme relevé, sinon la ligne de
  base enregistrerait deux fois le même instant et masquerait une disparition.

La détection de dérive est prouvée par **15 tests unitaires** couvrant
disparition, dégradation, apparition et construction de la ligne de base. La
démonstration de bout en bout sur données vivantes a été **reportée** faute de
quota disponible — je préfère le dire que de la présenter comme faite.
