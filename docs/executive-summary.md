# Résumé exécutif — Forensic Minimal v2

**Destinataires :** direction, RSSI, responsables SOC / CERT  
**Objet :** livraison de la plateforme SOC/DFIR forensic-minimal-v2  
**Date :** 2026-07-17  
**Décision recommandée :** adoption pour lab CERT / formation / exploitation contrôlée

---

## En une page

Forensic Minimal v2 est une **plateforme SOC et DFIR clé en main**. Elle regroupe, derrière un seul accès HTTPS, l’ingestion d’evidences, le SIEM, le renseignement menace (CTI), la gestion d’incidents, les timelines forensiques et la collecte endpoint.

Une mission d’ingénierie **SHADOW OPS** a redéployé la plateforme depuis zéro, corrigé les défauts bloquants, validé les parcours analystes réels, puis livré la documentation d’exploitation.

**Résultat :** santé **16/16 services OK**, aucun service DOWN ou DEGRADED, workflows authentifiés validés, code et documentation poussés sur GitHub.

---

## Ce que la plateforme apporte métier

| Besoin métier | Réponse produit |
|---------------|-----------------|
| Centraliser les evidences CERT/IT | Portail CERT + portail IT (jetons) + MinIO |
| Détecter et chercher dans les logs | OpenSearch / Dashboards + HELK |
| Enrichir en threat intelligence | OpenCTI + MISP + sync SIEM |
| Gérer les incidents | TheHive + Cortex |
| Reconstruire une timeline | Timesketch |
| Collecter sur endpoints | Velociraptor |
| Piloter la santé SOC | Grafana + healthchecks portail (**16/16**) |

---

## Risques éliminés par la mission

| Risque initial | Traitement |
|----------------|------------|
| Déploiement non reproductible | Procédure zero-touch documentée (`preflight` + `-full-start`) |
| Outils « verts » sans preuve d’usage | Workflows authentifiés obligatoires (login + API + actions analystes) |
| Clés API MISP invalides à la génération | Génération hex conforme + reset admin synchronisé |
| Faux échecs de santé HELK / portail | Correctifs verify + import Kibana |
| Documentation éparpillée | Suite professionnelle unifiée dans `docs/` |

---

## Stabilité confirmée

- Redéploiement neuf sur VM Debian 13 validé.
- Cluster OpenSearch **green**.
- Portail CERT affiche **16 OK / 0 DEGRADED / 0 DOWN**.
- Script `verify-platform-ready.sh` : succès.
- Preuves techniques : `docs/SHADOW_OPS_REPORT.md`, `docs/SHADOW_OPS_MATRIX.json`.

---

## Conformité SOC / DFIR (lab)

La plateforme couvre les fonctions attendues d’un SOC/CERT de lab :

- **Collecte & chaîne de custody** (upload, checksum MinIO, cases).
- **Détection & hunting** (SIEM, HELK, Sigma, Velociraptor).
- **CTI** (OpenCTI/MISP, corrélation IOC).
- **IR** (TheHive/Cortex).
- **Traçabilité** (journaux d’activité portail, audit).

> Note : le certificat TLS lab est auto-signé. Un passage en production entreprise nécessite PKI interne, durcissement et rotation secrets (voir `hardening-plan.md`).

---

## Valeur

1. **Time-to-SOC réduit** : une commande d’orchestration au lieu de dizaines d’installations manuelles.
2. **Parcours analyste unifié** : un portail, des deep-links vers tous les outils.
3. **Formation accélérée** : scénarios et guides livrés (`training-plan.md`, `analyst-guide.md`).
4. **Maintenabilité** : guides d’exploitation, maintenance, migration et QA continu.

---

## Recommandation

**Valider la livraison** pour usage lab / CERT interne, et planifier :

1. Formation analystes (plan fourni).
2. Durcissement progressif si exposition hors lab.
3. Exécution du plan QA continu à chaque mise à jour.

**Conclusion management : la plateforme est stable, opérationnelle et prête à être exploitée par une équipe SOC/DFIR.**
