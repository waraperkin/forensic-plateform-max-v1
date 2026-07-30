"""SEKOIA EXTENDED PLATFORM — mappings OpenSearch explicites.

Les index `sekoia-*` étaient jusqu'ici créés par mapping dynamique : les
identifiants (`intake_uuid`, `log_hostname`…) devenaient du `text`, sur lequel
toute agrégation `terms` échoue en HTTP 400. C'est ce qui cassait le SLO et
l'intelligence des hosts.

On déclare donc des templates explicites. Convention retenue : identifiants en
`text` + sous-champ `.keyword`, identique au mapping dynamique historique — de
sorte que les index déjà peuplés (sekoia-intakes-*, 18 282 documents) restent
interrogeables sans réindexation.
"""
from __future__ import annotations

import logging

import httpx

log = logging.getLogger("sekoia-mon")

_ID = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}

TEMPLATES: dict[str, dict] = {
    "sekoia-volumetry": {
        "index_patterns": ["sekoia-volumetry-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0,
                         "refresh_interval": "30s"},
            "mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "intake_uuid": _ID,
                "intake_name": _ID,
                "intake_status": _ID,
                "intake_format_name": _ID,
                "entity_name": _ID,
                "connector_name": _ID,
                "log_hostname": _ID,
                "window": {"type": "keyword"},
                "count_1h": {"type": "long"},
                "intake_count_1h": {"type": "long"},
                "measured": {"type": "boolean"},
                "silent": {"type": "boolean"},
            }},
        },
    },
    "sekoia-baselines": {
        "index_patterns": ["sekoia-baselines"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {"properties": {
                "intake_uuid": _ID,
                "intake_name": _ID,
                "baseline_avg": {"type": "double"},
                "baseline_std": {"type": "double"},
                "samples": {"type": "integer"},
                "updated_at": {"type": "date"},
            }},
        },
    },
    "sekoia-intakes": {
        "index_patterns": ["sekoia-intakes-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "intake_uuid": _ID,
                "intake_name": _ID,
                "intake_format": _ID,
                "intake_format_name": _ID,
                "intake_status": _ID,
                "entity_name": _ID,
                "connector_name": _ID,
                "current_count": {"type": "long"},
                "baseline_avg": {"type": "double"},
                "drop_ratio": {"type": "double"},
                "last_event_ts": {"type": "date"},
                "silent": {"type": "boolean"},
                "volume_available": {"type": "boolean"},
                "hostnames_count": {"type": "integer"},
            }},
        },
    },
}


async def ensure_templates(client: httpx.AsyncClient, os_url: str, auth) -> dict:
    """Pose les index templates. Idempotent — rejouable à chaque démarrage."""
    result = {"applied": [], "failed": {}}
    for name, body in TEMPLATES.items():
        try:
            r = await client.put(f"{os_url}/_index_template/{name}", json=body,
                                 auth=auth, timeout=20)
            if r.status_code < 300:
                result["applied"].append(name)
            else:
                result["failed"][name] = f"HTTP {r.status_code}: {r.text[:160]}"
        except httpx.HTTPError as exc:
            result["failed"][name] = f"{type(exc).__name__}: {exc}"
    if result["failed"]:
        log.warning("index templates en échec: %s", result["failed"])
    else:
        log.info("index templates posés: %s", ", ".join(result["applied"]))
    return result
