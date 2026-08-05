"""Tests unitaires inventaire Assets v2 (normalisation + query params)."""
from __future__ import annotations

import assets as am


def test_norm_asset_v2_flat():
    raw = {
        "uuid": "u1",
        "name": "HOST-01",
        "type": "host",
        "category": "server",
        "criticality": 90,
        "tags": ["prod", "dc"],
        "props": {"os": "windows"},
        "source": "manual",
        "reviewed": True,
        "revoked": False,
    }
    n = am._norm_asset(raw)
    assert n["uuid"] == "u1"
    assert n["type"] == "host"
    assert n["criticality"] == 90
    assert n["criticality_display"] == "high"
    assert n["os"] == "windows"
    assert n["tags_str"] == "prod, dc"


def test_norm_asset_v1_shape():
    raw = {
        "uuid": "u2",
        "name": "acc",
        "asset_type": {"name": "account"},
        "category": {"name": "user"},
        "criticity": {"value": 10, "display": "low"},
        "tags": [],
    }
    # v1 criticity key not used by _norm_asset — criticality absent → 0/info
    n = am._norm_asset(raw)
    assert n["type"] == "account"
    assert n["category"] == "user"


def test_list_params_filters():
    p = am._list_params({
        "limit": 50, "offset": 100, "search": "DC", "type": "host",
        "criticality": 80, "sort": "name", "direction": "asc",
        "also_search_in_tags": True,
    })
    assert p["limit"] == 50
    assert p["offset"] == 100
    assert p["search"] == "DC"
    assert p["type"] == "host"
    assert p["criticality"] == 80
    assert p["also_search_in_tags"] is True
