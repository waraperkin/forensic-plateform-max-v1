"""Environnement de test posé avant tout import de module de test.

pytest collecte test_analyst.py avant test_analytics.py : le premier import
de app/analytics fige les constantes de chemin (WATCHLISTS_PATH, SNAPSHOTS_PATH,
TTP_NAMES_PATH, ...) sur leur défaut /data/..., non inscriptible sur un runner
CI. Ce conftest garantit des chemins /tmp quel que soit l'ordre de collecte —
les assignations identiques en tête des modules de test deviennent des no-ops.
"""
import os

os.environ.setdefault("INTERNAL_API_TOKEN", "test-internal-token")
# Couche données neutralisée par défaut : les tests existants vérifient des
# lectures fraîches après mutation d'état interne (monkeypatch) — un cache TTL
# intercalé les ferait mentir. test_dataplane.py réactive ses réglages en local.
os.environ.setdefault("SEKOIA_DP_TTL_S", "0")
os.environ.setdefault("SEKOIA_DP_TTL_HEAVY_S", "0")
os.environ.setdefault("SEKOIA_JOBS_PER_MINUTE", "100000")
os.environ.setdefault("SECRETS_PATH", "/tmp/test-sekoia-secrets.enc")
os.environ.setdefault("SEKOIA_DATA_PATH", "/tmp/test-sekoia-data.enc")
os.environ.setdefault("WATCHLISTS_PATH", "/tmp/test-sekoia-watchlists.json")
os.environ.setdefault("SNAPSHOTS_PATH", "/tmp/test-sekoia-snapshots.json")
os.environ.setdefault("TTP_NAMES_PATH", "/tmp/test-sekoia-ttp-names.json")
