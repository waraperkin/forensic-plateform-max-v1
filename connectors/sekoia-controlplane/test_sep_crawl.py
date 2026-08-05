"""Tests du parcours d'actifs — la mécanique qui doit tenir à cent fois l'échelle.

Ce qui est protégé ici n'est pas la vitesse mais l'EXHAUSTIVITÉ. Un parcours
paginé se trompe en silence : il ne lève rien, il saute simplement des objets
qui n'apparaîtront jamais nulle part. Chaque test ci-dessous correspond à une
manière précise de perdre des actifs sans s'en apercevoir.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import app  # noqa: F401  (sep_crawl fait `import app as cp`)
import sep_crawl as crawl


def _asset(uuid: str, created: str, atype: str = "account") -> dict:
    return {"uuid": uuid, "name": uuid, "type": atype, "created_at": created,
            "criticality": 0, "tags": []}


def _kind(_asset_dict) -> str:
    return "test"


class FauxAPI:
    """Une API d'actifs qui respecte les contraintes mesurées sur le tenant."""

    def __init__(self, assets: list[dict]):
        self.assets = assets
        self.calls: list[dict] = []

    async def __call__(self, method, path, params=None, **kw):
        p = dict(params or {})
        self.calls.append(p)
        rows = [a for a in self.assets
                if not p.get("type") or a["type"] == p["type"]]
        rows.sort(key=lambda a: a["created_at"],
                  reverse=p.get("direction") == "desc")
        off = int(p.get("offset") or 0)
        lim = int(p.get("limit") or 100)
        return {"items": rows[off:off + lim], "total": len(rows)}, None


@pytest.fixture
def branche(monkeypatch):
    """Remplace l'API, l'écriture et la persistance : aucun test ne sort d'ici."""
    ecrits: list[dict] = []

    async def faux_index(docs):
        ecrits.extend(docs)
        return len(docs), None

    async def faux_count(by_type=False):
        return ({}, len(ecrits)) if by_type else len(ecrits)

    monkeypatch.setattr(crawl, "index_docs", faux_index)
    monkeypatch.setattr(crawl, "count_indexed", faux_count)
    return ecrits


# ── Voie de tête ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_la_tete_est_demandee_du_plus_recent_au_plus_ancien(branche,
                                                                  monkeypatch):
    """En ordre croissant, la voie de tête lirait les actifs de 2023 : elle ne
    verrait jamais celui créé il y a dix minutes, qui est le seul qu'elle
    cherche."""
    api = FauxAPI([_asset(f"a{i}", f"2026-01-{i + 1:02d}T00:00:00Z")
                   for i in range(5)])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    await crawl.head_lane(state, 3, _kind)
    assert api.calls[0]["direction"] == "desc"
    assert api.calls[0]["sort"] == "created_at"


@pytest.mark.asyncio
async def test_la_tete_sarrete_des_quelle_retrouve_un_actif_connu(branche,
                                                                  monkeypatch):
    """Son coût doit suivre le nombre de NOUVEAUTÉS, jamais la population :
    c'est ce qui rend la fraîcheur indépendante de la taille du tenant."""
    api = FauxAPI([_asset(f"a{i}", f"2026-01-{i + 1:02d}T00:00:00Z")
                   for i in range(300)])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    state["newest_seen"] = "2026-10-25T00:00:00Z"   # tout est déjà connu
    out = await crawl.head_lane(state, 10, _kind)
    assert out["pages"] == 1, "une seule page suffit à prouver qu'on est à jour"
    assert out["caught_up"] and out["indexed"] == 0


@pytest.mark.asyncio
async def test_la_tete_nindexe_que_les_actifs_plus_recents_que_le_repere(
        branche, monkeypatch):
    api = FauxAPI([_asset("vieux", "2026-01-01T00:00:00Z"),
                   _asset("neuf", "2026-06-01T00:00:00Z")])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    state["newest_seen"] = "2026-03-01T00:00:00Z"
    out = await crawl.head_lane(state, 5, _kind)
    assert out["indexed"] == 1
    assert [d["uuid"] for d in branche] == ["neuf"]
    assert state["newest_seen"] == "2026-06-01T00:00:00Z"


@pytest.mark.asyncio
async def test_le_repere_navance_pas_si_le_budget_a_interrompu_la_tete(
        branche, monkeypatch):
    """Avancer le repère sans avoir rejoint le front laisserait un trou entre le
    dernier actif lu et l'ancien repère — un trou que rien ne rattraperait."""
    api = FauxAPI([_asset(f"a{i:04d}", f"2026-01-01T00:00:{i % 60:02d}Z")
                   for i in range(500)])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    state["newest_seen"] = "2020-01-01T00:00:00Z"   # tout est nouveau
    out = await crawl.head_lane(state, 2, _kind)
    assert not out["caught_up"]
    assert state["newest_seen"] == "2020-01-01T00:00:00Z"


# ── Voie de fond ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_le_fond_est_parcouru_en_ordre_croissant(branche, monkeypatch):
    """Les créations s'ajoutent à la FIN en ordre croissant : les pages déjà
    lues ne se décalent jamais. En sens inverse, chaque création ferait glisser
    tout le reste d'un rang et le parcours sauterait des actifs."""
    api = FauxAPI([_asset(f"a{i}", f"2026-01-{i + 1:02d}T00:00:00Z", "host")
                   for i in range(3)])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    await crawl.backfill_lane(state, 8, _kind)
    assert all(c["direction"] == "asc" for c in api.calls)


@pytest.mark.asyncio
async def test_le_fond_couvre_la_totalite_de_chaque_type(branche, monkeypatch):
    api = FauxAPI([_asset(f"h{i}", "2026-01-01T00:00:00Z", "host")
                   for i in range(250)]
                  + [_asset(f"c{i}", "2026-01-01T00:00:00Z", "account")
                     for i in range(120)]
                  + [_asset("n0", "2026-01-01T00:00:00Z", "network")])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    for _ in range(6):
        await crawl.backfill_lane(state, 8, _kind)
    assert crawl._sweep_complete(state)
    assert len({d["uuid"] for d in branche}) == 371


@pytest.mark.asyncio
async def test_les_hotes_sont_rattrapes_avant_les_comptes(branche, monkeypatch):
    """Les hôtes portent les groupes CERT et sont cent fois moins nombreux :
    les traiter en premier rend la console utile dès le premier cycle."""
    api = FauxAPI([_asset(f"c{i}", "2026-01-01T00:00:00Z", "account")
                   for i in range(500)]
                  + [_asset("h0", "2026-01-01T00:00:00Z", "host")])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    await crawl.backfill_lane(state, 1, _kind)
    assert [d["uuid"] for d in branche] == ["h0"]


@pytest.mark.asyncio
async def test_un_type_epuise_est_marque_termine(branche, monkeypatch):
    api = FauxAPI([_asset("n0", "2026-01-01T00:00:00Z", "network")])
    monkeypatch.setattr(app, "sek_request", api)
    state = crawl._empty_state()
    await crawl.backfill_lane(state, 30, _kind)
    assert state["shards"]["network"]["done"] is True


# ── Balayage, reprise et purge ───────────────────────────────────────────────
def test_un_balayage_complet_ne_se_relance_pas_immediatement():
    """Sans délai, le parcours repartirait de zéro à chaque cycle et
    consommerait le quota pour redécouvrir une population inchangée."""
    state = crawl._empty_state()
    state["sweep_finished"] = datetime.now(timezone.utc).isoformat()
    assert crawl._sweep_due(state) is False


def test_un_balayage_ancien_est_relance():
    state = crawl._empty_state()
    vieux = datetime.now(timezone.utc) - timedelta(hours=crawl.SWEEP_MIN_HOURS + 1)
    state["sweep_finished"] = vieux.isoformat()
    assert crawl._sweep_due(state) is True


def test_un_premier_parcours_est_toujours_du():
    assert crawl._sweep_due(crawl._empty_state()) is True


@pytest.mark.asyncio
async def test_le_curseur_survit_a_un_redemarrage(branche, monkeypatch):
    """Le déduire du nombre de documents indexés devient faux dès que la voie de
    tête insère des actifs hors séquence : le parcours reprenait au mauvais rang
    et laissait un trou définitif."""
    enregistre = {}

    async def faux_save(state):
        enregistre.update(state)

    async def faux_load():
        return dict(enregistre) if enregistre else crawl._empty_state()

    api = FauxAPI([_asset(f"c{i}", "2026-01-01T00:00:00Z", "account")
                   for i in range(1000)])
    monkeypatch.setattr(app, "sek_request", api)
    monkeypatch.setattr(crawl, "save_state", faux_save)
    monkeypatch.setattr(crawl, "load_state", faux_load)
    await crawl.crawl(_kind, budget=4)
    premier = enregistre["shards"]["account"]["offset"]
    await crawl.crawl(_kind, budget=4)
    assert enregistre["shards"]["account"]["offset"] > premier > 0


@pytest.mark.asyncio
async def test_la_fraicheur_passe_avant_le_rattrapage(branche, monkeypatch):
    """Si le rattrapage passait devant, un tenant de dix millions d'actifs
    mettrait des jours à montrer un compte créé ce matin."""
    api = FauxAPI([_asset(f"c{i}", f"2026-01-{i % 28 + 1:02d}T00:00:00Z")
                   for i in range(400)])
    monkeypatch.setattr(app, "sek_request", api)
    monkeypatch.setattr(crawl, "save_state", lambda s: _noop())
    monkeypatch.setattr(crawl, "load_state", _fresh_state)
    report = await crawl.crawl(_kind, budget=6)
    assert report["head"]["pages"] >= 1
    assert api.calls[0]["direction"] == "desc"


async def _noop():
    return None


async def _fresh_state():
    return crawl._empty_state()


@pytest.mark.asyncio
async def test_la_couverture_est_annoncee_par_type_et_jamais_supposee_complete():
    state = crawl._empty_state()
    state["shards"]["host"].update({"total": 100, "done": True})
    state["shards"]["account"].update({"total": 900, "done": False})
    state["shards"]["network"].update({"total": 0, "done": True})
    cov = crawl.coverage(state, {"host": 100, "account": 250}, 350)
    assert cov["total"] == 1000 and cov["indexed"] == 350
    assert cov["pct"] == 35.0 and cov["complete"] is False
    assert cov["by_type"]["host"]["done"] is True


def test_la_couverture_ne_ment_pas_quand_les_totaux_sont_inconnus():
    """Un pourcentage calculé sur un total inconnu est une invention."""
    cov = crawl.coverage(crawl._empty_state(), {}, 12)
    assert cov["total"] is None and cov["pct"] is None


def test_les_trois_types_couvrent_la_population_entiere():
    """L'énumération de l'API est fermée — vérifié sur le tenant : la somme des
    trois types égale le total. Si Sekoia en ajoute un, ce test ne le verra pas,
    mais la couverture par type le rendra visible à l'écran."""
    assert set(crawl.ASSET_TYPES) == {"host", "account", "network"}


def test_un_actif_sans_identifiant_nest_pas_indexe():
    assert crawl.to_doc({"name": "sans uuid"}, _kind) is None


def test_le_document_indexe_porte_sa_date_de_creation():
    """La voie de tête s'arrête sur cette date : sans elle, elle relirait la
    population entière à chaque cycle."""
    doc = crawl.to_doc(_asset("a", "2026-01-01T00:00:00Z"), _kind)
    assert doc["created_at"] == "2026-01-01T00:00:00Z"
    assert doc["_id"] == "a" and doc["indexed_at"]


# ── Réconciliation : le défaut irréductible de la pagination par offset ──────
@pytest.mark.asyncio
async def test_un_ecart_apres_balayage_declenche_une_reprise(monkeypatch):
    """Si un actif est supprimé pendant le parcours, tout ce qui le suit remonte
    d'un rang et les pages déjà lues ont sauté un objet. Le seul remède est de
    recommencer : les décalages ne retombent pas au même endroit."""
    async def faux_count(by_type=False):
        return ({"host": 100, "account": 898, "network": 0}, 998)

    monkeypatch.setattr(crawl, "count_indexed", faux_count)
    state = crawl._empty_state()
    state["shards"]["host"].update({"total": 100, "done": True})
    state["shards"]["account"].update({"total": 900, "done": True})
    state["shards"]["network"].update({"total": 0, "done": True})
    state["sweep_finished"] = "2026-01-01T00:00:00.000Z"
    out = await crawl.reconcile(state)
    assert out["retried"] is True and out["by_type"] == {"account": 2}
    assert state["shards"]["account"]["done"] is False
    assert state["shards"]["host"]["done"] is True, "seul le type en écart reprend"
    assert state["sweep_finished"] is None


@pytest.mark.asyncio
async def test_un_ecart_persistant_ne_relance_pas_le_parcours_indefiniment(
        monkeypatch):
    """Un actif que l'API compte sans jamais le rendre relancerait sinon le
    parcours à chaque cycle, pour toujours."""
    async def faux_count(by_type=False):
        return ({"host": 98}, 98)

    monkeypatch.setattr(crawl, "count_indexed", faux_count)
    state = crawl._empty_state()
    for t in crawl.ASSET_TYPES:
        state["shards"][t].update({"total": 0, "done": True})
    state["shards"]["host"].update({"total": 100, "done": True})
    state["reconcile_attempts"] = 1
    out = await crawl.reconcile(state)
    assert out["retried"] is False and out["missing"] == 2
    assert state["shards"]["host"]["done"] is True
    assert state["reconcile_attempts"] == 0


@pytest.mark.asyncio
async def test_un_balayage_juste_remet_le_compteur_de_reprises_a_zero(monkeypatch):
    async def faux_count(by_type=False):
        return ({"host": 100}, 100)

    monkeypatch.setattr(crawl, "count_indexed", faux_count)
    state = crawl._empty_state()
    for t in crawl.ASSET_TYPES:
        state["shards"][t].update({"total": 0, "done": True})
    state["shards"]["host"].update({"total": 100, "done": True})
    state["reconcile_attempts"] = 1
    assert (await crawl.reconcile(state))["missing"] == 0
    assert state["reconcile_attempts"] == 0 and state["missing"] == 0
