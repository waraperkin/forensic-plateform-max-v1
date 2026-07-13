#!/bin/bash
# Idempotent — patches API Timesketch dans le venv (conteneur web/worker).
# explore.py : FP_PATCH_FIELDS_LIST, FP_PATCH_EMPTY_INDICES
# aggregation.py : FP_PATCH_AGG_NO_INDICES, FP_PATCH_AGG_TYPEERROR
# analysis.py : FP_PATCH_ANALYZER_GET, FP_PATCH_ANALYZERS_FILTER_GET
# manager.py : FP_PATCH_ANALYZERS_FILTER (get_enabled_analyzers)
set -e

mkdir -p /opt/fp-timesketch
if [ -f /opt/fp-timesketch-src/analyzers_enabled.txt ]; then
  cp -f /opt/fp-timesketch-src/analyzers_enabled.txt /opt/fp-timesketch/analyzers_enabled.txt
  echo "[fp-patch] analyzers_enabled.txt copié vers /opt/fp-timesketch/"
elif [ -f /opt/fp-timesketch/analyzers_enabled.txt ]; then
  echo "[fp-patch] analyzers_enabled.txt déjà dans /opt/fp-timesketch/"
fi

python3 <<'PY'
import glob
import sys
from pathlib import Path

paths = sorted(glob.glob("/opt/venv/lib/python3.*/site-packages/timesketch/api/v1/resources/explore.py"))
if not paths:
    print("[fp-patch] explore.py introuvable (venv ?)")
    sys.exit(0)
path = Path(paths[0])
text = path.read_text()
orig = text
changed = False

# ── Patch 1 : fields list ─────────────────────────────────────────────
if "FP_PATCH_FIELDS_LIST" not in text:
    old_a = """        return_field_string = form.fields.data
        if return_field_string:
            return_fields = [x.strip() for x in return_field_string.split(",")]
        else:
            return_fields = query_filter.get("fields", [])
            return_fields = [field["field"] for field in return_fields]
            return_fields.extend(DEFAULT_SOURCE_FIELDS)"""

    new_a = """        return_field_string = form.fields.data
        if return_field_string:
            # FP_PATCH_FIELDS_LIST
            if isinstance(return_field_string, str):
                return_fields = [x.strip() for x in return_field_string.split(",") if x.strip()]
            elif isinstance(return_field_string, list):
                if return_field_string and isinstance(return_field_string[0], dict):
                    return_fields = [
                        f.get("field") for f in return_field_string if isinstance(f, dict) and f.get("field")
                    ]
                else:
                    return_fields = [str(x).strip() for x in return_field_string if str(x).strip()]
            else:
                return_fields = []
            if not return_fields:
                return_fields = query_filter.get("fields", [])
                return_fields = [field["field"] for field in return_fields if isinstance(field, dict) and field.get("field")]
            return_fields.extend(DEFAULT_SOURCE_FIELDS)
        else:
            return_fields = query_filter.get("fields", [])
            return_fields = [field["field"] for field in return_fields if isinstance(field, dict) and field.get("field")]
            return_fields.extend(DEFAULT_SOURCE_FIELDS)"""

    if old_a in text:
        text = text.replace(old_a, new_a, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_FIELDS_LIST ({path})")
    else:
        old_b = old_a.replace("        ", "    ")
        new_b = new_a.replace("        ", "    ")
        if old_b in text:
            text = text.replace(old_b, new_b, 1)
            changed = True
            print(f"[fp-patch] FP_PATCH_FIELDS_LIST indent ({path})")
        else:
            print("[fp-patch] AVERTISSEMENT: bloc fields d'origine introuvable", file=sys.stderr)

# ── Patch 2 : aucun index (sketch vide) → 200 JSON vide ───────────────
if "FP_PATCH_EMPTY_INDICES" not in text:
    old_empty = """        if not indices:
            abort(
                HTTP_STATUS_CODE_BAD_REQUEST,
                "No valid search indices were found to perform the search on.",
            )"""

    new_empty = """        if not indices:
            # FP_PATCH_EMPTY_INDICES — pas de timeline : évite HTTP 400 + toast « Server side error »
            return jsonify(
                {
                    "meta": {
                        "es_time": 0,
                        "es_total_count": 0,
                        "es_total_count_complete": 0,
                        "count_over_time": {"data": {}, "interval": ""},
                        "count_per_index": {},
                        "count_per_timeline": {},
                        "scroll_id": "",
                        "search_node": None,
                        "timeline_colors": {},
                        "timeline_names": {},
                    },
                    "objects": [],
                }
            )"""

    if old_empty in text:
        text = text.replace(old_empty, new_empty, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_EMPTY_INDICES ({path})")
    else:
        print("[fp-patch] AVERTISSEMENT: bloc abort indices introuvable", file=sys.stderr)

if changed:
    path.write_text(text)
elif text == orig and "FP_PATCH_FIELDS_LIST" in orig and "FP_PATCH_EMPTY_INDICES" in orig:
    pass  # déjà tout appliqué
PY

python3 <<'PY_AGG'
import glob
import sys
from pathlib import Path

paths = sorted(glob.glob("/opt/venv/lib/python3.*/site-packages/timesketch/api/v1/resources/aggregation.py"))
if not paths:
    print("[fp-patch] aggregation.py introuvable")
    sys.exit(0)
path = Path(paths[0])
text = path.read_text()
orig = text
changed = False

if "FP_PATCH_AGG_NO_INDICES" not in text:
    old1 = """            if not (indices or timeline_ids):
                abort(HTTP_STATUS_CODE_NOT_FOUND, "No indices to aggregate on found.")"""

    new1 = """            if not (indices or timeline_ids):
                # FP_PATCH_AGG_NO_INDICES — même logique que explore vide (pas de 404 UI)
                return jsonify(
                    {
                        "meta": {
                            "method": "aggregator_run",
                            "aggregator_class": "legacy",
                            "es_time": 0.0,
                            "chart_type": None,
                            "name": None,
                            "description": None,
                        },
                        "objects": [],
                    }
                )"""

    if old1 in text:
        text = text.replace(old1, new1, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_AGG_NO_INDICES ({path})")

if "FP_PATCH_AGG_DSL_EMPTY" not in text:
    old2 = """        elif aggregation_dsl:
            try:
                # pylint: disable=unexpected-keyword-arg
                result = self.datastore.client.search(
                    index=",".join(sketch_indices), body=aggregation_dsl, size=0
                )"""

    new2 = """        elif aggregation_dsl:
            if not sketch_indices:
                # FP_PATCH_AGG_DSL_EMPTY — aucun index « ready » : ne pas interroger OpenSearch
                result = {"hits": {"total": 0, "max_score": 0.0}, "took": 0, "timed_out": False}
                meta = {
                    "es_time": 0,
                    "es_total_count": 0,
                    "timed_out": False,
                    "method": "aggregator_query",
                    "max_score": 0.0,
                }
                result_keys = set(result.keys()) - self.REMOVE_FIELDS
                objects = [result[key] for key in result_keys]
                utils.update_sketch_last_activity(sketch)
                return jsonify({"meta": meta, "objects": objects})
            try:
                # pylint: disable=unexpected-keyword-arg
                result = self.datastore.client.search(
                    index=",".join(sketch_indices), body=aggregation_dsl, size=0
                )"""

    if old2 in text:
        text = text.replace(old2, new2, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_AGG_DSL_EMPTY ({path})")

if "FP_PATCH_AGG_TYPEERROR" not in text:
    old3 = """            time_before = time.time()
            try:
                result_obj = aggregator.run(**aggregator_parameters)
            except NotFoundError:"""

    new3 = """            time_before = time.time()
            try:
                result_obj = aggregator.run(**aggregator_parameters)
            except TypeError as exc:
                # FP_PATCH_AGG_TYPEERROR — UI envoie field_bucket sans « field » → évite HTTP 500
                import logging as _logging

                _logging.getLogger(__name__).warning(
                    "Aggregator %s TypeError (params incomplets): %s",
                    aggregator_name,
                    exc,
                )
                desc = aggregator_description if isinstance(aggregator_description, dict) else {}
                return jsonify(
                    {
                        "meta": {
                            "method": "aggregator_run",
                            "aggregator_class": "legacy",
                            "es_time": 0.0,
                            "chart_type": chart_type,
                            "name": desc.get("name"),
                            "description": desc.get("description"),
                        },
                        "objects": [],
                    }
                )
            except NotFoundError:"""

    if old3 in text:
        text = text.replace(old3, new3, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_AGG_TYPEERROR ({path})")

if changed:
    path.write_text(text)
PY_AGG

python3 <<'PY_ANALYZER'
import glob
import sys
from pathlib import Path

paths = sorted(glob.glob("/opt/venv/lib/python3.*/site-packages/timesketch/api/v1/resources/analysis.py"))
if not paths:
    print("[fp-patch] analysis.py introuvable")
    sys.exit(0)
path = Path(paths[0])
text = path.read_text()
orig = text
changed = False

if "FP_PATCH_ANALYZER_GET" not in text:
    old_loop = """        for analyzer_name, analyzer_class in analyzers:
            # TODO: update the multi_analyzer detection logic for edgecases
            # where analyzers are using custom parameters (e.g. misp)
            analyzers_detail.append(
                {
                    "name": analyzer_name,
                    "display_name": analyzer_class.DISPLAY_NAME,
                    "description": analyzer_class.DESCRIPTION,
                    "is_multi": len(analyzer_class.get_kwargs()) > 0,
                    "is_dfiq": hasattr(analyzer_class, "IS_DFIQ_ANALYZER")
                    and analyzer_class.IS_DFIQ_ANALYZER,
                }
            )"""

    new_loop = """        for analyzer_name, analyzer_class in analyzers:
            # TODO: update the multi_analyzer detection logic for edgecases
            # where analyzers are using custom parameters (e.g. misp)
            try:
                # FP_PATCH_ANALYZER_GET — get_kwargs() peut lever (sigma DB, plugins)
                try:
                    is_multi = len(analyzer_class.get_kwargs()) > 0
                except Exception:
                    is_multi = False
                analyzers_detail.append(
                    {
                        "name": analyzer_name,
                        "display_name": getattr(
                            analyzer_class, "DISPLAY_NAME", analyzer_name
                        ),
                        "description": getattr(analyzer_class, "DESCRIPTION", ""),
                        "is_multi": is_multi,
                        "is_dfiq": hasattr(analyzer_class, "IS_DFIQ_ANALYZER")
                        and analyzer_class.IS_DFIQ_ANALYZER,
                    }
                )
            except Exception as exc:
                logger.warning("Skipping analyzer %s: %s", analyzer_name, exc)"""

    if old_loop in text:
        text = text.replace(old_loop, new_loop, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_ANALYZER_GET ({path})")
    else:
        print("[fp-patch] AVERTISSEMENT: bloc analyzer GET introuvable", file=sys.stderr)

# ── Route analyzer : get_enabled_analyzers() si disponible ────────────
if "FP_PATCH_ANALYZERS_FILTER_GET" not in text:
    old_get = """        analyzers = analyzer_manager.AnalysisManager.get_analyzers(
            include_dfiq=include_dfiq
        )"""
    new_get = """        _fp_mgr = analyzer_manager.AnalysisManager
        if hasattr(_fp_mgr, "get_enabled_analyzers"):
            # FP_PATCH_ANALYZERS_FILTER_GET
            analyzers = _fp_mgr.get_enabled_analyzers(include_dfiq=include_dfiq)
        else:
            analyzers = _fp_mgr.get_analyzers(include_dfiq=include_dfiq)"""
    if old_get in text:
        text = text.replace(old_get, new_get, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_ANALYZERS_FILTER_GET ({path})")
    else:
        print("[fp-patch] AVERTISSEMENT: bloc get_analyzers introuvable", file=sys.stderr)

if changed:
    path.write_text(text)
PY_ANALYZER

python3 <<'PY_MANAGER'
import glob
import sys
from pathlib import Path

paths = sorted(glob.glob("/opt/venv/lib/python3.*/site-packages/timesketch/lib/analyzers/manager.py"))
if not paths:
    print("[fp-patch] manager.py introuvable")
    sys.exit(0)
path = Path(paths[0])
text = path.read_text()
orig = text
changed = False

if "FP_PATCH_ANALYZERS_FILTER" not in text:
    marker = "        _ = cls._class_registry.pop(analyzer_name, None)\n"
    addition = """        _ = cls._class_registry.pop(analyzer_name, None)

    @classmethod
    def get_enabled_analyzers(cls, analyzer_names=None, include_dfiq=False):
        \"\"\"FP_PATCH_ANALYZERS_FILTER — filtre via /opt/fp-timesketch/analyzers_enabled.txt.\"\"\"
        from pathlib import Path as _Path

        enabled_file = _Path("/opt/fp-timesketch/analyzers_enabled.txt")
        all_items = list(cls.get_analyzers(analyzer_names=analyzer_names, include_dfiq=include_dfiq))
        if not enabled_file.is_file():
            for item in all_items:
                yield item
            return

        allow = set()
        for line in enabled_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                allow.add(line)

        for name, klass in all_items:
            if name in allow or klass.__name__ in allow:
                yield name, klass
"""
    if marker in text:
        text = text.replace(marker, addition, 1)
        changed = True
        print(f"[fp-patch] FP_PATCH_ANALYZERS_FILTER ({path})")
    else:
        print("[fp-patch] AVERTISSEMENT: fin manager.py introuvable", file=sys.stderr)

if changed:
    path.write_text(text)
elif "FP_PATCH_ANALYZERS_FILTER" in orig:
    pass
PY_MANAGER

# ── feature_extraction.get_kwargs : ignorer configs non-dict (évite HTTP 500 POST /analyzer/) ──
python3 <<'PY_FEATURE'
import glob
from pathlib import Path

needle = '                feature_config["plugin_name"] = plugin.NAME.lower()'
replacement = """                if not isinstance(feature_config, dict):
                    continue
                feature_config = dict(feature_config)
                feature_config["plugin_name"] = plugin.NAME.lower()"""

for path_str in sorted(glob.glob("/opt/venv/lib/python3.*/site-packages/timesketch/lib/analyzers/feature_extraction.py")):
    path = Path(path_str)
    text = path.read_text()
    if "FP_PATCH_FEATURE_KWARGS" in text:
        continue
    if needle not in text:
        print(f"[fp-patch] AVERTISSEMENT: feature_extraction.py non patché ({path})", file=__import__("sys").stderr)
        continue
    text = text.replace(
        needle,
        "                # FP_PATCH_FEATURE_KWARGS\n" + replacement,
        1,
    )
    path.write_text(text)
    print(f"[fp-patch] FP_PATCH_FEATURE_KWARGS ({path})")
PY_FEATURE

# ── tasks.build_sketch_analysis_pipeline : get_kwargs() ne doit pas faire échouer le POST ──
python3 <<'PY_TASKS'
import glob
from pathlib import Path

old = """        additional_kwargs = analyzer_class.get_kwargs()
        if isinstance(additional_kwargs, dict):"""
new = """        try:
            additional_kwargs = analyzer_class.get_kwargs()
        except Exception as exc:
            import logging as _logging
            _logging.getLogger("timesketch.tasks").warning(
                "Skipping analyzer %s get_kwargs: %s", analyzer_name, exc
            )
            continue
        if isinstance(additional_kwargs, dict):"""

for path_str in sorted(glob.glob("/opt/venv/lib/python3.*/site-packages/timesketch/lib/tasks.py")):
    path = Path(path_str)
    text = path.read_text()
    if "FP_PATCH_ANALYZER_BUILD_KWARGS" in text:
        continue
    if old not in text:
        print(f"[fp-patch] AVERTISSEMENT: tasks.py bloc get_kwargs introuvable ({path})", file=__import__("sys").stderr)
        continue
    path.write_text(
        text.replace(
            old,
            """        try:
            additional_kwargs = analyzer_class.get_kwargs()
        except Exception as exc:
            import logging as _logging
            _logging.getLogger("timesketch.tasks").warning(
                "Skipping analyzer %s get_kwargs: %s", analyzer_name, exc
            )
            continue
        if isinstance(additional_kwargs, dict):""",
            1,
        )
    )
    print(f"[fp-patch] FP_PATCH_ANALYZER_BUILD_KWARGS ({path})")
PY_TASKS

# â”€â”€ datastores.opensearch : autoriser OpenSearch 2.12 de la plateforme lab â”€â”€
python3 <<'PY_OS_VERSION'
import glob
import sys
from pathlib import Path

old = """            if version.parse(self.version) < version.parse("2.19.5"):
                raise errors.UnsupportedDatastoreVersionError(
                    f"Connected OpenSearch version {self.version} is not supported. "
                    f"Timesketch requires OpenSearch version >= 2.19.5."
                )"""

new = """            if version.parse(self.version) < version.parse("2.19.5"):
                # FP_PATCH_OS_VERSION_COMPAT — lab platform uses OpenSearch 2.12.x.
                os_logger.warning(
                    "OpenSearch version %s is below Timesketch upstream minimum 2.19.5; "
                    "continuing with forensic platform compatibility mode.",
                    self.version,
                )"""

for path_str in sorted(glob.glob("/opt/venv/lib/python3.*/site-packages/timesketch/lib/datastores/opensearch.py")):
    path = Path(path_str)
    text = path.read_text()
    if "FP_PATCH_OS_VERSION_COMPAT" in text:
        continue
    if old not in text:
        print(f"[fp-patch] AVERTISSEMENT: opensearch.py version check introuvable ({path})", file=sys.stderr)
        continue
    path.write_text(text.replace(old, new, 1))
    print(f"[fp-patch] FP_PATCH_OS_VERSION_COMPAT ({path})")
PY_OS_VERSION
