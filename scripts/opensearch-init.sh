#!/bin/sh
# OpenSearch init — templates, ingest pipelines, ISM, indices + aliases.
# Sans set -e : on continue même si une opération idempotente échoue.
OS="${OS_URL:-http://opensearch-node1:9200}"

echo "[os-init] Waiting for OpenSearch at $OS ..."
N=0
until curl -sf --max-time 5 "$OS/_cluster/health?wait_for_status=yellow&timeout=10s" >/dev/null 2>&1; do
  N=$((N+1))
  if [ "$N" -ge 90 ]; then
    echo "[os-init] TIMEOUT after 7.5 min — abort"
    exit 1
  fi
  sleep 5
done
echo "[os-init] OpenSearch ready"

# ── 1. Index template global (ECS-like) ─────────────────────────
echo "[os-init] PUT _index_template/forensic-ecs ..."
curl -sf -X PUT "$OS/_index_template/forensic-ecs" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns":["forensic-*"],
    "template":{
      "settings":{
        "number_of_shards":1,
        "number_of_replicas":1,
        "index.refresh_interval":"5s",
        "index.mapping.total_fields.limit":2000
      },
      "mappings":{
        "dynamic_templates":[{
          "strings_as_keyword":{
            "match_mapping_type":"string",
            "mapping":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"text"}}}
          }
        }],
        "properties":{
          "@timestamp":{"type":"date"},
          "upload_id":{"type":"keyword"},
          "case_id":{"type":"keyword"},
          "portal":{"type":"keyword"},
          "analyst":{"type":"keyword"},
          "priority":{"type":"keyword"},
          "status":{"type":"keyword"},
          "token_id":{"type":"keyword"},
          "os_type":{"type":"keyword"},
          "source_file":{"type":"keyword"},
          "file":{"properties":{"name":{"type":"keyword"},"size":{"type":"long"}}},
          "storage":{"properties":{"bucket":{"type":"keyword"},"key":{"type":"keyword"}}},
          "event":{"properties":{
            "module":{"type":"keyword"},
            "category":{"type":"keyword"},
            "action":{"type":"keyword"},
            "code":{"type":"keyword"},
            "outcome":{"type":"keyword"},
            "type":{"type":"keyword"},
            "severity":{"type":"long"}
          }},
          "host":{"properties":{
            "name":{"type":"keyword"},
            "ip":{"type":"ip"},
            "os":{"properties":{"family":{"type":"keyword"}}}
          }},
          "user":{"properties":{"name":{"type":"keyword"}}},
          "source":{"properties":{"ip":{"type":"ip"},"port":{"type":"long"}}},
          "destination":{"properties":{"ip":{"type":"ip"},"port":{"type":"long"}}},
          "process":{"properties":{
            "name":{"type":"keyword"},
            "pid":{"type":"long"},
            "executable":{"type":"keyword"},
            "command_line":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":2048}}}
          }},
          "tags":{"type":"keyword"},
          "message":{"type":"text"},
          "log":{"properties":{"level":{"type":"keyword"}}},
          "http":{"properties":{"response":{"properties":{"status_code":{"type":"long"}}}}},
          "threat":{"properties":{"technique":{"properties":{"id":{"type":"keyword"},"name":{"type":"keyword"}}}}}
        }
      }
    },
    "priority":200
  }' >/dev/null && echo "[os-init] ✓ template forensic-ecs" || echo "[os-init] SKIP template"

# ── 2. Ingest pipelines (chargés depuis /pipelines/*.json) ──────
if [ -d /pipelines ]; then
  for f in /pipelines/*.json; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .json)
    curl -sf -X PUT "$OS/_ingest/pipeline/$name" \
      -H "Content-Type: application/json" \
      --data-binary "@$f" >/dev/null && echo "[os-init] ✓ ingest pipeline $name" \
      || echo "[os-init] SKIP ingest $name"
  done
fi

# ── 3. Templates additionnels mountés (/templates/*.json) ───────
if [ -d /templates ]; then
  for f in /templates/*.json; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .json)
    curl -sf -X PUT "$OS/_index_template/${name}" \
      -H "Content-Type: application/json" \
      --data-binary "@$f" >/dev/null && echo "[os-init] ✓ template $name (file)" \
      || echo "[os-init] SKIP template-file $name"
  done
fi

# ── 4. Indices initiaux + aliases write ─────────────────────────
for idx in forensic-uploads forensic-tokens forensic-windows forensic-linux \
           forensic-macos forensic-web forensic-network forensic-cloud \
           forensic-k8s forensic-db forensic-endpoint forensic-firewall forensic-alerts; do
  # Crée -000001 avec alias write si absent
  exists=$(curl -s -o /dev/null -w '%{http_code}' "$OS/${idx}-000001")
  if [ "$exists" = "404" ]; then
    curl -sf -X PUT "$OS/${idx}-000001" \
      -H "Content-Type: application/json" \
      -d "{\"aliases\":{\"${idx}\":{\"is_write_index\":true}}}" >/dev/null \
      && echo "[os-init] ✓ created $idx-000001" \
      || echo "[os-init] FAIL $idx-000001"
  else
    # Index existe : vérifier que l'alias write est posé
    has_alias=$(curl -s "$OS/_alias/${idx}" -o /dev/null -w '%{http_code}')
    if [ "$has_alias" != "200" ]; then
      curl -sf -X POST "$OS/_aliases" -H "Content-Type: application/json" \
        -d "{\"actions\":[{\"add\":{\"index\":\"${idx}-000001\",\"alias\":\"${idx}\",\"is_write_index\":true}}]}" \
        >/dev/null && echo "[os-init] ✓ alias added ${idx}" || true
    else
      echo "[os-init] = ${idx} already aliased"
    fi
  fi
done

# ── 5. ISM lifecycle policy (90 j) ──────────────────────────────
curl -sf -X PUT "$OS/_plugins/_ism/policies/forensic-lifecycle" \
  -H "Content-Type: application/json" \
  -d '{"policy":{"description":"90d lifecycle","default_state":"hot","states":[
    {"name":"hot","actions":[{"rollover":{"min_size":"5gb","min_index_age":"1d"}}],"transitions":[{"state_name":"warm","conditions":{"min_index_age":"7d"}}]},
    {"name":"warm","actions":[{"replica_count":{"number_of_replicas":0}}],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"90d"}}]},
    {"name":"delete","actions":[{"delete":{}}],"transitions":[]}]}}' >/dev/null \
    && echo "[os-init] ✓ ISM policy" || echo "[os-init] SKIP ISM"

# ── 6. Refresh ──────────────────────────────────────────────────
curl -sf -X POST "$OS/forensic-*/_refresh" >/dev/null 2>&1 && echo "[os-init] ✓ refresh" || true

echo "[os-init] Done"
