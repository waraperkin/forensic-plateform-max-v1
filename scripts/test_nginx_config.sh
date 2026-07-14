#!/usr/bin/env bash
# Valide la syntaxe nginx de forensic.conf (resolver + proxy_pass variables).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$ROOT/config/nginx/conf.d/forensic.conf"

fail=0

if ! grep -q 'resolver 127.0.0.11' "$CONF"; then
  echo "FAIL: resolver Docker DNS absent dans forensic.conf" >&2
  fail=1
fi

if ! grep -q 'set \$helk_kibana_upstream' "$CONF"; then
  echo "FAIL: upstream HELK dynamique absent" >&2
  fail=1
fi

if ! grep -q 'set \$velociraptor_upstream' "$CONF"; then
  echo "FAIL: upstream Velociraptor dynamique absent" >&2
  fail=1
fi

if grep -q 'default "https://192.0.2.9"' "$CONF"; then
  echo "FAIL: CORS Grafana encore figé sur 192.0.2.9" >&2
  fail=1
fi

if ! grep -q 'set \$vr_bridge_upstream' "$CONF"; then
  echo "FAIL: upstream Velociraptor bridge dynamique absent" >&2
  fail=1
fi

if ! grep -q 'location /helk/kibana {' "$CONF"; then
  echo "FAIL: HELK Kibana proxy pattern (OSD-style) absent" >&2
  fail=1
fi

if ! grep -q 'location = /site-info.html' "$CONF"; then
  echo "FAIL: page site-info.html absente" >&2
  fail=1
fi

if ! grep -q '/etc/nginx/ssl/forensic.crt' "$CONF"; then
  echo "FAIL: nginx doit utiliser /etc/nginx/ssl/forensic.crt (modèle fp-final2)" >&2
  fail=1
fi

if ! grep -q 'include /etc/nginx/generated/ec2-dns-redirect.conf' "$CONF"; then
  echo "FAIL: include redirect DNS EC2 absent" >&2
  fail=1
fi

for snip in grafana-proxy.conf misp-root-paths.conf; do
  if [ -f "$ROOT/config/nginx/snippets/$snip" ]; then
    echo "PASS: snippet $snip présent"
  else
    echo "FAIL: snippet $snip absent" >&2
    fail=1
  fi
done

_fp_nginx_docker_add_hosts() {
  local host
  # upstream { server name:port } + set $var name:port + proxy_pass http://name:port
  {
    grep -oE '(server |set \$[a-z_]+ )[a-zA-Z0-9._-]+:' "$CONF" 2>/dev/null || true
    grep -oE 'proxy_pass https?://[a-zA-Z0-9._-]+:' "$CONF" 2>/dev/null \
      | sed -E 's|proxy_pass https?://||' || true
  } | awk -F: '{print $1}' | sort -u \
    | while read -r host; do
        [ -n "$host" ] && printf '%s\n' "--add-host" "${host}:127.0.0.1"
      done
}

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  GEN_SNIP="$ROOT/config/nginx/generated/ec2-dns-redirect.conf"
  mkdir -p "$ROOT/config/nginx/generated" "$ROOT/config/nginx/static"
  [ -f "$GEN_SNIP" ] || echo "# stub preflight" > "$GEN_SNIP"

  CRT="" KEY="" CERT_TMP=""
  if [ -f "$ROOT/config/nginx/ssl/forensic.crt" ] && [ -f "$ROOT/config/nginx/ssl/forensic.key" ]; then
    CRT="$ROOT/config/nginx/ssl/forensic.crt"
    KEY="$ROOT/config/nginx/ssl/forensic.key"
  elif [ -f "$ROOT/nginx/certs/server/server.crt" ] && [ -f "$ROOT/nginx/certs/server/server.key" ]; then
    CRT="$ROOT/nginx/certs/server/server.crt"
    KEY="$ROOT/nginx/certs/server/server.key"
  elif command -v openssl >/dev/null 2>&1; then
    CERT_TMP=$(mktemp -d)
    if openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "$CERT_TMP/forensic.key" -out "$CERT_TMP/forensic.crt" \
      -days 1 -subj "/CN=forensic-platform" 2>/dev/null; then
      CRT="$CERT_TMP/forensic.crt"
      KEY="$CERT_TMP/forensic.key"
    fi
  fi

  if [ -n "$CRT" ] && [ -n "$KEY" ]; then
    mapfile -t ADD_HOSTS < <(_fp_nginx_docker_add_hosts)
    NGINX_ERR=$(mktemp)
    # Même montages que docker-compose.yml (service nginx) — snippets + generated requis
    if docker run --rm --entrypoint nginx \
      "${ADD_HOSTS[@]}" \
      -v "$ROOT/config/nginx/conf.d/forensic.conf:/etc/nginx/conf.d/default.conf:ro" \
      -v "$ROOT/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
      -v "$ROOT/config/nginx/generated:/etc/nginx/generated:ro" \
      -v "$ROOT/config/nginx/static:/etc/nginx/static:ro" \
      -v "$ROOT/config/nginx/snippets:/etc/nginx/snippets:ro" \
      -v "$CRT:/etc/nginx/ssl/forensic.crt:ro" \
      -v "$KEY:/etc/nginx/ssl/forensic.key:ro" \
      nginx:1.25-alpine -t 2>"$NGINX_ERR"; then
      echo "PASS: docker nginx -t"
    else
      echo "FAIL: docker nginx -t" >&2
      grep -E 'nginx: \[(warn|emerg)\]' "$NGINX_ERR" | tail -5 >&2 || tail -5 "$NGINX_ERR" >&2 || true
      fail=1
    fi
    rm -f "$NGINX_ERR"
  else
    echo "SKIP: docker nginx -t (certificat indisponible — lancer test_tls_forensic_platform.sh d'abord)"
  fi
  [ -n "$CERT_TMP" ] && rm -rf "$CERT_TMP"
else
  echo "SKIP: docker nginx -t (Docker indisponible)"
fi

[ "$fail" -eq 0 ] && echo "PASS: forensic.conf structure OK"
exit "$fail"
