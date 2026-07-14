#!/bin/bash
# Détection de l'hôte public pour TLS, .env et portails.
# Priorité : PUBLIC_HOST explicite → AWS IMDS public-ipv4 → IP routable locale → AWS local-ipv4 → hostname -I

_fp_is_ipv4() {
  [[ "${1:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

_fp_is_documentation_ip() {
  case "${1:-}" in
    192.0.2.*|198.51.100.*|203.0.113.*) return 0 ;;
    *) return 1 ;;
  esac
}

_fp_is_placeholder_host() {
  case "${1:-}" in
    ""|192.0.2.9|127.0.0.1|localhost) return 0 ;;
    *) _fp_is_documentation_ip "$1" ;;
  esac
}

_fp_aws_imds_token() {
  curl -sf --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true
}

_fp_aws_metadata() {
  local path="$1" token="${2:-}"
  if [ -n "$token" ]; then
    curl -sf --max-time 2 -H "X-aws-ec2-metadata-token: $token" \
      "http://169.254.169.254/latest/meta-data/${path}" 2>/dev/null || true
  else
    curl -sf --max-time 2 "http://169.254.169.254/latest/meta-data/${path}" 2>/dev/null || true
  fi
}

_fp_aws_public_ipv4() {
  local token ip
  token=$(_fp_aws_imds_token)
  ip=$(_fp_aws_metadata "public-ipv4" "$token")
  if _fp_is_ipv4 "$ip" && ! _fp_is_documentation_ip "$ip"; then
    echo "$ip"
  fi
}

_fp_aws_public_hostname() {
  local token
  token=$(_fp_aws_imds_token)
  _fp_aws_metadata "public-hostname" "$token"
}

_fp_aws_local_ipv4() {
  local token ip
  token=$(_fp_aws_imds_token)
  ip=$(_fp_aws_metadata "local-ipv4" "$token")
  if _fp_is_ipv4 "$ip" && ! _fp_is_documentation_ip "$ip"; then
    echo "$ip"
  fi
}

_fp_is_docker_or_link_local() {
  case "${1:-}" in
    127.*|169.254.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*)
      return 0
      ;;
  esac
  return 1
}

_fp_pick_routable_ipv4_from_hostname() {
  local ip
  for ip in $(hostname -I 2>/dev/null); do
    _fp_is_ipv4 "$ip" || continue
    _fp_is_docker_or_link_local "$ip" && continue
    echo "$ip"
    return 0
  done
  for ip in $(hostname -I 2>/dev/null); do
    _fp_is_ipv4 "$ip" || continue
    case "$ip" in 127.*) continue ;; esac
    echo "$ip"
    return 0
  done
  return 1
}

# Point d'entrée — imprime l'IP à utiliser pour HTTPS / soc_base_url / certs.
fp_detect_public_host() {
  local ip="" aws_pub="" aws_local="" routed="" first=""

  if [ -n "${PUBLIC_HOST:-}" ] && ! _fp_is_placeholder_host "$PUBLIC_HOST"; then
    echo "$PUBLIC_HOST"
    return 0
  fi
  if [ -n "${FP_PUBLIC_HOST:-}" ] && ! _fp_is_placeholder_host "$FP_PUBLIC_HOST"; then
    echo "$FP_PUBLIC_HOST"
    return 0
  fi

  aws_pub=$(_fp_aws_public_ipv4)
  if _fp_is_ipv4 "$aws_pub"; then
    echo "$aws_pub"
    return 0
  fi

  routed=$(_fp_pick_routable_ipv4_from_hostname || true)
  if _fp_is_ipv4 "$routed"; then
    echo "$routed"
    return 0
  fi

  aws_local=$(_fp_aws_local_ipv4)
  if _fp_is_ipv4 "$aws_local"; then
    echo "$aws_local"
    return 0
  fi

  first=$(hostname -I 2>/dev/null | awk '{print $1}')
  if _fp_is_ipv4 "$first"; then
    echo "$first"
    return 0
  fi

  echo "127.0.0.1"
  return 1
}

_fp_cert_san_contains_ip() {
  local cert="$1" want_ip="$2"
  [ -f "$cert" ] || return 1
  openssl x509 -in "$cert" -noout -text 2>/dev/null \
    | grep -E "IP Address:|DNS:" \
    | grep -Fq "$want_ip"
}

_fp_patch_nginx_grafana_maps() {
  local conf="$1" ip="$2"
  [ -f "$conf" ] || return 0
  # Rétrocompat : remplace les maps Grafana figées sur l'IP lab si encore présentes.
  sed -i \
    -e "s/default \"https:\/\/10\.78\.0\.9\";/default \"https:\/\/${ip}\";/g" \
    -e "s/\"~\\^https?://(10\\.78\\.0\\.9|localhost|127\\.0\\.0\\.1)/\"~^https?:\\/\\/(10\\.78\\.0\\.9|${ip}|localhost|127\\.0\\.0\\.1)/g" \
    "$conf" 2>/dev/null || true
}

_fp_patch_nginx_server_name() {
  local conf="$1" ip="$2"
  [ -f "$conf" ] || return 0
  if grep -q 'server_name _;' "$conf" 2>/dev/null; then
    return 0
  fi
  sed -i "s/server_name .*/server_name _;/" "$conf" 2>/dev/null || true
  sed -i "s/^[[:space:]]*# server_name .*/# server_name ${ip};/" "$conf" 2>/dev/null || true
}

# Charge PUBLIC_HOST depuis .env si présent (sans écraser l'environnement courant).
fp_load_env_public_host() {
  local root="${DIR:-.}" line key val
  if [ -n "${PUBLIC_HOST:-}" ] && ! _fp_is_placeholder_host "$PUBLIC_HOST"; then
    return 0
  fi
  [ -f "$root/.env" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in "#"*|"") continue ;; esac
    if [[ "$line" =~ ^PUBLIC_HOST=(.*)$ ]]; then
      val="${BASH_REMATCH[1]}"
      val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
      if [ -n "$val" ] && ! _fp_is_placeholder_host "$val"; then
        export PUBLIC_HOST="$val"
        return 0
      fi
    fi
  done < "$root/.env"
  return 1
}

# IP effective pour toute la plateforme (env explicite > détection > fallback).
fp_resolve_public_host() {
  fp_load_env_public_host 2>/dev/null || true
  fp_detect_public_host 2>/dev/null || echo "127.0.0.1"
}

_fp_is_hostname() {
  _fp_is_ipv4 "${1:-}" && return 1
  [[ "${1:-}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]
}

# Retire schéma / slash parasite (évite https://https://… dans MISP / VR).
fp_normalize_host() {
  local h="${1:-}"
  h="${h#https://}"
  h="${h#http://}"
  h="${h%%/*}"
  h="${h%/}"
  echo "$h"
}

# URL publique HTTPS (inclut FP_HTTPS_PORT si ≠ 443).
fp_public_https_origin() {
  local host port
  host=$(fp_url_identity 2>/dev/null || echo "localhost")
  host=$(fp_normalize_host "$host")
  port="${FP_HTTPS_PORT:-443}"
  port="${port//$'\r'/}"
  port="${port//$'\n'/}"
  if [ "$port" = "443" ]; then
    echo "https://${host}"
  else
    echo "https://${host}:${port}"
  fi
}

# URL publique MISP sans slash final (convention CakePHP MISP.baseurl).
fp_misp_public_base_url() {
  echo "$(fp_public_https_origin)/misp"
}

# IP publique AWS (certificat SAN) — indépendant du hostname navigateur.
fp_detect_public_ip() {
  local aws_pub="" routed="" aws_local="" first=""
  aws_pub=$(_fp_aws_public_ipv4)
  if _fp_is_ipv4 "$aws_pub"; then
    echo "$aws_pub"
    return 0
  fi
  fp_load_env_public_host 2>/dev/null || true
  if [ -n "${PUBLIC_HOST:-}" ] && _fp_is_ipv4 "$PUBLIC_HOST"; then
    echo "$PUBLIC_HOST"
    return 0
  fi
  routed=$(_fp_pick_routable_ipv4_from_hostname || true)
  if _fp_is_ipv4 "$routed"; then
    echo "$routed"
    return 0
  fi
  aws_local=$(_fp_aws_local_ipv4)
  if _fp_is_ipv4 "$aws_local"; then
    echo "$aws_local"
    return 0
  fi
  first=$(hostname -I 2>/dev/null | awk '{print $1}')
  if _fp_is_ipv4 "$first"; then
    echo "$first"
    return 0
  fi
  echo "127.0.0.1"
  return 1
}

# Hôte utilisé dans les URLs navigateur (TLS, MISP, VR, Kibana).
# Par défaut : IP publique AWS. PUBLIC_HOSTNAME seulement si explicitement défini.
fp_url_identity() {
  local ph=""
  if [ -n "${PUBLIC_HOSTNAME:-}" ] && ! _fp_is_placeholder_host "$PUBLIC_HOSTNAME"; then
    fp_normalize_host "$PUBLIC_HOSTNAME"
    return 0
  fi
  fp_load_env_public_host 2>/dev/null || true
  ph=$(fp_normalize_host "${PUBLIC_HOST:-}" 2>/dev/null || true)
  if [ -n "$ph" ]; then
    if _fp_is_ipv4 "$ph" || [ "$ph" = "localhost" ]; then
      echo "$ph"
      return 0
    fi
  fi
  fp_detect_public_ip 2>/dev/null || fp_detect_public_host 2>/dev/null || echo "127.0.0.1"
}

# Identité TLS : IP par défaut (accès https://<IP>/), domaine si PUBLIC_HOSTNAME renseigné.
fp_cert_identity() {
  fp_url_identity 2>/dev/null || echo "127.0.0.1"
}

# Force PUBLIC_HOST=.env sur l'IP (corrige un ancien bootstrap DNS EC2).
fp_align_env_public_ip() {
  [ "${FP_SKIP_ENV_ALIGN:-0}" = "1" ] && return 0
  local root="${DIR:-.}" ip="" current=""
  ip=$(fp_detect_public_ip 2>/dev/null || true)
  _fp_is_ipv4 "$ip" || return 0
  [ -f "$root/.env" ] || return 0
  current=$(grep -m1 '^PUBLIC_HOST=' "$root/.env" 2>/dev/null | cut -d= -f2- || true)
  current=$(fp_normalize_host "$current" 2>/dev/null || true)
  if [ "$current" = "$ip" ]; then
    export PUBLIC_HOST="$ip"
    return 0
  fi
  if _fp_is_hostname "$current" 2>/dev/null || _fp_is_placeholder_host "$current" \
    || _fp_is_documentation_ip "$current" || [ "$current" != "$ip" ]; then
    if grep -q '^PUBLIC_HOST=' "$root/.env"; then
      sed -i "s/^PUBLIC_HOST=.*/PUBLIC_HOST=${ip}/" "$root/.env"
    else
      echo "PUBLIC_HOST=${ip}" >> "$root/.env"
    fi
    export PUBLIC_HOST="$ip"
  fi
}

_fp_cert_san_contains_identity() {
  local cert="$1" identity="$2"
  _fp_cert_san_contains_ip "$cert" "$identity"
}

# True si une valeur URL/IP doit être réécrite pour l'hôte courant.
fp_host_binding_stale() {
  local val="${1:-}" target
  target=$(fp_normalize_host "${2:-$(fp_url_identity 2>/dev/null || echo "")}" 2>/dev/null || echo "")
  [ -z "$val" ] && return 0
  [ -z "$target" ] && return 1
  if _fp_is_placeholder_host "$(echo "$val" | sed -E 's|^https?://||;s|/.*$||')" 2>/dev/null; then
    return 0
  fi
  if _fp_is_documentation_ip "$(echo "$val" | sed -E 's|^https?://||;s|/.*$||;s|:.*$||')" 2>/dev/null; then
    return 0
  fi
  case "$val" in
    *"$target"*) return 1 ;;
  esac
  echo "$val" | grep -qE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' && return 0
  [ "$val" = "" ] && return 0
  return 1
}

fp_patch_portal_soc_base_urls() {
  local root="${DIR:-.}" ip="$1" cfg current expected
  ip=$(fp_normalize_host "$ip" 2>/dev/null || echo "$ip")
  expected="$(fp_public_https_origin 2>/dev/null || echo "https://${ip}")"
  for cfg in "$root/portal-cert/public/config.json" "$root/portal-it/public/config.json"; do
    [ -f "$cfg" ] || continue
    current=$(jq -r '.soc_base_url // ""' "$cfg" 2>/dev/null || echo "")
    if [ "$current" = "$expected" ]; then
      continue
    fi
    if [ "$current" != "$expected" ] || fp_host_binding_stale "$current" "$ip" || [ -z "$current" ]; then
      jq --arg url "$expected" '.soc_base_url = $url' "$cfg" > "${cfg}.tmp" && mv -f "${cfg}.tmp" "$cfg"
    fi
  done
}
