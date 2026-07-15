#!/usr/bin/env bash
# Velociraptor GUI — port hôte (FP_VR_GUI_PORT → 18000 par défaut) et codes HTTP « service UP ».

fp_vr_gui_port() {
  local p="${FP_VR_GUI_PORT:-}"
  if [ -z "$p" ]; then
    local root="${FP_ROOT:-${DIR:-${ROOT:-}}}"
    if [ -n "$root" ] && [ -f "$root/.env" ]; then
      p=$(grep -E '^FP_VR_GUI_PORT=' "$root/.env" 2>/dev/null | tail -1 | sed 's/^FP_VR_GUI_PORT=//' | tr -d '"' | tr -d "'" | tr -d ' ')
    fi
  fi
  echo "${p:-18000}"
}

fp_vr_host_gui_url() {
  echo "http://127.0.0.1:$(fp_vr_gui_port)/velociraptor/"
}

fp_vr_http_up_re() {
  echo '^(200|301|302|307|308|401)$'
}

fp_vr_http_code_ok() {
  echo "$1" | grep -qE "$(fp_vr_http_up_re)"
}

fp_vr_curl_code() {
  local url="$1" timeout="${2:-10}"
  curl -sk -o /dev/null -w '%{http_code}' --max-time "$timeout" "$url" 2>/dev/null || echo "000"
}

fp_vr_test_host_gui() {
  local code
  code=$(fp_vr_curl_code "$(fp_vr_host_gui_url)" "${1:-10}")
  fp_vr_http_code_ok "$code"
}

# Depuis forensic-nginx → velociraptor-server:8000 (port conteneur, pas le mapping hôte).
fp_vr_test_nginx_to_server() {
  local nginx="${1:-forensic-nginx}" path="${2:-/velociraptor/app/index.html}" code
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${nginx}$"; then
    return 1
  fi
  if docker exec "$nginx" wget -q -O /dev/null -T 15 \
    "http://velociraptor-server:8000${path}" 2>/dev/null; then
    return 0
  fi
  code=$((docker exec "$nginx" wget -S -O /dev/null -T 10 \
    "http://velociraptor-server:8000${path}" 2>&1 || true) | awk '/^[[:space:]]*HTTP\//{print $2}' | tail -1)
  fp_vr_http_code_ok "$code"
}
