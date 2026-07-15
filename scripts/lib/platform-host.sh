#!/bin/bash
# Préparation hôte plateforme (IP, nginx static, redirect DNS EC2) — sans Docker requis.
# Appelé automatiquement par bootstrap et ./forensic.sh -full-start.

fp_prepare_platform_host() {
  local root="${DIR:-.}" host="" rc=0
  if [ -f "$root/scripts/lib/host-ip.sh" ]; then
    # shellcheck source=/dev/null
    . "$root/scripts/lib/host-ip.sh"
  else
    return 1
  fi

  fp_load_env_public_host 2>/dev/null || true
  fp_align_env_public_ip 2>/dev/null || true

  host=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "127.0.0.1")
  host=$(fp_normalize_host "$host" 2>/dev/null || echo "$host")
  export PUBLIC_HOST="$host"
  export HELK_KIBANA_PUBLIC_URL="https://${host}/helk/kibana"
  export MISP_PUBLIC_BASE_URL="$(fp_misp_public_base_url 2>/dev/null || echo "https://${host}/misp")"

  mkdir -p "$root/config/nginx/generated" "$root/config/nginx/static/.well-known"

  if [ -x "$root/scripts/setup-site-identity.sh" ]; then
    bash "$root/scripts/setup-site-identity.sh" >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 \
      || rc=1
  fi
  if [ -x "$root/scripts/generate-nginx-access-snippet.sh" ]; then
    bash "$root/scripts/generate-nginx-access-snippet.sh" >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 \
      || rc=1
  fi
  if [ -x "$root/scripts/generate-timesketch-conf.sh" ]; then
    bash "$root/scripts/generate-timesketch-conf.sh" >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 \
      || rc=1
  fi
  if [ -x "$root/scripts/generate-grafana-ini.sh" ]; then
    bash "$root/scripts/generate-grafana-ini.sh" >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 \
      || rc=1
  fi
  if [ -x "$root/scripts/render-velociraptor-nginx-snippet.sh" ]; then
    bash "$root/scripts/render-velociraptor-nginx-snippet.sh" >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 \
      || rc=1
  fi
  fp_patch_portal_soc_base_urls "$host" 2>/dev/null || true

  fp_log install "fp_prepare_platform_host OK host=$host" 2>/dev/null || true
  return "$rc"
}

# Finalisation après démarrage Docker : MISP, sidecars, nginx reload.
fp_finalize_platform_access() {
  local root="${DIR:-.}" rc=0
  fp_prepare_platform_host || rc=1

  if [ -x "$root/scripts/post-start-align.sh" ]; then
    FP_SKIP_PREPARE=1 bash "$root/scripts/post-start-align.sh" >> "${FP_LOG_START:-$root/logs/forensic_start.log}" 2>&1 \
      || rc=1
  fi
  return "$rc"
}
