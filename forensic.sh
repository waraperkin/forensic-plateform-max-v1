#!/bin/bash
# ==============================================================
#  forensic.sh — Forensic Minimal Platform
# ==============================================================
# IMPORTANT: set -e activé — utiliser if/then/fi jamais cmd && cmd
set -euo pipefail

# Garantir l'accès à sysctl/ip/etc. (certains shells non-interactifs ont un PATH minimal)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

DIR="$(cd "$(dirname "$0")" && pwd)"; cd "$DIR"

if [ -f "$DIR/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$DIR/scripts/lib/host-ip.sh"
fi

# Chemins d'état SOC/health DANS le projet (logs/, inscriptible par l'utilisateur).
# Évite l'échec "Permission denied" sur d'éventuels fichiers /tmp/fp-* résiduels
# appartenant à root (run antérieur). Tous les scripts honorent ces variables.
mkdir -p "$DIR/logs" 2>/dev/null || true
export FP_SOC_AUTO_LOG="${FP_SOC_AUTO_LOG:-$DIR/logs/soc-autonomous.log}"
export FP_SOC_AUTO_STATUS="${FP_SOC_AUTO_STATUS:-$DIR/logs/soc-autonomous-status.json}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BLUE='\033[0;34m'; NC='\033[0m'
info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
ok()  { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR ]${NC} $*"; }
step(){ echo -e "\n${BLUE}━━━ $* ━━━${NC}"; }

# ──────────────────────────────────────────────────────────────
#  TLS CYBERCORP — CA interne + certificat serveur (IP auto)
#  Point d'entrée : ./forensic.sh tls  (ou appelé depuis pre_start)
# ──────────────────────────────────────────────────────────────
setup_tls() {
  local IP
  IP=$(fp_detect_public_ip 2>/dev/null || fp_url_identity 2>/dev/null || true)
  if [ -z "$IP" ] || [ "$IP" = "127.0.0.1" ]; then
    IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  fi
  if [ -z "$IP" ]; then
    err "[TLS] Impossible de détecter l'IP publique (fp_detect_public_ip / hostname -I)"
    return 1
  fi
  echo "[TLS] IP publique : $IP (certificat CN=forensic-platform, modèle fp-final2)"

  if [ ! -f "$DIR/nginx/certs/ca/ca.crt" ]; then
    echo "[TLS] CA interne absente — génération..."
    bash "$DIR/scripts/generate_ca.sh"
  else
    echo "[TLS] CA interne déjà présente."
  fi

  local need_cert=0
  if [ ! -f "$DIR/config/nginx/ssl/forensic.crt" ] \
    || [ ! -f "$DIR/config/nginx/ssl/forensic.key" ]; then
    need_cert=1
  elif ! _fp_cert_san_contains_identity "$DIR/config/nginx/ssl/forensic.crt" "$IP"; then
    echo "[TLS] Certificat SAN ≠ $IP — régénération..."
    need_cert=1
  fi
  if [ "$need_cert" -eq 1 ]; then
    echo "[TLS] Génération certificat forensic-platform (SAN IP=$IP)..."
    bash "$DIR/scripts/generate_server_cert.sh" "$IP"
  else
    echo "[TLS] Certificat forensic-platform déjà présent (SAN IP=$IP)."
  fi

  echo "[TLS] Mise à jour des config.json avec soc_base_url=https://$IP"
  _tls_update_config_json() {
    local cfg="$1"
    if [ ! -f "$cfg" ]; then
      warn "[TLS] Fichier absent : $cfg"
      return 0
    fi
    if command -v jq >/dev/null 2>&1; then
      jq --arg url "https://${IP}" '.soc_base_url = $url' "$cfg" > "${cfg}.tmp"
      mv "${cfg}.tmp" "$cfg"
    else
      python3 - "$cfg" "$IP" <<'PY'
import json, sys
path, ip = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
data["soc_base_url"] = f"https://{ip}"
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
    fi
  }
  _tls_update_config_json "$DIR/portal-cert/public/config.json"
  _tls_update_config_json "$DIR/portal-it/public/config.json"

  echo "[TLS] Mise à jour nginx (server_name catch-all + maps Grafana)..."
  _fp_patch_nginx_server_name "$DIR/config/nginx/conf.d/forensic.conf" "$IP"
  _fp_patch_nginx_grafana_maps "$DIR/config/nginx/conf.d/forensic.conf" "$IP"
  if [ -f "$DIR/nginx/nginx.conf" ]; then
    sed -i "s/^[[:space:]]*# server_name .*/# server_name ${IP};/" "$DIR/nginx/nginx.conf" 2>/dev/null || true
  fi

  echo "[TLS] Redémarrage Nginx + portails CERT/IT..."
  if [ "${FP_TLS_NO_DOCKER:-0}" = "1" ] \
    || ! command -v docker >/dev/null 2>&1 \
    || ! docker ps >/dev/null 2>&1; then
    echo "[TLS] Docker indisponible — certificats prêts, reload Nginx différé (full-start)."
    return 0
  fi
  if [ "${FP_TLS_BUILD:-}" = "1" ]; then
    docker compose up -d --build nginx cert-portal it-portal
  else
    docker compose up -d nginx cert-portal it-portal
  fi
  docker exec forensic-nginx nginx -s reload 2>/dev/null || true

  echo "[TLS] Validation du certificat..."
  if curl -vk --max-time 15 "https://${IP}/login.html" >/dev/null 2>&1; then
    echo "[TLS] OK — TLS opérationnel."
    return 0
  fi
  curl -vk --max-time 15 "https://${IP}/login.html" 2>&1 | tail -30 || true
  if curl -sfk --max-time 15 "https://${IP}/login.html" >/dev/null 2>&1; then
    echo "[TLS] OK — TLS opérationnel (certificat auto-signé — confiance CA locale requise pour curl -f)."
    return 0
  fi
  err "[TLS] Échec validation HTTPS sur https://${IP}/"
  return 1
}

UP="docker compose up -d"
DOWN="docker compose down --remove-orphans"

# ──────────────────────────────────────────────────────────────
#  Module installateur + orchestrateur (PHASE 1/2/4/5/6)
# ──────────────────────────────────────────────────────────────
if [ -f "$DIR/scripts/lib/installer.sh" ]; then
  # shellcheck source=/dev/null
  . "$DIR/scripts/lib/installer.sh"
fi

# ──────────────────────────────────────────────────────────────
#  PRÉ-DÉMARRAGE
# ──────────────────────────────────────────────────────────────
pre_start() {
  # Socket Docker (souvent 1001:1001 hors groupe docker) — nécessite sudo une fois
  if [ -S /var/run/docker.sock ] && ! docker ps >/dev/null 2>&1; then
    warn "Accès Docker refusé — vérifier docker ps (dockerd / groupe docker)"
  fi
  step "Pré-démarrage — Configurations dynamiques"
  # Charger .env de façon robuste (gère valeurs avec espaces + guillemets)
  # FIX: dans bash, les guillemets dans une regex =~ font partie du motif littéral.
  # On utilise donc des patterns sans guillemets et on strip les wrappers à la main.
  if [ -f "$DIR/.env" ]; then
    while IFS= read -r _line || [ -n "$_line" ]; do
      case "$_line" in "#"*|"") continue ;; esac
      if [[ "${_line// /}" == "" ]]; then continue; fi
      if [[ "$_line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
        local _key="${BASH_REMATCH[1]}"
        local _val="${BASH_REMATCH[2]}"
        # Strip double-quotes wrappantes
        if [[ "${_val:0:1}" == '"' && "${_val: -1}" == '"' ]]; then
          _val="${_val:1:${#_val}-2}"
        fi
        # Strip simple-quotes wrappantes
        if [[ "${_val:0:1}" == "'" && "${_val: -1}" == "'" ]]; then
          _val="${_val:1:${#_val}-2}"
        fi
        export "${_key}=${_val}" 2>/dev/null || true
      fi
    done < "$DIR/.env"
  fi

  # TLS CYBERCORP (CA interne + cert IP + config portails) ───
  if command -v _fp_ensure_runtime_host_config >/dev/null 2>&1; then
    _fp_ensure_runtime_host_config || warn "patch IP hôte partiel — voir logs/forensic_install.log"
  fi
  setup_tls || warn "setup_tls: échec partiel — relancer ./forensic.sh tls"

  # Certificat SSL (modèle fp-final2 : CN=forensic-platform + IP en SAN) ──
  local SSL_DIR="$DIR/config/nginx/ssl"
  mkdir -p "$SSL_DIR"
  local LOCAL_IP need_ssl=0
  LOCAL_IP=$(fp_detect_public_ip 2>/dev/null || fp_url_identity 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
  if [ ! -f "$SSL_DIR/forensic.crt" ] || [ ! -f "$SSL_DIR/forensic.key" ]; then
    need_ssl=1
  elif ! openssl x509 -checkend 2592000 -noout -in "$SSL_DIR/forensic.crt" >/dev/null 2>&1; then
    need_ssl=1
    warn "Certificat SSL expiré — régénération"
  elif ! _fp_cert_san_contains_identity "$SSL_DIR/forensic.crt" "$LOCAL_IP" 2>/dev/null; then
    need_ssl=1
    warn "Certificat SSL SAN ≠ $LOCAL_IP — régénération"
  fi

  if [ "$need_ssl" -eq 1 ]; then
    info "Génération certificat forensic-platform (SAN IP=$LOCAL_IP)..."
    bash "$DIR/scripts/generate_server_cert.sh" "$LOCAL_IP"
    ok "SSL généré — $(cat "$SSL_DIR/fingerprint.txt" 2>/dev/null || echo 'fingerprint OK')"
  else
    ok "SSL valide — $(cat "$SSL_DIR/fingerprint.txt" 2>/dev/null || echo 'fingerprint OK')"
  fi

  # Timesketch config ──────────────────────────────────────────
  info "Génération timesketch.conf..."
  bash "$DIR/scripts/generate-timesketch-conf.sh"

  # vm.max_map_count (requis OpenSearch) ───────────────────────
  local mc
  mc=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)
  # FIX: utiliser if/then/fi — jamais "[ ... ] && cmd" avec set -e
  if [ "$mc" -lt 262144 ]; then
    info "vm.max_map_count=$mc → application 262144..."
    if sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
      ok "vm.max_map_count=262144"
    else
      warn "sysctl échoué — relancer avec sudo ou: sudo sysctl -w vm.max_map_count=262144"
    fi
  else
    ok "vm.max_map_count=$mc ✓"
  fi
}

# ──────────────────────────────────────────────────────────────
#  NETTOYAGE RÉSEAU (legacy 172.20 uniquement — NE PAS toucher 172.25 FP)
# ──────────────────────────────────────────────────────────────
# NOTE : fp_network_repair() gère le réseau principal fp-*_forensic-net.
#        Cette fonction ne supprime que les réseaux legacy 172.20.x conflictuels.
cleanup_network() {
  info "Vérification réseaux legacy (172.20.x)..."
  _fp_init_net_names 2>/dev/null || true
  local fp_net="${FP_NET_NAME:-fp-final2_forensic-net}"
  local nets net sn
  nets=$(_fp_docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "forensic|fp-" | grep -v "^$" || true)
  if [ -z "$nets" ]; then
    return 0
  fi
  while IFS= read -r net; do
    [ -z "$net" ] && continue
    # Ne JAMAIS supprimer le réseau FP principal (172.25 = subnet compose)
    [ "$net" = "$fp_net" ] && continue
    sn=$(_fp_docker network inspect "$net" \
      --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)
    # Legacy conflictuel : subnet 172.20.x seulement
    if echo "$sn" | grep -qE "^172\.20\."; then
      warn "Réseau legacy conflictuel: $net ($sn) — suppression"
      _fp_docker network rm "$net" >/dev/null 2>&1 || true
      fp_log network "cleanup_network: removed legacy $net ($sn)"
    fi
  done <<< "$nets"
}

# ──────────────────────────────────────────────────────────────
#  ATTENTE d'un service HTTP (sans crash set -e)
# ──────────────────────────────────────────────────────────────
wait_http() {
  # $1=url $2=max_tries $3=sleep_secs $4=service_name
  local url="$1" max="${2:-30}" delay="${3:-5}" name="${4:-service}"
  local n=0
  info "Attente $name..."
  while true; do
    if curl -skf --max-time 8 "$url" >/dev/null 2>&1; then
      echo ""
      ok "$name prêt"
      return 0
    fi
    n=$((n+1))
    if [ "$n" -ge "$max" ]; then
      echo ""
      warn "$name: timeout après $((max*delay))s (continue)"
      return 0
    fi
    printf "."
    sleep "$delay"
  done
}

# Attente HTTP dans un container (docker exec python3)
wait_container_http() {
  local container="$1" url="$2" max="${3:-60}" delay="${4:-5}" name="${5:-service}"
  local n=0
  info "Attente $name (HTTP interne container)..."
  while true; do
    if docker exec "$container" python3 -c \
      "import urllib.request; urllib.request.urlopen('$url',timeout=8)" >/dev/null 2>&1; then
      echo ""
      ok "$name HTTP OK"
      return 0
    fi
    n=$((n+1))
    if [ "$n" -ge "$max" ]; then
      echo ""
      warn "$name: timeout — vérifier: docker logs $container | tail -20"
      return 0
    fi
    printf "."
    sleep "$delay"
  done
}

# Attente postgres prêt
wait_postgres() {
  local n=0
  info "Attente PostgreSQL..."
  while true; do
    if docker exec forensic-postgres pg_isready \
      -U "${POSTGRES_USER:-forensic}" >/dev/null 2>&1; then
      ok "PostgreSQL prêt"
      return 0
    fi
    n=$((n+1))
    if [ "$n" -ge 30 ]; then
      err "PostgreSQL timeout"
      return 1
    fi
    sleep 2
  done
}

# Attente OpenSearch
wait_opensearch() {
  local n=0
  info "Attente OpenSearch (2-3 min au 1er démarrage)..."
  while true; do
    local health
    health=$(curl -sf --max-time 5 "http://localhost:9200/_cluster/health" 2>/dev/null || true)
    if [ -n "$health" ] && ! echo "$health" | grep -q '"status":"red"'; then
      echo ""
      ok "OpenSearch healthy"
      return 0
    fi
    n=$((n+1))
    if [ "$n" -ge 60 ]; then
      echo ""
      err "OpenSearch timeout. Solutions:"
      err "  Erreur Lucene codec: ./forensic.sh fix-opensearch"
      err "  Logs: docker logs forensic-opensearch-1 | tail -30"
      return 1
    fi
    printf "."
    sleep 5
  done
}

# ──────────────────────────────────────────────────────────────
#  START — helpers (résumé idempotent)
# ──────────────────────────────────────────────────────────────
START_OK=()
START_FAIL=()
START_WARN=()

fp_try() {
  local label="$1"
  shift
  info "► ${label}"
  if "$@"; then
    START_OK+=("$label")
    ok "$label"
    return 0
  fi
  START_FAIL+=("$label")
  warn "$label — échec"
  return 1
}

fp_try_optional() {
  local label="$1"
  shift
  info "► ${label} (optionnel)"
  if "$@"; then
    START_OK+=("$label")
    ok "$label"
    return 0
  fi
  START_WARN+=("$label")
  warn "$label — ignoré"
  return 1
}

start_print_summary() {
  echo ""
  step "Récapitulatif ./forensic.sh start"
  local s
  for s in "${START_OK[@]}"; do
    echo -e "  ${GREEN}[OK]${NC}  $s"
  done
  for s in "${START_WARN[@]}"; do
    echo -e "  ${YELLOW}[WARN]${NC} $s"
  done
  for s in "${START_FAIL[@]}"; do
    echo -e "  ${RED}[FAIL]${NC} $s"
  done
  if [ "${#START_FAIL[@]}" -gt 0 ]; then
    err "${#START_FAIL[@]} étape(s) en échec — voir logs/ ci-dessus"
    return 1
  fi
  ok "Toutes les étapes critiques OK (${#START_OK[@]})"
  return 0
}

start_build_images() {
  step "0/8 Build images Docker"
  local services=(ingest-worker timesketch-worker)
  if [ "${FP_FULL_ORCHESTRATOR:-0}" = "1" ] || [ "${FP_START_BUILD_PORTALS:-0}" = "1" ]; then
    services+=(cert-portal it-portal helk-bridge velociraptor-bridge)
  fi
  local svc built=0
  for svc in "${services[@]}"; do
    info "docker compose build $svc ..."
    if docker compose build "$svc"; then
      ok "build $svc"
      built=$((built + 1))
    else
      warn "build $svc échoué (continue)"
    fi
  done
  START_OK+=("Build images ($built service(s))")
}

start_wait_frontends() {
  step "Attente frontends HTTPS (Nginx / Grafana / OSD)"
  wait_http "https://localhost/grafana/api/health" 24 5 "Grafana (HTTPS)"
  wait_http "https://localhost/dashboards/api/status" 24 5 "OpenSearch Dashboards (HTTPS)"
  wait_http "https://localhost/" 12 5 "Portail CERT (HTTPS)"
}

start_activation_layers() {
  step "7/8 Activation — OpenSearch SIEM/TI + Timesketch + Grafana"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  local _had_e=0
  [[ $- == *e* ]] && _had_e=1
  set +e

  fp_try "OpenSearch SIEM (advanced)" opensearch_advanced
  fp_try "OpenSearch Dashboards FP" opensearch_dashboards_fp
  fp_try "OpenSearch TI sync (OpenCTI+MISP)" opensearch_ti_sync
  fp_try "OpenSearch TI alerting" opensearch_siem_ti_rules
  fp_try "OpenSearch Dashboards TI" opensearch_dashboards_ti
  fp_try "OpenSearch SIEM verify" opensearch_fp_verify
  fp_try "OpenSearch SIEM TI verify" opensearch_siem_ti_verify
  fp_try "OpenSearch Dashboards Observability" opensearch_dashboards_obs
  fp_try "OpenSearch SIEM rules 700+" opensearch_siem_rules_mass
  fp_try "OpenSearch Plugins Zone 3 (AD/Reporting/SecAnalytics)" opensearch_zone3_plugins
  fp_try "OpenSearch SIEM full verify" opensearch_siem_full_verify
  fp_try "OpenSearch SIEM full (activation)" opensearch_siem_full
  fp_try "Cross-tool + Pivot + IR" opensearch_cross_pivot_ir
  fp_try "Enterprise modules" enterprise_setup
  fp_try "Analyst Playbook" analyst_playbook_setup
  fp_try "SOC Manager Playbook" soc_manager_playbook_setup
  fp_try "Incident Commander Playbook" incident_commander_playbook_setup
  fp_try "SOC Director Playbook" soc_director_playbook_setup
  fp_try "TI Lead Playbook" ti_lead_playbook_setup
  fp_try "DFIR Senior Playbook" dfir_senior_playbook_setup
  fp_try "Purple Team Playbook" purple_team_playbook_setup
  fp_try "Threat Hunting Lead Playbook" th_lead_playbook_setup
  fp_try "SOC Automation Playbook" soc_automation_playbook_setup
  fp_try "CTI Fusion Playbook" cti_fusion_playbook_setup
  fp_try "Global SOC Command Center" global_soc_command_center_setup
  fp_try "Cyber Crisis Management" cyber_crisis_management_setup
  fp_try "Nation-State CTI Playbook" nation_state_cti_playbook_setup
  fp_try "Autonomous SOC Playbook" autonomous_soc_playbook_setup
  fp_try "SOC Director Executive Playbook" soc_director_executive_playbook_setup
  fp_try "Red Team Lead Playbook" red_team_lead_playbook_setup
  fp_try "Blue Team Lead Playbook" blue_team_lead_playbook_setup
  fp_try "CTI Fusion Global Playbook" cti_fusion_global_playbook_setup
  fp_try "Parsing Master Full" parsing_master_full_setup
  fp_try "Barres 18 playbooks (patch final)" fp_playbooks_bars_patch
  fp_try "Enterprise verify" enterprise_verify
  fp_try "Analyst Playbook verify" analyst_playbook_verify
  fp_try "SOC Manager Playbook verify" soc_manager_playbook_verify
  fp_try "Incident Commander Playbook verify" incident_commander_playbook_verify
  fp_try "SOC Director Playbook verify" soc_director_playbook_verify
  fp_try "TI Lead Playbook verify" ti_lead_playbook_verify
  fp_try "DFIR Senior Playbook verify" dfir_senior_playbook_verify
  fp_try "Purple Team Playbook verify" purple_team_playbook_verify
  fp_try "Threat Hunting Lead Playbook verify" th_lead_playbook_verify
  fp_try "SOC Automation Playbook verify" soc_automation_playbook_verify
  fp_try "CTI Fusion Playbook verify" cti_fusion_playbook_verify
  fp_try "Global SOC Command Center verify" global_soc_command_center_verify
  fp_try "Cyber Crisis Management verify" cyber_crisis_management_verify
  fp_try "Nation-State CTI Playbook verify" nation_state_cti_playbook_verify
  fp_try "Autonomous SOC Playbook verify" autonomous_soc_playbook_verify
  fp_try "SOC Director Executive Playbook verify" soc_director_executive_playbook_verify
  fp_try "Red Team Lead Playbook verify" red_team_lead_playbook_verify
  fp_try "Blue Team Lead Playbook verify" blue_team_lead_playbook_verify
  fp_try "CTI Fusion Global Playbook verify" cti_fusion_global_playbook_verify
  fp_try "Parsing Master Full verify" parsing_master_full_verify
  fp_try "Playbooks ECS sync" parsing_playbook_ecs_apply
  fp_try "Hunting parsing verify" hunting_parsing_verify
  fp_try "Purple Team parsing verify" purple_team_parsing_verify
  fp_try "DFIR parsing verify" dfir_parsing_verify
  fp_try "CTI parsing verify" cti_parsing_verify
  fp_try "SOC parsing verify" soc_parsing_verify
  fp_try "Incident parsing verify" incident_parsing_verify
  fp_try "Parsing integration verify" parsing_master_full_integration_verify

  fp_try "Timesketch setup" timesketch_setup
  fp_try "Timesketch Master setup" timesketch_master_setup
  fp_try "Timesketch Master verify" timesketch_master_verify
  fp_try "Timesketch UI verify" timesketch_ui_verify
  fp_try "Timesketch Playbook setup" timesketch_playbook_setup
  fp_try "Timesketch Playbook verify" timesketch_playbook_verify
  fp_try "Timesketch zones setup" timesketch_zones_setup
  fp_try "Timesketch zones verify" timesketch_zones_verify
  fp_try "Timesketch full zones integration" timesketch_full_zones_integration_verify

  fp_try "Cross-Pivot setup" crosspivot_setup
  fp_try "Cross-Pivot verify" crosspivot_verify
  fp_try "Cross-Pivot UI verify" crosspivot_ui_verify

  fp_try "Timesketch CTI Fusion setup" ts_cti_fusion_setup
  fp_try "Timesketch CTI Fusion verify" ts_cti_fusion_verify
  fp_try "Timesketch CTI Fusion UI verify" ts_cti_fusion_ui_verify

  fp_try "Timesketch Incident Commander setup" ts_incident_commander_setup
  fp_try "Timesketch Incident Commander verify" ts_incident_commander_verify
  fp_try "Timesketch Incident Commander UI verify" ts_incident_commander_ui_verify

  fp_try "Timesketch Purple Team setup" ts_purple_team_setup
  fp_try "Timesketch Purple Team verify" ts_purple_team_verify
  fp_try "Timesketch Purple Team UI verify" ts_purple_team_ui_verify

  fp_try "Sigma Master setup" sigma_master_setup
  fp_try "Sigma Master verify" sigma_master_verify
  fp_try "Sigma Master UI verify" sigma_master_ui_verify
  fp_try "TI Master setup" ti_master_setup
  fp_try "TI Master verify" ti_master_verify
  fp_try "TI Master UI verify" ti_master_ui_verify
  fp_try "Analyzers Master setup" analyzers_master_setup
  fp_try "Analyzers Master verify" analyzers_master_verify
  fp_try "Analyzers Master UI verify" analyzers_master_ui_verify
  fp_try "Visualizations Master setup" visualizations_master_setup
  fp_try "Visualizations Master verify" visualizations_master_verify
  fp_try "Visualizations Master UI verify" visualizations_master_ui_verify

  fp_try "SOC Autonomous run" soc_autonomous_run
  fp_try "SOC Autonomous verify" soc_autonomous_verify
  fp_try "SOC Autonomous UI verify" soc_autonomous_ui_verify

  fp_try "Platform Health dashboard setup" platform_health_dashboard_setup
  fp_try "Platform Health dashboard verify" platform_health_dashboard_verify

  fp_try "Grafana Master setup" grafana_master_setup
  fp_try "Grafana Master verify" grafana_master_verify
  fp_try "Grafana Master UI verify" grafana_master_ui_verify

  fp_try "OpenCTI Master setup" opencti_master_setup
  fp_try "OpenCTI Master verify" opencti_master_verify
  fp_try "OpenCTI Master UI verify" opencti_master_ui_verify

  fp_try "MISP Master setup" misp_master_setup
  fp_try "MISP Master verify" misp_master_verify
  fp_try "MISP Master UI verify" misp_master_ui_verify

  fp_try "TheHive Master setup" thehive_master_setup
  fp_try "TheHive Master verify" thehive_master_verify
  fp_try "TheHive Master UI verify" thehive_master_ui_verify

  fp_try "Cortex Master setup" cortex_master_setup
  fp_try "Cortex Master verify" cortex_master_verify
  fp_try "Cortex Master UI verify" cortex_master_ui_verify

  fp_try "MinIO Master setup" minio_master_setup
  fp_try "MinIO Master verify" minio_master_verify
  fp_try "MinIO Master UI verify" minio_master_ui_verify

  fp_try "Portal CERT Master setup" portal_cert_master_setup
  fp_try "Portal CERT Master verify" portal_cert_master_verify
  fp_try "Portal CERT Master UI verify" portal_cert_master_ui_verify
  fp_try "Portal auth UI verify" portal_auth_ui_verify

  [ "$_had_e" -eq 1 ] && set -e
}

start_automated_tests() {
  step "8/8 Tests automatiques minimaux"
  set +e
  fp_try "Health endpoints" _start_health_check
  if [ -f "$DIR/scripts/ui_campaign_verify.py" ]; then
    fp_try "Campagne UI/fonctionnelle" python3 "$DIR/scripts/ui_campaign_verify.py"
  fi
  if [ "${FP_START_SKIP_UPLOAD:-0}" != "1" ] && [ -x "$DIR/scripts/portal_upload_ti_test.sh" ]; then
    fp_try_optional "Upload test TI (portail)" bash "$DIR/scripts/portal_upload_ti_test.sh"
  fi
  set -e
}

_start_health_check() {
  local fails=0
  curl -sf --max-time 8 "http://localhost:9200/_cluster/health" >/dev/null 2>&1 || fails=$((fails+1))
  curl -sfk --max-time 8 "https://localhost/dashboards/api/status" >/dev/null 2>&1 || fails=$((fails+1))
  curl -sfk --max-time 8 "https://localhost/grafana/api/health" >/dev/null 2>&1 || fails=$((fails+1))
  curl -sf --max-time 8 "http://localhost:5000/login" >/dev/null 2>&1 || fails=$((fails+1))
  [ "$fails" -eq 0 ]
}

start_open_ui() {
  [ "${FP_START_OPEN_UI:-1}" = "0" ] && return 0
  step "Ouverture UIs (navigateur intégré Cursor ou système)"
  if [ -x "$DIR/scripts/start_open_ui.sh" ]; then
    bash "$DIR/scripts/start_open_ui.sh" || warn "Ouverture UIs partielle"
  else
    warn "Script manquant: scripts/start_open_ui.sh"
  fi
}

open_ui() {
  start_open_ui
}

# Logs des services critiques (noms containers réels docker compose)
start_logs() {
  local tail_n="${1:-100}"
  local containers=(
    forensic-opensearch-1
    forensic-opensearch-dashboards
    forensic-timesketch-web
    forensic-timesketch-worker
    forensic-ingest-worker
    forensic-grafana
    forensic-logstash
    forensic-nginx
  )
  for c in "${containers[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
      step "Logs $c (tail $tail_n)"
      docker logs "$c" --tail "$tail_n" 2>&1 || true
    else
      warn "Container absent: $c"
    fi
  done
}

# ──────────────────────────────────────────────────────────────
#  FAST-BOOT — Dépendances, waiters rapides, status (CERT VM vierge)
# ──────────────────────────────────────────────────────────────

# --- PHASE 0 : dépendances --------------------------------------------------
# Installe Docker CE (méthode officielle) si le binaire docker est absent.
fp_install_docker_ce() {
  if command -v docker >/dev/null 2>&1; then
    return 0
  fi
  warn "Docker absent — installation Docker CE (get.docker.com)"
  if ! command -v curl >/dev/null 2>&1; then
    _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y curl >/dev/null 2>&1 || true
  fi
  if curl -fsSL https://get.docker.com -o /tmp/get-docker.sh 2>/dev/null; then
    if _fp_sudo sh /tmp/get-docker.sh >/dev/null 2>&1; then
      ok "Docker CE installé"
    else
      err "Installation Docker CE échouée — installer Docker manuellement"
      return 1
    fi
  else
    err "Téléchargement get.docker.com impossible (vérifier le réseau)"
    return 1
  fi
  _fp_sudo systemctl enable --now docker >/dev/null 2>&1 || true
  return 0
}

# Installe le plugin docker compose v2 si absent.
fp_install_compose_plugin() {
  command -v docker >/dev/null 2>&1 || return 1
  if docker compose version >/dev/null 2>&1; then
    return 0
  fi
  warn "Plugin docker compose v2 absent — installation (docker-compose-plugin)"
  if command -v apt-get >/dev/null 2>&1; then
    _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
  fi
  if docker compose version >/dev/null 2>&1; then
    ok "docker compose v2 OK"
    return 0
  fi
  warn "docker compose v2 toujours absent — vérifier l'installation Docker"
  return 1
}

# Vérifie que l'utilisateur est dans le groupe docker (sinon ajout).
fp_check_docker_group() {
  local u="${USER:-$(id -un)}"
  if id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    ok "Utilisateur '$u' dans le groupe docker"
    return 0
  fi
  warn "Utilisateur '$u' hors du groupe docker — ajout"
  if _fp_sudo usermod -aG docker "$u" >/dev/null 2>&1; then
    warn "Ajouté au groupe docker — exécuter 'newgrp docker' ou rouvrir la session"
  else
    warn "Impossible d'ajouter au groupe docker (sudo requis)"
  fi
  return 0
}

# Démarre dockerd s'il ne répond pas.
fp_start_dockerd() {
  if docker ps >/dev/null 2>&1; then
    return 0
  fi
  info "dockerd ne répond pas — tentative de démarrage..."
  _fp_sudo systemctl start docker >/dev/null 2>&1 \
    || _fp_sudo service docker start >/dev/null 2>&1 \
    || true
  local n=0
  while [ "$n" -lt 10 ]; do
    if docker ps >/dev/null 2>&1; then
      ok "dockerd démarré"
      return 0
    fi
    n=$((n+1)); sleep 1
  done
  return 1
}

# PHASE 0 complète — dépendances + Docker + compose + groupe + daemon.
fp_phase0_dependencies() {
  step "PHASE 0 — Vérification & installation des dépendances"
  if command -v pre_install >/dev/null 2>&1; then
    pre_install || warn "pre_install: vérifications partielles (voir logs/forensic_install.log)"
  fi
  if ! fp_install_docker_ce; then
    err "Docker indisponible — arrêt."
    return 1
  fi
  fp_install_compose_plugin || true
  fp_check_docker_group
  fp_start_dockerd || true
  if command -v fp_ensure_docker >/dev/null 2>&1; then
    if ! fp_ensure_docker; then
      err "Docker inaccessible — impossible de démarrer la plateforme."
      err "  Vérifier : docker ps    ·  groupe docker : newgrp docker"
      return 1
    fi
    command -v fp_bind_compose_cmds >/dev/null 2>&1 && fp_bind_compose_cmds
  fi
  return 0
}

# --- PHASE 1 : préparation système -----------------------------------------
# fp_check_ports — alias lisible vers cleanup_ports (vérif ports critiques).
fp_check_ports() {
  if command -v cleanup_ports >/dev/null 2>&1; then
    cleanup_ports
  else
    warn "cleanup_ports indisponible (module installer.sh absent)"
  fi
}

# Libère l'espace Docker RÉCUPÉRABLE si le disque est critique (≥ seuil %).
# Non destructif : ne touche QUE le cache de build et les images/containers
# dangling — jamais les volumes, ni les index, ni les données utilisateur.
fp_disk_guard() {
  local threshold="${FP_DISK_CRITICAL_PCT:-90}"
  local usepct
  usepct=$(df -P "$DIR" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
  [ -z "$usepct" ] && return 0
  info "Disque ($DIR): ${usepct}% utilisé"
  if [ "$usepct" -ge "$threshold" ]; then
    warn "Disque critique (${usepct}% ≥ ${threshold}%) — purge cache Docker récupérable (non destructif)"
    local docker_bin="${FP_DOCKER:-docker}"
    info "Purge Docker en cours (1–15 min selon le cache)..."
    if command -v timeout >/dev/null 2>&1; then
      timeout "${FP_DOCKER_PRUNE_TIMEOUT:-900}" $docker_bin builder prune -af >> "${FP_LOG_START:-$DIR/logs/forensic_start.log}" 2>&1 \
        || warn "Purge builder Docker timeout/partielle (continuer)"
    else
      $docker_bin builder prune -af >> "${FP_LOG_START:-$DIR/logs/forensic_start.log}" 2>&1 || true
    fi
    $docker_bin image prune -f >> "${FP_LOG_START:-$DIR/logs/forensic_start.log}" 2>&1 || true
    usepct=$(df -P "$DIR" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
    ok "Disque après purge: ${usepct}% utilisé"
  fi
}

# Réparation OpenSearch NON DESTRUCTIVE — cause RED #1 sur VM : flood watermark.
# Configure les watermarks disque + lève le blocage read-only + relance
# l'allocation. Aucune suppression d'index/volume.
fp_opensearch_repair() {
  local os_url="${OS_URL:-http://localhost:9200}"
  local n=0
  while [ "$n" -lt 30 ]; do
    if curl -sf --max-time 3 "$os_url" >/dev/null 2>&1; then
      break
    fi
    n=$((n+1)); sleep 2
  done
  if ! curl -sf --max-time 3 "$os_url" >/dev/null 2>&1; then
    warn "OpenSearch (:9200) injoignable — réparation disque/watermark différée"
    return 1
  fi
  if [ -f "$DIR/scripts/opensearch_disk_repair.py" ]; then
    info "Réparation disque/watermark OpenSearch (non destructive)..."
    OS_URL="$os_url" python3 "$DIR/scripts/opensearch_disk_repair.py" \
      || warn "Réparation OpenSearch partielle"
  fi
  # Attendre la STABILISATION de l'allocation (réplicas) avant l'activation :
  # sinon les écritures précoces (ISM, .opendistro-ism-config) échouent en
  # "shard_not_in_primary_mode" pendant la recovery. Non destructif.
  fp_opensearch_wait_green "$os_url" "${FP_OS_GREEN_TIMEOUT:-210}" || true
  return 0
}

# Booste les recoveries puis attend unassigned=0 & initializing=0 (GREEN),
# avec reroute périodique. Tolérant : retourne 0 si stable, 1 sinon (poursuite).
fp_opensearch_wait_green() {
  local os_url="${1:-http://localhost:9200}" timeout="${2:-210}" start_ts now
  curl -sf --max-time 8 -X PUT "$os_url/_cluster/settings" \
    -H 'Content-Type: application/json' \
    -d '{"transient":{"cluster.routing.allocation.node_concurrent_recoveries":8,"indices.recovery.max_bytes_per_sec":"200mb"}}' \
    >/dev/null 2>&1 || true
  info "Attente stabilisation allocation OpenSearch (max ${timeout}s)..."
  start_ts=$(date +%s)
  while true; do
    local h ua init
    h=$(curl -sf --max-time 5 "$os_url/_cluster/health" 2>/dev/null || true)
    if [ -n "$h" ]; then
      ua=$(echo "$h" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("unassigned_shards",1))' 2>/dev/null || echo 1)
      init=$(echo "$h" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("initializing_shards",1))' 2>/dev/null || echo 1)
      if [ "${ua:-1}" = "0" ] && [ "${init:-1}" = "0" ]; then
        ok "OpenSearch allocation stable (GREEN, 0 shard non assigné)"
        return 0
      fi
    fi
    now=$(date +%s)
    if [ $((now - start_ts)) -ge "$timeout" ]; then
      warn "OpenSearch: allocation non finalisée après ${timeout}s (poursuite)"
      return 1
    fi
    curl -sf --max-time 5 -X POST "$os_url/_cluster/reroute?retry_failed=true" >/dev/null 2>&1 || true
    sleep 6
  done
}

fp_phase1_system() {
  step "PHASE 1 — Préparation système (disque + SSL + sysctl + ports)"
  fp_disk_guard
  pre_start
  fp_check_ports
}

# --- PHASE 4 : waiters rapides (FAST-BOOT) ---------------------------------
# Attente OpenSearch rapide — accepte green/yellow, refuse red/injoignable.
fp_wait_opensearch() {
  local timeout="${1:-20}" start_ts now health
  info "Attente OpenSearch (max ${timeout}s)..."
  start_ts=$(date +%s)
  while true; do
    health=$(curl -sf --max-time 3 "http://localhost:9200/_cluster/health" 2>/dev/null || true)
    if [ -n "$health" ] && ! echo "$health" | grep -q '"status":"red"'; then
      ok "OpenSearch prêt"
      return 0
    fi
    now=$(date +%s)
    if [ $((now - start_ts)) -ge "$timeout" ]; then
      warn "OpenSearch: pas green/yellow après ${timeout}s (poursuite)"
      return 1
    fi
    sleep 2
  done
}

# Attente Timesketch rapide — /login répond.
fp_wait_timesketch() {
  local timeout="${1:-10}" start_ts now
  info "Attente Timesketch (max ${timeout}s)..."
  start_ts=$(date +%s)
  while true; do
    if curl -sf --max-time 3 "http://localhost:5000/login" >/dev/null 2>&1; then
      ok "Timesketch prêt"
      return 0
    fi
    now=$(date +%s)
    if [ $((now - start_ts)) -ge "$timeout" ]; then
      warn "Timesketch: timeout ${timeout}s (poursuite)"
      return 1
    fi
    sleep 2
  done
}

# Attente générique d'un container (running + healthy/none).
# $1=container $2=timeout $3=bloquant(1)/non-bloquant(0)
_fp_wait_container() {
  local c="$1" timeout="${2:-5}" blocking="${3:-1}" start_ts now st health
  start_ts=$(date +%s)
  while true; do
    st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null || echo "none")
    if [ "$st" = "running" ] && { [ "$health" = "healthy" ] || [ "$health" = "none" ]; }; then
      ok "$c prêt ($st/$health)"
      return 0
    fi
    now=$(date +%s)
    if [ $((now - start_ts)) -ge "$timeout" ]; then
      if [ "$blocking" = "1" ]; then
        warn "$c: pas prêt après ${timeout}s ($st/$health)"
      else
        warn "$c: pas prêt après ${timeout}s ($st/$health, non bloquant)"
      fi
      return 1
    fi
    sleep 1
  done
}

fp_phase4_waits() {
  step "PHASE 4 — Attente rapide des services critiques"
  fp_wait_opensearch 20            || START_WARN+=("OpenSearch (20s)")
  _fp_wait_container forensic-redis    5  1 || START_WARN+=("Redis")
  _fp_wait_container forensic-postgres 5  1 || START_WARN+=("Postgres")
  _fp_wait_container forensic-minio    5  1 || START_WARN+=("MinIO")
  fp_wait_timesketch 10            || START_WARN+=("Timesketch")
  _fp_wait_container forensic-grafana  5  1 || START_WARN+=("Grafana")
  _fp_wait_container forensic-opencti  10 0 || START_WARN+=("OpenCTI (non bloquant)")
  _fp_wait_container forensic-thehive  10 0 || START_WARN+=("TheHive (non bloquant)")
}

# --- PHASE 5 : status complet ----------------------------------------------
# fp_status — status global (containers + endpoints + cluster + réseau + TI).
fp_status() {
  if command -v status_full >/dev/null 2>&1; then
    status_full
  else
    docker compose ps
  fi
  fp_status_ti_connectors
}

# Connecteurs Threat Intelligence actifs (OpenCTI / MISP).
fp_status_ti_connectors() {
  command -v docker >/dev/null 2>&1 || return 0
  echo ""
  echo -e "${CYAN}── Connecteurs Threat Intelligence ──${NC}"
  local total up
  total=$(docker ps -a --filter "name=forensic-connector" -q 2>/dev/null | wc -l | tr -d ' ')
  up=$(docker ps --filter "name=forensic-connector" --filter "status=running" -q 2>/dev/null | wc -l | tr -d ' ')
  if [ "${total:-0}" -eq 0 ]; then
    echo "  (aucun connecteur déployé)"
    return 0
  fi
  echo "  Actifs: ${up}/${total}"
  docker ps -a --filter "name=forensic-connector" \
    --format '  {{.Names}}	{{.Status}}' 2>/dev/null \
    | sed 's/forensic-connector-//' | head -40 || true
}

# ──────────────────────────────────────────────────────────────
#  ORCHESTRATEUR CLÉ EN MAIN — ./forensic.sh -full-start
#  Phases 1-3 (système, deps, monorepo) → full_start → santé → tests → rapport
# ──────────────────────────────────────────────────────────────
full_start_orchestrator() {
  local _e=0
  case $- in *e*) _e=1;; esac
  set +e

  FP_ORCH_START_TS=$(date +%s)
  FP_ORCH_REPORT=()
  FP_ORCH_TEST_OK=0
  FP_ORCH_TEST_FAIL=0
  START_OK=()
  START_FAIL=()
  START_WARN=()

  local ip
  ip=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || fp_detect_public_host 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
  [ -n "$ip" ] && export FP_ORCH_BASE_URL="https://${ip}"

  echo ""
  info "╔══════════════════════════════════════════════════════════════╗"
  info "║  FORENSIC-MINIMAL — ORCHESTRATEUR FULL-START                 ║"
  info "║  Install · Build · Start · Test · Rapport                    ║"
  info "╚══════════════════════════════════════════════════════════════╝"
  echo ""

  if command -v fp_bootstrap_fresh_machine >/dev/null 2>&1; then
    if ! fp_bootstrap_fresh_machine; then
      err "Bootstrap machine vierge échoué — corriger puis relancer ./forensic.sh -full-start"
      command -v fp_full_start_final_report >/dev/null 2>&1 && fp_full_start_final_report 1
      [ "$_e" -eq 1 ] && set -e
      return 1
    fi
  else
    warn "fp_bootstrap_fresh_machine indisponible (installer.sh)"
  fi

  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null \
    | grep -qE '^forensic-'; then
    local other_proj
    other_proj=$(docker ps --filter "name=forensic-nginx" --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | head -1)
    if [ -n "$other_proj" ] && [ "$other_proj" != "$(basename "$DIR")" ]; then
      warn "Stack forensic déjà active (projet Docker: $other_proj) — ports 80/443/9200… occupés"
      warn "  Sur machine vierge : OK. Ici : arrêter l'autre stack → cd ../$other_proj && ./forensic.sh full-stop"
      _fp_orch_note "Conflit ports: projet $other_proj actif"
    fi
  fi

  command -v fp_verify_system >/dev/null 2>&1 && fp_verify_system || warn "fp_verify_system indisponible"

  if ! fp_phase0_dependencies; then
    command -v fp_full_start_final_report >/dev/null 2>&1 && fp_full_start_final_report 1
    [ "$_e" -eq 1 ] && set -e
    return 1
  fi

  command -v fp_install_dependencies_extended >/dev/null 2>&1 && fp_install_dependencies_extended || true

  if command -v fp_verify_monorepo >/dev/null 2>&1; then
    if ! fp_verify_monorepo; then
      err "Monorepo invalide — arrêt orchestrateur"
      command -v fp_full_start_final_report >/dev/null 2>&1 && fp_full_start_final_report 1
      [ "$_e" -eq 1 ] && set -e
      return 1
    fi
  fi

  fp_phase1_system

  FP_ORCH_PREAMBLE_DONE=1
  FP_FULL_BOOT=1
  FP_START_BUILD_PORTALS=1
  FP_FULL_ORCHESTRATOR=1

  full_start
  local fs_rc=$?

  command -v fp_full_start_health_global >/dev/null 2>&1 && fp_full_start_health_global || true
  if [ -x "$DIR/scripts/verify-platform-ready.sh" ]; then
    step "ORCHESTRATEUR — Vérification portail + outils (HTTPS)"
    if bash "$DIR/scripts/verify-platform-ready.sh"; then
      ok "verify-platform-ready : portail et outils OK"
    else
      warn "verify-platform-ready : échecs — relancer ./forensic.sh -full-start ou voir logs/forensic_start.log"
      fs_rc=1
    fi
  fi
  command -v fp_full_start_extended_tests >/dev/null 2>&1 && fp_full_start_extended_tests || true

  if command -v fp_full_start_final_report >/dev/null 2>&1; then
    fp_full_start_final_report "$fs_rc"
  fi

  [ "$_e" -eq 1 ] && set -e
  return "$fs_rc"
}

# ──────────────────────────────────────────────────────────────
#  FULL-BOOT (stack Docker + build + activation SIEM/TI/Timesketch/Grafana)
#  Activé via : ./forensic.sh rebuild | full-start  ou  FP_FULL_BOOT=1
# ──────────────────────────────────────────────────────────────
full_start() {
  local _start_had_e=0
  case $- in *e*) _start_had_e=1;; esac
  set +e

  START_OK=()
  START_FAIL=()
  START_WARN=()

  # PHASE 5 — Logging structuré (no-op si module absent)
  command -v fp_log_init >/dev/null 2>&1 && fp_log_init
  command -v fp_log >/dev/null 2>&1 && fp_log start "===== ./forensic.sh start ($(date)) ====="

  # PHASE 1 — Pré-installation (packages + groupe docker + sysctl)
  if [ "${FP_ORCH_PREAMBLE_DONE:-0}" != "1" ]; then
    if command -v pre_install >/dev/null 2>&1; then
      pre_install || warn "pre_install: certaines vérifications ont échoué (voir logs/forensic_install.log)"
    fi
  fi

  # Docker obligatoire avant toute opération compose/réseau
  if command -v fp_ensure_docker >/dev/null 2>&1; then
    if ! fp_ensure_docker; then
      err "Docker inaccessible — impossible de démarrer la plateforme."
      err "  Vérifier : docker ps"
      err "  Groupe docker : newgrp docker  (ou rouvrir le terminal)"
      [ "$_start_had_e" -eq 1 ] && set -e
      return 1
    fi
    command -v fp_bind_compose_cmds >/dev/null 2>&1 && fp_bind_compose_cmds
  fi

  # Garde-fou disque (purge cache Docker récupérable si disque critique)
  fp_disk_guard

  # PHASE 2 — Nettoyage avant start (processus, ports, réseaux)
  if command -v cleanup_processes >/dev/null 2>&1; then
    cleanup_processes || true
  fi
  if command -v cleanup_ports >/dev/null 2>&1; then
    cleanup_ports || true
  fi

  pre_start
  cleanup_network 2>&1 | tee -a "${FP_LOG_NETWORK:-/dev/null}" >/dev/null || true

  # PHASE 2bis — Réparation réseau Docker FP (AVANT phase 0/8)
  # Garantit que fp-final2_forensic-net existe avec le bon subnet.
  if command -v fp_network_repair >/dev/null 2>&1; then
    if ! fp_network_repair; then
      err "Réparation réseau Docker FP impossible — arrêt propre du start."
      err "  • Diagnostic : docker ps && docker network ls"
      err "  • Inspect   : docker network inspect ${FP_NET_NAME:-fp-final2_forensic-net}"
      err "  • Logs      : tail -50 logs/forensic_network.log"
      [ "$_start_had_e" -eq 1 ] && set -e
      return 1
    fi
  fi

  echo ""
  info "╔══════════════════════════════════════════════╗"
  info "║  CYBER FORENSIC PLATFORM v2.1 — START       ║"
  info "║  Stack + SIEM/TI + Timesketch + Grafana     ║"
  info "╚══════════════════════════════════════════════╝"
  echo ""

  start_build_images

  # ── Phase 1: Infrastructure ──────────────────────────────────
  step "1/8 Infrastructure (PostgreSQL, Redis, RabbitMQ, Cassandra)"
  $UP postgres redis rabbitmq cassandra
  sleep 5
  if ! wait_postgres; then
    START_FAIL+=("PostgreSQL readiness")
    warn "PostgreSQL non prêt — poursuite avec risque"
  fi
  ok "Infrastructure OK"

  # ── Phase 2: MinIO ───────────────────────────────────────────
  step "2/8 MinIO + buckets"
  $UP minio
  wait_http "http://localhost:9000/minio/health/live" 24 5 "MinIO"
  $UP minio-init
  sleep 5
  ok "MinIO OK"

  # ── Phase 3: OpenSearch ──────────────────────────────────────
  step "3/8 OpenSearch 2.12.0"
  $UP opensearch-node1 opensearch-node2
  # Réparation disque/watermark AVANT l'attente (évite RED par flood watermark).
  fp_opensearch_repair || true
  if ! wait_opensearch; then
    # 2e passe : forcer la réparation puis réessayer une fois.
    fp_opensearch_repair || true
    if ! wait_opensearch; then
      START_FAIL+=("OpenSearch readiness")
      warn "OpenSearch non prêt — poursuite avec risque (./forensic.sh fix-opensearch)"
    fi
  fi
  $UP opensearch-dashboards opensearch-init
  sleep 8

  # ── Phase 4: SIEM + Timesketch ───────────────────────────────
  step "4/8 Logstash + Filebeat + Timesketch"
  $UP logstash filebeat
  $UP timesketch-web
  # Attendre que Timesketch réponde vraiment (init DB + migrations)
  wait_container_http "forensic-timesketch-web" "http://127.0.0.1:5000/login" 72 5 "Timesketch"
  bash "$DIR/scripts/timesketch-patch-explore.sh" 2>/dev/null || true
  $UP timesketch-worker
  $UP timesketch-init 2>/dev/null || true
  sleep 5
  ok "SIEM & Timesketch OK"

  # ── Phase 5: CTI + IR + IOC + Grafana ────────────────────────
  step "5/8 OpenCTI + MISP + TheHive + Cortex + Grafana"
  $UP misp-db
  sleep 8
  $UP misp
  $UP opencti
  info "OpenCTI démarré (~3-5min au 1er boot)"
  $UP connector-mitre connector-cve connector-opencti-datasets connector-urlhaus connector-vxvault
  info "Connecteurs Threat Intelligence (TI)..."
  bash "$DIR/scripts/opencti-start-ti.sh" 2>/dev/null || \
    docker compose --profile connectors-ti up -d 2>/dev/null || true
  $UP thehive cortex
  info "Bootstrap indicateurs OpenCTI si vide (URLhaus)..."
  OPENCTI_BOOTSTRAP_MAX=120 python3 "$DIR/scripts/opencti-bootstrap-indicators.py" 2>/dev/null || true
  wait_http "http://localhost:9002/thehive/api/status" 36 5 "TheHive"
  $UP thehive-init 2>/dev/null || true
  $UP grafana
  sleep 8
  ok "Phase 5 OK"

  # ── Phase 6: Portails + Nginx + Portainer ────────────────────
  step "6/8 Portails CERT + IT + ingest-worker + Nginx HTTPS + Portainer"
  docker compose up -d --build ingest-worker 2>/dev/null || $UP ingest-worker
  if [ "${FP_RECREATE_CERT_PORTAL:-0}" = "1" ]; then
    info "Recréation cert-portal ( .env régénéré )"
    docker compose up -d --force-recreate --build cert-portal it-portal 2>/dev/null || $UP cert-portal it-portal
  else
    $UP cert-portal it-portal
  fi
  sleep 8
  if [ "${FP_SKIP_SIDECARS:-0}" != "1" ] && [ -x "$DIR/scripts/setup-sidecars.sh" ]; then
    step "6a/8 Sidecars HELK / Velociraptor (avant Nginx)"
    if bash "$DIR/scripts/setup-sidecars.sh" 2>&1 \
      | tee -a "${FP_LOG_START:-$DIR/logs/forensic_start.log}"; then
      ok "Sidecars HELK/Velociraptor OK"
    else
      START_FAIL+=("Sidecars HELK/Velociraptor")
      err "Sidecars HELK/Velociraptor échoués — /velociraptor/ risque 502 Bad Gateway"
    fi
  elif [ "${FP_FULL_ORCHESTRATOR:-0}" = "1" ] && [ -x "$DIR/scripts/helk_velociraptor_master_setup.sh" ]; then
    step "6a/8 Sidecars HELK / Velociraptor (avant Nginx)"
    if bash "$DIR/scripts/helk_velociraptor_master_setup.sh" 2>&1 \
      | tee -a "${FP_LOG_START:-$DIR/logs/forensic_start.log}"; then
      ok "Sidecars HELK/Velociraptor OK"
    else
      START_FAIL+=("Sidecars HELK/Velociraptor")
      err "Sidecars HELK/Velociraptor échoués — /velociraptor/ risque 502 Bad Gateway"
    fi
  fi
  if command -v fp_prepare_platform_host >/dev/null 2>&1; then
    fp_prepare_platform_host 2>&1 | tee -a "${FP_LOG_START:-$DIR/logs/forensic_start.log}" \
      || warn "Préparation hôte IP / nginx partielle"
  fi
  # Nginx résout velociraptor-bridge / helk-bridge au démarrage — les lancer avant nginx
  # même si le setup HELK/VR sidecar a échoué partiellement (ex. port Kafka occupé).
  $UP helk-bridge velociraptor-bridge 2>/dev/null || true
  $UP nginx

  START_OK+=("Services Docker (8 phases stack)")

  step "6b/8 Attente stabilisation services"
  start_wait_frontends

  start_activation_layers
  start_automated_tests

  step "6c/8 Finalisation accès IP — MISP / HELK / VR / nginx"
  if command -v fp_finalize_platform_access >/dev/null 2>&1; then
    if fp_finalize_platform_access 2>&1 | tee -a "${FP_LOG_START:-$DIR/logs/forensic_start.log}"; then
      ok "Finalisation accès IP OK"
    else
      START_FAIL+=("Finalisation accès IP (MISP/VR/verify)")
      err "Finalisation plateforme échouée — voir logs/forensic_start.log"
    fi
  elif [ -x "$DIR/scripts/post-start-align.sh" ]; then
    if bash "$DIR/scripts/post-start-align.sh" 2>&1 \
      | tee -a "${FP_LOG_START:-$DIR/logs/forensic_start.log}"; then
      ok "post-start-align OK"
    else
      START_FAIL+=("post-start-align (MISP/VR/verify)")
      err "post-start-align échoué — voir logs/forensic_start.log"
    fi
  fi

  # Appliquer les mappings OpenSearch en arrière-plan (30s délai pour init)
  (sleep 30; fix_existing_data >/dev/null 2>&1) &

  echo ""
  if start_print_summary; then
    ok "╔══════════════════════════════════════════════════╗"
    ok "║  PLATEFORME PRÊTE — SIEM/TI + Timesketch + GF  ║"
    ok "╚══════════════════════════════════════════════════╝"
  else
    warn "╔══════════════════════════════════════════════════╗"
    warn "║  PLATEFORME DÉMARRÉE — certaines étapes ont échoué ║"
    warn "╚══════════════════════════════════════════════════╝"
  fi

  urls
  start_open_ui

  # PHASE 6 — Tests automatiques avec BOUCLE auto-réparation (3 retries max)
  if command -v fp_auto_repair_loop >/dev/null 2>&1; then
    fp_auto_repair_loop || warn "Auto-réparation épuisée — vérification humaine requise (voir diagnostic ci-dessus)"
  elif command -v fp_start_tests >/dev/null 2>&1; then
    if ! fp_start_tests; then
      START_FAIL+=("Tests automatiques post-démarrage")
      warn "Tests automatiques post-démarrage — échecs (Velociraptor/sidecar ?)"
    fi
  fi
  if command -v status_full >/dev/null 2>&1; then
    status_full || true
  fi

  # Validation humaine — pas de "OK produit"
  echo ""
  echo -e "${YELLOW}━━━ VALIDATION ━━━${NC}"
  local _access_ip
  _access_ip=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "localhost")
  echo "  • Accès plateforme : https://${_access_ip}/"
  echo "  • Logs : logs/forensic_start.log, logs/forensic_install.log"
  echo "  • Statut : ./forensic.sh status"
  echo ""
  command -v fp_log >/dev/null 2>&1 && fp_log start "===== start terminé : OK=${#START_OK[@]} WARN=${#START_WARN[@]} FAIL=${#START_FAIL[@]} ====="

  local _rc=0
  [ "${#START_FAIL[@]}" -eq 0 ] || _rc=1
  [ "$_start_had_e" -eq 1 ] && set -e
  return "$_rc"
}

# Liste les services compose dont l'image est présente localement (ou dont
# l'image de build existe déjà). Permet, en FAST-BOOT (--no-build --pull never),
# de ne PAS lancer les services à image absente : sinon `docker compose up`
# avorte sur "No such image" et laisse les autres services non réconciliés.
fp_present_services() {
  local compose="${FP_COMPOSE:-docker compose}"
  local docker_bin="${FP_DOCKER:-docker}"
  $compose config --format json 2>/dev/null \
    | FP_DOCKER_BIN="$docker_bin" FP_PROJECT="$(basename "$DIR")" python3 -c '
import json, sys, os, subprocess, shlex
docker = shlex.split(os.environ.get("FP_DOCKER_BIN", "docker"))
proj = os.environ.get("FP_PROJECT", "")
def has_image(img):
    return subprocess.run(docker + ["image", "inspect", img],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0
try:
    cfg = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for name, s in (cfg.get("services") or {}).items():
    img = s.get("image")
    ok = False
    if img and has_image(img):
        ok = True
    elif s.get("build"):
        for cand in ([img] if img else []) + [proj + "-" + name, proj + "_" + name]:
            if cand and has_image(cand):
                ok = True
                break
    if ok:
        print(name)
' 2>/dev/null
}

# ──────────────────────────────────────────────────────────────
#  FAST-BOOT — démarrage rapide (défaut) : sans build, pull, patchs ni QA
# ──────────────────────────────────────────────────────────────
fast_start() {
  local _e=0
  case $- in *e*) _e=1;; esac
  set +e

  START_OK=(); START_FAIL=(); START_WARN=()
  command -v fp_log_init >/dev/null 2>&1 && fp_log_init
  command -v fp_log >/dev/null 2>&1 && fp_log start "===== FAST-BOOT ($(date)) ====="

  echo ""
  info "╔══════════════════════════════════════════════════╗"
  info "║  CYBER FORENSIC PLATFORM — FAST-BOOT (CERT)       ║"
  info "╚══════════════════════════════════════════════════╝"
  echo ""

  # PHASE 0 — dépendances + Docker
  if ! fp_phase0_dependencies; then
    [ "$_e" -eq 1 ] && set -e
    return 1
  fi

  # PHASE 1 — préparation système
  fp_phase1_system

  # PHASE 2 — réseau FP (sans patch compose, sans migration de subnet)
  if command -v fp_network_repair >/dev/null 2>&1; then
    step "PHASE 2 — Réseau FP"
    FP_NET_NO_PATCH=1 fp_network_repair \
      || warn "Réparation réseau partielle — voir logs/forensic_network.log"
  fi

  # PHASE 3 — FAST-BOOT
  step "PHASE 3 — Lancement plateforme (FAST-BOOT : sans build ni pull)"
  local compose="${FP_COMPOSE:-docker compose}"

  # On ne lance que les services dont l'image est déjà présente : un service à
  # image absente ferait avorter tout le `compose up` (--pull never --no-build).
  local present all excluded
  present=$(fp_present_services | sort -u)
  all=$($compose config --services 2>/dev/null | sort -u)
  if [ -n "$present" ] && [ -n "$all" ]; then
    excluded=$(comm -23 <(printf '%s\n' "$all") <(printf '%s\n' "$present"))
  else
    excluded=""
  fi
  if [ -n "$excluded" ]; then
    warn "Services à image absente (ignorés en FAST-BOOT, pas de pull/build) :"
    printf '%s\n' "$excluded" | sed 's/^/    • /'
    warn "  → Pour les construire/récupérer : ./forensic.sh full-start"
    START_WARN+=("Services à image absente ($(printf '%s\n' "$excluded" | grep -c . | tr -d ' '))")
  fi

  local up_out up_rc=0
  if [ -n "$present" ]; then
    # shellcheck disable=SC2086
    up_out=$($compose up -d --no-build --pull never $present 2>&1) || up_rc=$?
  else
    up_out=$($compose up -d --no-build --pull never 2>&1) || up_rc=$?
  fi
  echo "$up_out"
  if [ "$up_rc" -eq 0 ]; then
    ok "docker compose up -d --no-build --pull never (services à image présente)"
    START_OK+=("FAST-BOOT compose up")
  else
    # Échecs tolérés (non bloquants) : un service attend une dépendance non
    # saine (ex. OpenSearch RED). Le cœur tourne et les services en attente
    # démarreront dès que la dépendance redeviendra saine. Tout autre motif
    # (config invalide, etc.) reste bloquant.
    local hard
    hard=$(echo "$up_out" \
      | grep -iE "error|cannot|failed" \
      | grep -viE "dependency .* failed to start|is unhealthy|dependency failed to start|No such image" \
      || true)
    if [ -z "$hard" ]; then
      echo "$up_out" | grep -iE "is unhealthy|dependency failed to start" | sort -u | sed 's/^/    /'
      warn "compose up incomplet : dépendance(s) non saine(s) (ex. OpenSearch)."
      warn "  Les services en attente démarreront dès la dépendance saine."
      warn "  → OpenSearch dégradé ? : ./forensic.sh full-start  ou  ./forensic.sh fix-opensearch"
      START_WARN+=("compose up: dépendance non saine (non bloquant)")
    else
      warn "docker compose up partiel — erreurs bloquantes :"
      echo "$hard" | sort -u | sed 's/^/    /'
      START_FAIL+=("FAST-BOOT compose up")
    fi
  fi

  # PHASE 3bis — réparation OpenSearch (watermark/read-only) AVANT les attentes :
  # garantit un cluster green/yellow et débloque les services dépendants.
  step "PHASE 3bis — Réparation OpenSearch (disque/watermark, non destructif)"
  fp_opensearch_repair || true
  # Relance les services qui attendaient un OpenSearch sain (créés mais non démarrés).
  $compose up -d --no-build --pull never >/dev/null 2>&1 || true

  # PHASE 4 — attente rapide des services critiques
  fp_phase4_waits

  # PHASE 5 — STATUS final complet
  urls
  fp_status

  echo ""
  if [ "${#START_FAIL[@]}" -eq 0 ]; then
    ok "╔══════════════════════════════════════════════════╗"
    ok "║  FAST-BOOT TERMINÉ — plateforme opérationnelle    ║"
    ok "╚══════════════════════════════════════════════════╝"
  else
    warn "╔══════════════════════════════════════════════════╗"
    warn "║  FAST-BOOT terminé AVEC erreurs (voir ci-dessus)  ║"
    warn "╚══════════════════════════════════════════════════╝"
  fi
  if [ "${#START_WARN[@]}" -gt 0 ]; then
    warn "Avertissements (non bloquants): ${START_WARN[*]}"
  fi
  echo -e "${CYAN}  ↳ FULL-BOOT (build + patchs + QA) : ./forensic.sh full-start | rebuild${NC}"

  command -v fp_log >/dev/null 2>&1 && \
    fp_log start "FAST-BOOT terminé: OK=${#START_OK[@]} WARN=${#START_WARN[@]} FAIL=${#START_FAIL[@]}"

  local rc=0
  [ "${#START_FAIL[@]}" -eq 0 ] || rc=1
  [ "$_e" -eq 1 ] && set -e
  return "$rc"
}

# Point d'entrée `start` : FAST-BOOT par défaut, FULL-BOOT si FP_FULL_BOOT=1.
start() {
  if [ "${FP_FULL_BOOT:-0}" = "1" ]; then
    full_start
    return $?
  fi
  fast_start
}

# ──────────────────────────────────────────────────────────────
#  STOP / RESTART
# ──────────────────────────────────────────────────────────────
stop()    { info "Arrêt..."; $DOWN; ok "Arrêt complet"; }
restart() { stop; sleep 3; start; }
status()  {
  if command -v status_full >/dev/null 2>&1; then
    status_full
  else
    docker compose ps
  fi
}

# ──────────────────────────────────────────────────────────────
#  HEALTH CHECK
# ──────────────────────────────────────────────────────────────
health() {
  echo ""
  _c() {
    local name="$1" url="$2" ok_flag=0
    local code
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "$url" 2>/dev/null || echo "000")
    # OpenCTI /health renvoie 401 sans token — service up si 200 ou 401
    if [ "$code" = "200" ] || { [ "$name" = "OpenCTI" ] || [ "$name" = "OpenCTI (direct)" ]; } && [ "$code" = "401" ]; then
      ok_flag=1
    fi
    if [ "$ok_flag" -eq 1 ]; then
      echo -e "  ${GREEN}✓${NC} ${name}"
    else
      echo -e "  ${RED}✗${NC} ${name}  (${url})"
    fi
  }
  echo -e "${CYAN}=== Health checks ===${NC}"
  _c "OpenSearch"            "http://localhost:9200/_cluster/health"
  _c "OpenSearch Dashboards" "http://localhost:5601/dashboards/api/status"
  _c "Logstash"              "http://localhost:9700/"
  _c "Timesketch"            "http://localhost:5000/login"
  _c "OpenCTI"               "https://localhost/cti/health"
  _c "OpenCTI (direct)"      "http://localhost:8080/cti/health"
  _c "MISP"                  "http://localhost:8090/"
  _c "TheHive"               "http://localhost:9002/thehive/api/status"
  _c "Cortex"                "http://localhost:9003/api/status"
  _c "Grafana"               "http://localhost:3001/api/health"
  _c "MinIO API"             "http://localhost:9000/minio/health/live"
  _c "MinIO Console"         "http://localhost:9001/"
  _c "Portail CERT (direct)" "http://localhost:3000/api/health"
  _c "Portail IT (direct)"   "http://localhost:3002/api/health"
  echo ""
  _c "Nginx HTTP→HTTPS"      "http://localhost:80/nginx-health"
  _c "Nginx HTTPS /"         "https://localhost:443/"
  _c "Nginx /dashboards/"    "https://localhost/dashboards/"
  _c "Nginx /grafana/"       "https://localhost/grafana/"
  _c "Nginx /cti/"           "https://localhost/cti/"
  _c "Nginx /thehive/"       "https://localhost/thehive/"
  _c "Nginx /it/"            "https://localhost/it/api/health"
}

# ──────────────────────────────────────────────────────────────
#  LOGS
# ──────────────────────────────────────────────────────────────
logs() {
  local svc="${2:-}"
  docker compose logs --tail=150 -f $svc
}

# ──────────────────────────────────────────────────────────────
#  MISE À JOUR PORTAILS (--no-cache)
# ──────────────────────────────────────────────────────────────
update_portals() {
  step "Rebuild portails (--no-cache)"
  docker compose build --no-cache cert-portal it-portal
  docker compose up -d cert-portal it-portal
  sleep 5
  if docker exec forensic-nginx nginx -s reload >/dev/null 2>&1; then
    ok "Nginx rechargé"
  fi
  ok "Portails mis à jour"
}

# ──────────────────────────────────────────────────────────────
#  FIX DONNÉES EXISTANTES (mapping OpenSearch + MISP reset)
# ──────────────────────────────────────────────────────────────
fix_existing_data() {
  step "Correction données existantes"

  info "Mise à jour mapping OpenSearch (portal + status + upload_id)..."
  for idx in forensic-uploads-000001 forensic-tokens-000001; do
    local result
    result=$(curl -sf -X PUT "http://localhost:9200/${idx}/_mapping" \
      -H "Content-Type: application/json" \
      -d '{"properties":{"portal":{"type":"keyword"},"status":{"type":"keyword"},
           "upload_id":{"type":"keyword"},"case_id":{"type":"keyword"},
           "token_id":{"type":"keyword"},"priority":{"type":"keyword"}}}' 2>/dev/null || true)
    if echo "$result" | grep -q '"acknowledged":true'; then
      ok "Mapping $idx mis à jour"
    else
      warn "Mapping $idx: $result"
    fi
  done

  info "Refresh indices..."
  curl -sf -X POST "http://localhost:9200/forensic-uploads*/_refresh" >/dev/null 2>&1 || true
  curl -sf -X POST "http://localhost:9200/forensic-tokens*/_refresh"  >/dev/null 2>&1 || true
  ok "Refresh OK"

  info "Reset credentials MISP..."
  bash "$DIR/scripts/misp-init.sh"
}

# ──────────────────────────────────────────────────────────────
#  RELOAD NGINX
# ──────────────────────────────────────────────────────────────
reload_nginx() {
  pre_start
  if docker exec forensic-nginx nginx -t >/dev/null 2>&1; then
    docker exec forensic-nginx nginx -s reload
    ok "Nginx rechargé"
  else
    err "Config nginx invalide"
    docker exec forensic-nginx nginx -t 2>&1
  fi
}

# ──────────────────────────────────────────────────────────────
#  TIMESKETCH AVANCÉ (Sigma / TI / analyzers — POINT 2)
# ──────────────────────────────────────────────────────────────
timesketch_advanced() {
  step "Timesketch avancé — activation Sigma/TI/analyzers"
  if [ ! -x "$DIR/scripts/activate_timesketch_advanced.sh" ]; then
    err "Script manquant: $DIR/scripts/activate_timesketch_advanced.sh"
    return 1
  fi
  info "Lancement scripts/activate_timesketch_advanced.sh ..."
  if bash "$DIR/scripts/activate_timesketch_advanced.sh"; then
    ok "Timesketch avancé activé — voir docs/POINT2_TIMESKETCH_ACTIVATION.md"
    return 0
  fi
  err "Activation Timesketch avancé échouée (code de sortie non nul)"
  return 1
}

observability_deep_test() {
  step "OpenSearch + Grafana — deep test (cluster, OSD, datasources, dashboards)"
  for s in opensearch_deep_test.sh grafana_deep_test.sh observability_deep_test.sh; do
    if [ ! -f "$DIR/scripts/$s" ]; then
      err "Script manquant: $DIR/scripts/$s"
      return 1
    fi
  done
  chmod +x "$DIR/scripts/opensearch_deep_test.sh" \
            "$DIR/scripts/grafana_deep_test.sh" \
            "$DIR/scripts/observability_deep_test.sh" 2>/dev/null || true
  if bash "$DIR/scripts/observability_deep_test.sh"; then
    ok "Deep test OpenSearch/Grafana OK — logs/opensearch_deep_test.log + logs/grafana_deep_test.log"
    return 0
  fi
  err "Deep test OpenSearch/Grafana échoué"
  return 1
}

opensearch_deep_test() {
  step "OpenSearch — deep test"
  chmod +x "$DIR/scripts/opensearch_deep_test.sh" 2>/dev/null || true
  bash "$DIR/scripts/opensearch_deep_test.sh"
}

grafana_deep_test() {
  step "Grafana — deep test"
  chmod +x "$DIR/scripts/grafana_deep_test.sh" 2>/dev/null || true
  bash "$DIR/scripts/grafana_deep_test.sh"
}

grafana_timesketch() {
  step "Grafana — dashboards Timesketch (POINT 4)"
  if [ ! -x "$DIR/scripts/grafana_import_timesketch_dashboards.sh" ]; then
    err "Script manquant: $DIR/scripts/grafana_import_timesketch_dashboards.sh"
    return 1
  fi
  info "Prérequis recommandés : timesketch-advanced + timesketch-e2e pour données réelles"
  if bash "$DIR/scripts/grafana_import_timesketch_dashboards.sh"; then
    ok "Dashboards Timesketch importés — docs/POINT4_TIMESKETCH_GRAFANA.md"
    echo ""
    echo -e "${CYAN}Grafana Timesketch Overview :${NC} https://localhost/grafana/d/timesketch-overview"
    echo -e "${CYAN}Grafana Timesketch Workflow :${NC} https://localhost/grafana/d/timesketch-analyst-workflow"
    return 0
  fi
  err "Import Grafana Timesketch échoué — logs/grafana_timesketch_import.log"
  return 1
}

grafana_timesketch_verify() {
  step "Grafana — vérification dashboards Timesketch"
  if [ ! -f "$DIR/scripts/grafana_timesketch_verify.py" ]; then
    err "Script manquant: scripts/grafana_timesketch_verify.py"
    return 1
  fi
  if python3 "$DIR/scripts/grafana_timesketch_verify.py"; then
    ok "grafana_timesketch_verify.py OK"
    return 0
  fi
  err "Vérification Grafana Timesketch échouée"
  return 1
}

grafana_master_setup() {
  step "Grafana Master — setup enterprise"
  python3 "$DIR/scripts/grafana_master_setup.py" || return 1
  ok "grafana_master_setup.py OK"
}

grafana_master_verify() {
  step "Grafana Master — verify API"
  python3 "$DIR/scripts/grafana_master_verify.py" || return 1
  ok "grafana_master_verify.py OK"
}

grafana_master_ui_verify() {
  step "Grafana Master — verify UI"
  python3 "$DIR/scripts/grafana_master_ui_verify.py" || return 1
  ok "grafana_master_ui_verify.py OK"
}

opencti_master_setup() {
  step "OpenCTI Master — setup enterprise CTI"
  python3 "$DIR/scripts/opencti_master_setup.py" || return 1
  ok "opencti_master_setup.py OK"
}

opencti_master_verify() {
  step "OpenCTI Master — verify API"
  python3 "$DIR/scripts/opencti_master_verify.py" || return 1
  ok "opencti_master_verify.py OK"
}

opencti_master_ui_verify() {
  step "OpenCTI Master — verify UI"
  python3 "$DIR/scripts/opencti_master_ui_verify.py" || return 1
  ok "opencti_master_ui_verify.py OK"
}

misp_master_setup() {
  step "MISP Master — setup enterprise MISP"
  python3 "$DIR/scripts/misp_master_setup.py" || return 1
  ok "misp_master_setup.py OK"
}

misp_master_verify() {
  step "MISP Master — verify API"
  python3 "$DIR/scripts/misp_master_verify.py" || return 1
  ok "misp_master_verify.py OK"
}

misp_master_ui_verify() {
  step "MISP Master — verify UI"
  python3 "$DIR/scripts/misp_master_ui_verify.py" || return 1
  ok "misp_master_ui_verify.py OK"
}

thehive_master_setup() {
  step "TheHive Master — setup enterprise IR"
  python3 "$DIR/scripts/thehive_master_setup.py" || return 1
  ok "thehive_master_setup.py OK"
}

thehive_master_verify() {
  step "TheHive Master — verify API"
  python3 "$DIR/scripts/thehive_master_verify.py" || return 1
  ok "thehive_master_verify.py OK"
}

thehive_master_ui_verify() {
  step "TheHive Master — verify UI"
  python3 "$DIR/scripts/thehive_master_ui_verify.py" || return 1
  ok "thehive_master_ui_verify.py OK"
}

cortex_master_setup() {
  step "Cortex Master — setup analyzers/responders + intégrations"
  python3 "$DIR/scripts/cortex_master_setup.py" || return 1
  ok "cortex_master_setup.py OK"
}

cortex_master_verify() {
  step "Cortex Master — verify API"
  python3 "$DIR/scripts/cortex_master_verify.py" || return 1
  ok "cortex_master_verify.py OK"
}

cortex_master_ui_verify() {
  step "Cortex Master — verify UI"
  python3 "$DIR/scripts/cortex_master_ui_verify.py" || return 1
  ok "cortex_master_ui_verify.py OK"
}

minio_master_setup() {
  step "MinIO Master — buckets premium + RBAC + intégrations"
  python3 "$DIR/scripts/minio_master_setup.py" || return 1
  ok "minio_master_setup.py OK"
}

minio_master_verify() {
  step "MinIO Master — verify API"
  python3 "$DIR/scripts/minio_master_verify.py" || return 1
  ok "minio_master_verify.py OK"
}

minio_master_ui_verify() {
  step "MinIO Master — verify UI"
  python3 "$DIR/scripts/minio_master_ui_verify.py" || return 1
  ok "minio_master_ui_verify.py OK"
}

portal_cert_master_setup() {
  step "Portal CERT Master — setup 11 zones + intégrations"
  python3 "$DIR/scripts/portal_cert_master_setup.py" || return 1
  ok "portal_cert_master_setup.py OK"
}

portal_cert_master_verify() {
  step "Portal CERT Master — verify API"
  python3 "$DIR/scripts/portal_cert_master_verify.py" || return 1
  ok "portal_cert_master_verify.py OK"
}

portal_cert_master_ui_verify() {
  step "Portal CERT Master — verify UI"
  python3 "$DIR/scripts/portal_cert_master_ui_verify.py" || return 1
  ok "portal_cert_master_ui_verify.py OK"
}

portal_auth_ui_verify() {
  step "Portal CERT — verify auth UI/API"
  python3 "$DIR/scripts/portal_auth_ui_verify.py" || return 1
  ok "portal_auth_ui_verify.py OK"
}

opensearch_advanced() {
  step "OpenSearch SIEM — ILM, templates, platform-logs"
  chmod +x "$DIR/scripts/opensearch_advanced.sh" 2>/dev/null || true
  if bash "$DIR/scripts/opensearch_advanced.sh"; then
    ok "OpenSearch advanced OK — docs/POINT_OPENSEARCH_SIEM.md"
    return 0
  fi
  err "OpenSearch advanced échoué — logs/opensearch_advanced.log"
  return 1
}

opensearch_dashboards_fp() {
  step "OpenSearch Dashboards — import dashboards SIEM FP"
  chmod +x "$DIR/scripts/opensearch_dashboards_import_fp.sh" 2>/dev/null || true
  if bash "$DIR/scripts/opensearch_dashboards_import_fp.sh"; then
    ok "Dashboards FP importés"
    info "https://localhost/dashboards/app/dashboards#/view/fp-opensearch-overview"
    return 0
  fi
  err "Import OSD FP échoué — logs/opensearch_dashboards_import.log"
  return 1
}

opensearch_fp_verify() {
  step "OpenSearch SIEM — vérification"
  if python3 "$DIR/scripts/opensearch_fp_verify.py"; then
    ok "opensearch_fp_verify.py OK"
    return 0
  fi
  err "Vérification OpenSearch SIEM échouée"
  return 1
}

opensearch_siem() {
  step "OpenSearch SIEM — activation complète"
  opensearch_advanced || return 1
  opensearch_dashboards_fp || return 1
  opensearch_fp_verify || return 1
  ok "OpenSearch SIEM prêt"
  return 0
}

opensearch_ti_sync() {
  step "OpenSearch TI — sync OpenCTI + MISP"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  local n_opencti=0 n_misp=0
  if python3 "$DIR/scripts/opensearch_ioc_opencti_sync.py"; then
    n_opencti=1
    ok "OpenCTI → OpenSearch"
  else
    warn "OpenCTI sync partiel ou échoué"
  fi
  if python3 "$DIR/scripts/opensearch_ioc_misp_sync.py"; then
    n_misp=1
    ok "MISP → OpenSearch"
  else
    warn "MISP sync partiel ou échoué"
  fi
  chmod +x "$DIR/scripts/opensearch_ti_setup.sh" 2>/dev/null || true
  bash "$DIR/scripts/opensearch_ti_setup.sh" || return 1
  python3 "$DIR/scripts/opensearch_ti_enrich_logs.py" 2>/dev/null || warn "Ré-enrichissement logs (optionnel)"
  info "Résumé index TI:"
  curl -sf "${OS_URL:-http://localhost:9200}/_cat/indices/forensic-ti*?v" 2>/dev/null | head -20 || true
  [ "$n_opencti" = "1" ] || [ "$n_misp" = "1" ] || return 1
  return 0
}

opensearch_siem_ti_rules() {
  step "OpenSearch TI — règles alerting"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  python3 "$DIR/scripts/opensearch_alerts_ti_generate.py" || return 1
  ok "Alertes TI générées"
  return 0
}

opensearch_siem_ti_verify() {
  step "OpenSearch TI — vérification"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  python3 "$DIR/scripts/opensearch_siem_ti_verify.py" || return 1
  ok "SIEM TI verify OK"
  return 0
}

opensearch_dashboards_ti() {
  step "OpenSearch Dashboards — import dashboards TI"
  chmod +x "$DIR/scripts/opensearch_dashboards_import_ti.sh" 2>/dev/null || true
  bash "$DIR/scripts/opensearch_dashboards_import_ti.sh" || return 1
  return 0
}

opensearch_siem_ti() {
  step "OpenSearch SIEM TI — activation complète (IOC + corrélation + dashboards)"
  opensearch_advanced || return 1
  opensearch_ti_sync || return 1
  opensearch_siem_ti_rules || return 1
  opensearch_dashboards_ti || return 1
  opensearch_siem_ti_verify || return 1
  ok "SIEM TI complet — docs/POINT_OPENSEARCH_SIEM_TI.md"
  info "https://localhost/dashboards/app/dashboards#/view/fp-ti-overview"
  return 0
}

opensearch_siem_rules_mass() {
  step "OpenSearch SIEM — génération 700+ règles de détection"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  python3 "$DIR/scripts/opensearch_alerting_prune.py" 2>/dev/null || true
  if python3 "$DIR/scripts/opensearch_generate_detection_rules.py"; then
    ok "Règles FP-DET-* déployées — index fp-detection-rules"
    return 0
  fi
  err "Génération règles échouée"
  return 1
}

opensearch_dashboards_obs() {
  step "OpenSearch Dashboards — import Observability FP"
  chmod +x "$DIR/scripts/opensearch_dashboards_import_obs.sh" 2>/dev/null || true
  bash "$DIR/scripts/opensearch_dashboards_import_obs.sh" || return 1
  return 0
}

opensearch_siem_panel_verify() {
  step "OpenSearch SIEM — données derrière les panels FP"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  python3 "$DIR/scripts/osd_panel_data_verify.py" || return 1
  ok "Panels FP avec données"
  return 0
}

opensearch_refresh_index_patterns() {
  step "OpenSearch — rafraîchissement index-patterns OSD"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  python3 "$DIR/scripts/opensearch_refresh_index_pattern.py" fp-ti fp-events fp-logs || return 1
  ok "Index-patterns rafraîchis"
  return 0
}

opensearch_siem_full_verify() {
  step "OpenSearch SIEM — vérification complète"
  export PYTHONPATH="${DIR}/scripts:${PYTHONPATH:-}"
  opensearch_refresh_index_patterns || return 1
  python3 "$DIR/scripts/opensearch_siem_full_verify.py" || return 1
  opensearch_siem_panel_verify || return 1
  ok "SIEM full verify OK"
  return 0
}

parsing_master_setup() {
  step "Parsing Master — pipelines, templates, backfill"
  python3 "$DIR/scripts/parsing_master_setup.py" || return 1
  ok "Parsing Master déployé"
  return 0
}

parsing_master_verify() {
  python3 "$DIR/scripts/parsing_master_verify.py" || return 1
  ok "Parsing Master verify OK"
  return 0
}

parsing_master_full_setup() {
  step "Parsing Master Full Spectrum — pipelines, templates, backfill"
  python3 "$DIR/scripts/parsing_master_full_setup.py" || return 1
  ok "Parsing Master Full déployé"
  return 0
}

parsing_master_full_verify() {
  python3 "$DIR/scripts/parsing_master_full_verify.py" || return 1
  ok "Parsing Master Full verify OK"
  return 0
}

fp_playbooks_bars_patch() {
  step "Barres 18 playbooks — patch final sur tous les dashboards FP"
  python3 "$DIR/scripts/fp_playbooks_bars_patch.py" || return 1
  ok "Barres playbooks patchées"
  return 0
}

parsing_playbook_ecs_apply() {
  step "Synchronisation requêtes ECS — hunts et playbooks"
  python3 "$DIR/scripts/parsing_playbook_ecs_apply.py" || return 1
  ok "Requêtes ECS synchronisées sur OSD"
  return 0
}

hunting_parsing_verify() {
  python3 "$DIR/scripts/hunting_parsing_verify.py" || return 1
  ok "Hunting parsing verify OK"
  return 0
}

purple_team_parsing_verify() {
  python3 "$DIR/scripts/purple_team_parsing_verify.py" || return 1
  ok "Purple Team parsing verify OK"
  return 0
}

dfir_parsing_verify() {
  python3 "$DIR/scripts/dfir_parsing_verify.py" || return 1
  ok "DFIR parsing verify OK"
  return 0
}

cti_parsing_verify() {
  python3 "$DIR/scripts/cti_parsing_verify.py" || return 1
  ok "CTI parsing verify OK"
  return 0
}

soc_parsing_verify() {
  python3 "$DIR/scripts/soc_parsing_verify.py" || return 1
  ok "SOC parsing verify OK"
  return 0
}

incident_parsing_verify() {
  python3 "$DIR/scripts/incident_parsing_verify.py" || return 1
  ok "Incident parsing verify OK"
  return 0
}

parsing_master_full_integration_verify() {
  python3 "$DIR/scripts/parsing_master_full_integration_verify.py" || return 1
  ok "Parsing integration verify OK"
  return 0
}

opensearch_cross_pivot_ir() {
  step "Cross-tool + Pivot + IR"
  python3 "$DIR/scripts/opensearch_drilldown_setup.py" || return 1
  python3 "$DIR/scripts/opensearch_cross_pivot_ir_setup.py" || return 1
  ok "Cross-tool + Pivot + IR déployés"
  return 0
}

enterprise_setup() {
  step "Enterprise modules"
  python3 "$DIR/scripts/opensearch_enterprise_setup.py" || return 1
  ok "Enterprise modules déployés"
  return 0
}

enterprise_verify() {
  python3 "$DIR/scripts/enterprise_verify.py" || return 1
  ok "Enterprise verify OK"
  return 0
}

analyst_playbook_setup() {
  step "Analyst Playbook"
  python3 "$DIR/scripts/analyst_playbook_setup.py" || return 1
  ok "Analyst Playbook déployé"
  return 0
}

analyst_playbook_verify() {
  python3 "$DIR/scripts/analyst_playbook_verify.py" || return 1
  ok "Analyst Playbook verify OK"
  return 0
}

soc_manager_playbook_setup() {
  step "SOC Manager Playbook"
  python3 "$DIR/scripts/soc_manager_playbook_setup.py" || return 1
  ok "SOC Manager Playbook déployé"
  return 0
}

soc_manager_playbook_verify() {
  python3 "$DIR/scripts/soc_manager_playbook_verify.py" || return 1
  ok "SOC Manager Playbook verify OK"
  return 0
}

incident_commander_playbook_setup() {
  step "Incident Commander Playbook"
  python3 "$DIR/scripts/incident_commander_playbook_setup.py" || return 1
  ok "Incident Commander Playbook déployé"
  return 0
}

incident_commander_playbook_verify() {
  python3 "$DIR/scripts/incident_commander_playbook_verify.py" || return 1
  ok "Incident Commander Playbook verify OK"
  return 0
}

soc_director_playbook_setup() {
  step "SOC Director Playbook"
  python3 "$DIR/scripts/soc_director_playbook_setup.py" || return 1
  ok "SOC Director Playbook déployé"
  return 0
}

soc_director_playbook_verify() {
  python3 "$DIR/scripts/soc_director_playbook_verify.py" || return 1
  ok "SOC Director Playbook verify OK"
  return 0
}

ti_lead_playbook_setup() {
  step "TI Lead Playbook"
  python3 "$DIR/scripts/ti_lead_playbook_setup.py" || return 1
  ok "TI Lead Playbook déployé"
  return 0
}

ti_lead_playbook_verify() {
  python3 "$DIR/scripts/ti_lead_playbook_verify.py" || return 1
  ok "TI Lead Playbook verify OK"
  return 0
}

dfir_senior_playbook_setup() {
  step "DFIR Senior Playbook"
  python3 "$DIR/scripts/dfir_senior_playbook_setup.py" || return 1
  ok "DFIR Senior Playbook déployé"
  return 0
}

dfir_senior_playbook_verify() {
  python3 "$DIR/scripts/dfir_senior_playbook_verify.py" || return 1
  ok "DFIR Senior Playbook verify OK"
  return 0
}

purple_team_playbook_setup() {
  step "Purple Team Playbook"
  python3 "$DIR/scripts/purple_team_playbook_setup.py" || return 1
  ok "Purple Team Playbook déployé"
  return 0
}

purple_team_playbook_verify() {
  python3 "$DIR/scripts/purple_team_playbook_verify.py" || return 1
  ok "Purple Team Playbook verify OK"
  return 0
}

th_lead_playbook_setup() {
  step "Threat Hunting Lead Playbook"
  python3 "$DIR/scripts/th_lead_playbook_setup.py" || return 1
  ok "Threat Hunting Lead Playbook déployé"
  return 0
}

th_lead_playbook_verify() {
  python3 "$DIR/scripts/th_lead_playbook_verify.py" || return 1
  ok "Threat Hunting Lead Playbook verify OK"
  return 0
}

soc_automation_playbook_setup() {
  step "SOC Automation Playbook"
  python3 "$DIR/scripts/soc_automation_playbook_setup.py" || return 1
  ok "SOC Automation Playbook déployé"
  return 0
}

soc_automation_playbook_verify() {
  python3 "$DIR/scripts/soc_automation_playbook_verify.py" || return 1
  ok "SOC Automation Playbook verify OK"
  return 0
}

cti_fusion_playbook_setup() {
  step "CTI Fusion Playbook"
  python3 "$DIR/scripts/cti_fusion_playbook_setup.py" || return 1
  ok "CTI Fusion Playbook déployé"
  return 0
}

cti_fusion_playbook_verify() {
  python3 "$DIR/scripts/cti_fusion_playbook_verify.py" || return 1
  ok "CTI Fusion Playbook verify OK"
  return 0
}

global_soc_command_center_setup() {
  step "Global SOC Command Center"
  python3 "$DIR/scripts/global_soc_command_center_setup.py" || return 1
  ok "Global SOC Command Center déployé"
  return 0
}

global_soc_command_center_verify() {
  python3 "$DIR/scripts/global_soc_command_center_verify.py" || return 1
  ok "Global SOC Command Center verify OK"
  return 0
}

cyber_crisis_management_setup() {
  step "Cyber Crisis Management"
  python3 "$DIR/scripts/cyber_crisis_management_setup.py" || return 1
  ok "Cyber Crisis Management déployé"
  return 0
}

cyber_crisis_management_verify() {
  python3 "$DIR/scripts/cyber_crisis_management_verify.py" || return 1
  ok "Cyber Crisis Management verify OK"
  return 0
}

nation_state_cti_playbook_setup() {
  step "Nation-State CTI Playbook"
  python3 "$DIR/scripts/nation_state_cti_playbook_setup.py" || return 1
  ok "Nation-State CTI Playbook déployé"
  return 0
}

nation_state_cti_playbook_verify() {
  python3 "$DIR/scripts/nation_state_cti_playbook_verify.py" || return 1
  ok "Nation-State CTI Playbook verify OK"
  return 0
}

autonomous_soc_playbook_setup() {
  step "Autonomous SOC Playbook"
  python3 "$DIR/scripts/autonomous_soc_playbook_setup.py" || return 1
  ok "Autonomous SOC Playbook déployé"
  return 0
}

autonomous_soc_playbook_verify() {
  python3 "$DIR/scripts/autonomous_soc_playbook_verify.py" || return 1
  ok "Autonomous SOC Playbook verify OK"
  return 0
}

soc_director_executive_playbook_setup() {
  step "SOC Director Executive Playbook"
  python3 "$DIR/scripts/soc_director_executive_playbook_setup.py" || return 1
  ok "SOC Director Executive Playbook déployé"
  return 0
}

soc_director_executive_playbook_verify() {
  python3 "$DIR/scripts/soc_director_executive_playbook_verify.py" || return 1
  ok "SOC Director Executive Playbook verify OK"
  return 0
}

red_team_lead_playbook_setup() {
  step "Red Team Lead Playbook"
  python3 "$DIR/scripts/red_team_lead_playbook_setup.py" || return 1
  ok "Red Team Lead Playbook déployé"
  return 0
}

red_team_lead_playbook_verify() {
  python3 "$DIR/scripts/red_team_lead_playbook_verify.py" || return 1
  ok "Red Team Lead Playbook verify OK"
  return 0
}

blue_team_lead_playbook_setup() {
  step "Blue Team Lead Playbook"
  python3 "$DIR/scripts/blue_team_lead_playbook_setup.py" || return 1
  ok "Blue Team Lead Playbook déployé"
  return 0
}

blue_team_lead_playbook_verify() {
  python3 "$DIR/scripts/blue_team_lead_playbook_verify.py" || return 1
  ok "Blue Team Lead Playbook verify OK"
  return 0
}

cti_fusion_global_playbook_setup() {
  step "CTI Fusion Global Playbook"
  python3 "$DIR/scripts/cti_fusion_global_playbook_setup.py" || return 1
  ok "CTI Fusion Global Playbook déployé"
  return 0
}

cti_fusion_global_playbook_verify() {
  python3 "$DIR/scripts/cti_fusion_global_playbook_verify.py" || return 1
  ok "CTI Fusion Global Playbook verify OK"
  return 0
}

opensearch_zone3_plugins() {
  step "OpenSearch Plugins (Zone 3) — Alerting/Reporting/Anomaly Detection/Security Analytics"
  python3 "$DIR/scripts/opensearch_plugins_zone3_setup.py" || return 1
  ok "Plugins Zone 3 activés (détecteur anomalie + reporting + security analytics)"
  return 0
}

opensearch_siem_full() {
  step "OpenSearch SIEM complet — SIEM + TI + Observability + 700+ règles"
  opensearch_zone3_plugins || true
  opensearch_siem || return 1
  opensearch_ti_sync || return 1
  opensearch_dashboards_ti || return 1
  opensearch_dashboards_obs || return 1
  opensearch_siem_rules_mass || return 1
  opensearch_siem_ti_rules || return 1
  opensearch_siem_ti_verify || return 1
  opensearch_fp_verify || return 1
  opensearch_siem_full_verify || return 1
  ok "SIEM complet prêt"
  return 0
}

timesketch_deep_test() {
  step "Timesketch — deep test (Sigma/TI/UI/API)"
  if [ ! -x "$DIR/scripts/timesketch_deep_test.sh" ]; then
    err "Script manquant: $DIR/scripts/timesketch_deep_test.sh"
    return 1
  fi
  bash "$DIR/scripts/generate-timesketch-conf.sh" 2>/dev/null || true
  info "Redémarrage timesketch-web/worker pour appliquer config YAML..."
  docker compose up -d timesketch-web timesketch-worker 2>/dev/null || true
  docker restart forensic-timesketch-web forensic-timesketch-worker 2>/dev/null || true
  sleep 12
  if bash "$DIR/scripts/timesketch_deep_test.sh"; then
    ok "Deep test Timesketch OK — voir logs/timesketch_deep_test.log"
    return 0
  fi
  err "Deep test Timesketch échoué — logs/timesketch_deep_test.log"
  return 1
}

timesketch_setup() {
  step "Timesketch — configuration + services (Master prerequisite)"
  bash "$DIR/scripts/generate-timesketch-conf.sh" 2>/dev/null || true
  info "Démarrage timesketch-web/worker..."
  docker compose up -d timesketch-web timesketch-worker 2>/dev/null || true
  docker restart forensic-timesketch-web forensic-timesketch-worker 2>/dev/null || true
  bash "$DIR/scripts/timesketch-patch-explore.sh" 2>/dev/null || true
  wait_container_http "forensic-timesketch-web" "http://127.0.0.1:5000/login" 72 5 "Timesketch" || return 1
  ok "Timesketch prêt (http://localhost:5000)"
}

timesketch_master_setup() {
  step "Timesketch Master — setup (ECS + fusion + playbooks)"
  if [ ! -f "$DIR/scripts/timesketch_master_setup.py" ]; then
    err "Script manquant: scripts/timesketch_master_setup.py"
    return 1
  fi
  if python3 "$DIR/scripts/timesketch_master_setup.py"; then
    ok "Timesketch Master setup OK"
    [ -f "$DIR/logs/timesketch_master_sketch.url" ] && info "UI: $(cat "$DIR/logs/timesketch_master_sketch.url")"
    return 0
  fi
  err "Timesketch Master setup échoué"
  return 1
}

timesketch_master_verify() {
  step "Timesketch Master — verify API"
  python3 "$DIR/scripts/timesketch_master_verify.py" || return 1
  ok "timesketch_master_verify.py OK"
}

timesketch_ui_verify() {
  step "Timesketch Master — verify UI"
  python3 "$DIR/scripts/timesketch_master_ui_verify.py" || return 1
  ok "timesketch_master_ui_verify.py OK"
}

timesketch_playbook_setup() {
  step "Timesketch Playbook — setup"
  python3 "$DIR/scripts/timesketch_playbook_setup.py" || return 1
  ok "timesketch_playbook_setup.py OK"
}

timesketch_playbook_verify() {
  step "Timesketch Playbook — verify"
  python3 "$DIR/scripts/timesketch_playbook_verify.py" || return 1
  ok "timesketch_playbook_verify.py OK"
}

timesketch_zones_setup() {
  step "Timesketch Full Zones — setup (11 zones)"
  python3 "$DIR/scripts/timesketch_zones_setup.py" || return 1
  ok "timesketch_zones_setup.py OK"
}

timesketch_zones_verify() {
  step "Timesketch Full Zones — verify"
  python3 "$DIR/scripts/timesketch_zones_verify.py" || return 1
  ok "timesketch_zones_verify.py OK"
}

timesketch_full_zones_integration_verify() {
  step "Timesketch Full Zones — integration verify"
  python3 "$DIR/scripts/timesketch_full_zones_integration_verify.py" || return 1
  ok "timesketch_full_zones_integration_verify.py OK"
}

crosspivot_setup() {
  step "Cross-Pivot Engine — setup (OS↔TS)"
  python3 "$DIR/scripts/crosspivot_setup.py" || return 1
  ok "crosspivot_setup.py OK"
}

crosspivot_verify() {
  step "Cross-Pivot Engine — verify API"
  python3 "$DIR/scripts/crosspivot_verify.py" || return 1
  ok "crosspivot_verify.py OK"
}

crosspivot_ui_verify() {
  step "Cross-Pivot Engine — verify UI"
  python3 "$DIR/scripts/crosspivot_ui_verify.py" || return 1
  ok "crosspivot_ui_verify.py OK"
}

ts_cti_fusion_setup() {
  step "Timesketch CTI Fusion — setup (timeline FP-CTI-Fusion + pivots)"
  python3 "$DIR/scripts/ts_cti_fusion_setup.py" || return 1
  ok "ts_cti_fusion_setup.py OK"
}

ts_cti_fusion_verify() {
  step "Timesketch CTI Fusion — verify API"
  python3 "$DIR/scripts/ts_cti_fusion_verify.py" || return 1
  ok "ts_cti_fusion_verify.py OK"
}

ts_cti_fusion_ui_verify() {
  step "Timesketch CTI Fusion — verify UI"
  python3 "$DIR/scripts/ts_cti_fusion_ui_verify.py" || return 1
  ok "ts_cti_fusion_ui_verify.py OK"
}

ts_incident_commander_setup() {
  step "Timesketch Incident Commander — setup (timeline FP-Incident-Timeline)"
  python3 "$DIR/scripts/ts_incident_commander_setup.py" || return 1
  ok "ts_incident_commander_setup.py OK"
}

ts_incident_commander_verify() {
  step "Timesketch Incident Commander — verify API"
  python3 "$DIR/scripts/ts_incident_commander_verify.py" || return 1
  ok "ts_incident_commander_verify.py OK"
}

ts_incident_commander_ui_verify() {
  step "Timesketch Incident Commander — verify UI"
  python3 "$DIR/scripts/ts_incident_commander_ui_verify.py" || return 1
  ok "ts_incident_commander_ui_verify.py OK"
}

ts_purple_team_setup() {
  step "Timesketch Purple Team — setup (timeline FP-PurpleTeam-Timeline)"
  python3 "$DIR/scripts/ts_purple_team_setup.py" || return 1
  ok "ts_purple_team_setup.py OK"
}

ts_purple_team_verify() {
  step "Timesketch Purple Team — verify API"
  python3 "$DIR/scripts/ts_purple_team_verify.py" || return 1
  ok "ts_purple_team_verify.py OK"
}

ts_purple_team_ui_verify() {
  step "Timesketch Purple Team — verify UI"
  python3 "$DIR/scripts/ts_purple_team_ui_verify.py" || return 1
  ok "ts_purple_team_ui_verify.py OK"
}

sigma_master_setup() {
  step "Sigma Master — setup"
  python3 "$DIR/scripts/sigma_master_setup.py" || return 1
  ok "sigma_master_setup.py OK"
}

sigma_master_verify() {
  step "Sigma Master — verify API"
  python3 "$DIR/scripts/sigma_master_verify.py" || return 1
  ok "sigma_master_verify.py OK"
}

sigma_master_ui_verify() {
  step "Sigma Master — verify UI"
  python3 "$DIR/scripts/sigma_master_ui_verify.py" || return 1
  ok "sigma_master_ui_verify.py OK"
}

ti_master_setup() {
  step "TI Master — setup"
  python3 "$DIR/scripts/ti_master_setup.py" || return 1
  ok "ti_master_setup.py OK"
}

ti_master_verify() {
  step "TI Master — verify API"
  python3 "$DIR/scripts/ti_master_verify.py" || return 1
  ok "ti_master_verify.py OK"
}

ti_master_ui_verify() {
  step "TI Master — verify UI"
  python3 "$DIR/scripts/ti_master_ui_verify.py" || return 1
  ok "ti_master_ui_verify.py OK"
}

analyzers_master_setup() {
  step "Analyzers Master — setup"
  python3 "$DIR/scripts/analyzers_master_setup.py" || return 1
  ok "analyzers_master_setup.py OK"
}

analyzers_master_verify() {
  step "Analyzers Master — verify API"
  python3 "$DIR/scripts/analyzers_master_verify.py" || return 1
  ok "analyzers_master_verify.py OK"
}

analyzers_master_ui_verify() {
  step "Analyzers Master — verify UI"
  python3 "$DIR/scripts/analyzers_master_ui_verify.py" || return 1
  ok "analyzers_master_ui_verify.py OK"
}

visualizations_master_setup() {
  step "Visualizations Master — setup"
  python3 "$DIR/scripts/visualizations_master_setup.py" || return 1
  ok "visualizations_master_setup.py OK"
}

visualizations_master_verify() {
  step "Visualizations Master — verify API"
  python3 "$DIR/scripts/visualizations_master_verify.py" || return 1
  ok "visualizations_master_verify.py OK"
}

visualizations_master_ui_verify() {
  step "Visualizations Master — verify UI"
  python3 "$DIR/scripts/visualizations_master_ui_verify.py" || return 1
  ok "visualizations_master_ui_verify.py OK"
}

soc_autonomous_run() {
  step "SOC Autonomous Mode — health cycle"
  python3 "$DIR/scripts/soc_autonomous_master.py" || return 1
  ok "soc_autonomous_master.py OK"
}

soc_autonomous_verify() {
  step "SOC Autonomous Mode — verify agrégé"
  python3 "$DIR/scripts/soc_autonomous_verify.py" || return 1
  ok "soc_autonomous_verify.py OK"
}

soc_autonomous_ui_verify() {
  step "SOC Autonomous Mode — verify UI"
  python3 "$DIR/scripts/soc_autonomous_ui_verify.py" || return 1
  ok "soc_autonomous_ui_verify.py OK"
}

platform_health_dashboard_setup() {
  step "Platform Health — setup dashboard"
  python3 "$DIR/scripts/platform_health_dashboard_setup.py" || return 1
  ok "platform_health_dashboard_setup.py OK"
}

platform_health_dashboard_verify() {
  step "Platform Health — verify dashboard"
  python3 "$DIR/scripts/platform_health_dashboard_verify.py" || return 1
  ok "platform_health_dashboard_verify.py OK"
}

dashboard_metrics_extract() {
  step "Dashboard metrics — extraction DOM (Playwright, pas HTTP/API)"
  python3 "$DIR/scripts/dashboard_metrics_extract.py" || return 1
  ok "dashboard_metrics_extract.py OK → /tmp/fp-dashboard-metrics.json"
}

dashboard_panels_check() {
  step "Dashboard panels — détection panels cassés / pages blanches (Playwright)"
  python3 "$DIR/scripts/dashboard_panels_check.py" || return 1
  ok "dashboard_panels_check.py OK → /tmp/fp-dashboard-panels.json"
}

dashboard_metrics_compare() {
  step "Dashboard metrics — comparaison stricte (règles YAML)"
  python3 "$DIR/scripts/dashboard_metrics_compare.py" || return 1
  ok "dashboard_metrics_compare.py OK → /tmp/fp-dashboard-metrics-compare.json"
}

dashboard_metrics_verify() {
  step "Dashboard metrics — verify + rapport (validation humaine requise)"
  python3 "$DIR/scripts/dashboard_metrics_verify.py" || return 1
  ok "dashboard_metrics_verify.py OK → docs/DASHBOARD_METRICS_REPORT.md"
}

dashboard_qa_full() {
  step "Dashboard QA — campagne complète (extract → panels → compare → verify)"
  local rc=0
  dashboard_metrics_extract || rc=1
  dashboard_panels_check || rc=1
  dashboard_metrics_compare || rc=1
  dashboard_metrics_verify || rc=1
  if [[ "$rc" -eq 0 ]]; then
    ok "Campagne dashboard QA terminée — validation humaine requise"
  else
    warn "Campagne dashboard QA terminée avec échec(s) — voir docs/DASHBOARD_METRICS_REPORT.md"
    return 1
  fi
}

fp_consolidation_master() {
  step "FP Consolidation Master — pack final"
  python3 "$DIR/scripts/fp_consolidation_master.py" || return 1
  ok "fp_consolidation_master.py OK"
}

fp_consolidation_verify() {
  step "FP Consolidation — verify statut"
  python3 "$DIR/scripts/fp_consolidation_verify.py" || return 1
  ok "fp_consolidation_verify.py OK"
}

fp_audit_global() {
  step "FP Audit Global — inventaire éditeur"
  python3 "$DIR/scripts/fp_audit_global.py" || return 1
  ok "fp_audit_global.py OK"
}

fp_audit_global_verify() {
  step "FP Audit Global — verify rapport"
  python3 "$DIR/scripts/fp_audit_global_verify.py" || return 1
  ok "fp_audit_global_verify.py OK"
}

fp_e2e_tests() {
  step "FP E2E Tests — chaîne complète + vérif. navigateur"
  export FP_BROWSER_HEADLESS="${FP_BROWSER_HEADLESS:-1}"
  export FP_QA_STRICT="${FP_QA_STRICT:-1}"
  python3 "$DIR/scripts/fp_e2e_tests.py" || return 1
  ok "fp_e2e_tests.py OK"
}

fp_e2e_tests_verify() {
  step "FP E2E Tests — verify statut"
  python3 "$DIR/scripts/fp_e2e_tests_verify.py" || return 1
  ok "fp_e2e_tests_verify.py OK"
}

fp_ui_tests() {
  step "FP UI Tests — navigateur réel (QA HARD LOCK pessimiste)"
  export FP_QA_STRICT="${FP_QA_STRICT:-1}"
  export FP_BROWSER_HEADLESS="${FP_BROWSER_HEADLESS:-1}"
  if [ -z "${DISPLAY:-}" ] && command -v xvfb-run >/dev/null 2>&1; then
    xvfb-run -a python3 "$DIR/scripts/fp_ui_tests.py" || return 1
  else
    python3 "$DIR/scripts/fp_ui_tests.py" || return 1
  fi
  ok "fp_ui_tests.py OK"
}

fp_ui_tests_verify() {
  step "FP UI Tests — verify statut"
  python3 "$DIR/scripts/fp_ui_tests_verify.py" || return 1
  ok "fp_ui_tests_verify.py OK"
}

timesketch_e2e() {
  step "Timesketch avancé — test E2E complet (POINT 3)"
  if [ ! -x "$DIR/scripts/timesketch_advanced_e2e.sh" ]; then
    err "Script manquant: $DIR/scripts/timesketch_advanced_e2e.sh"
    return 1
  fi
  info "Lancement scripts/timesketch_advanced_e2e.sh ..."
  if bash "$DIR/scripts/timesketch_advanced_e2e.sh"; then
    local sketch_url=""
    if [ -f "$DIR/logs/timesketch_advanced_e2e_sketch.url" ]; then
      sketch_url=$(cat "$DIR/logs/timesketch_advanced_e2e_sketch.url")
      ok "E2E Timesketch OK — UI: $sketch_url"
      echo ""
      echo -e "${CYAN}Ouvrir dans le navigateur :${NC} ${sketch_url}"
    else
      ok "E2E Timesketch OK — voir docs/POINT3_TIMESKETCH_E2E.md"
    fi
    return 0
  fi
  err "E2E Timesketch avancé échoué — logs: $DIR/logs/timesketch_advanced_e2e.log"
  return 1
}

# ──────────────────────────────────────────────────────────────
#  BACKUP
# ──────────────────────────────────────────────────────────────
backup() {
  local d="./backups/$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$d"
  docker exec forensic-postgres pg_dumpall \
    -U "${POSTGRES_USER:-forensic}" > "$d/postgres.sql"
  ok "Backup: $d/postgres.sql"
}

# ──────────────────────────────────────────────────────────────
#  FIX OPENSEARCH (Lucene codec error)
# ──────────────────────────────────────────────────────────────
fix_opensearch() {
  warn "Suppression volumes OpenSearch (résout erreur Lucene codec)..."
  docker stop forensic-opensearch-1 forensic-opensearch-2 2>/dev/null || true
  docker rm   forensic-opensearch-1 forensic-opensearch-2 2>/dev/null || true
  docker volume ls -q | grep "opensearch.data" | xargs -r docker volume rm 2>/dev/null || true
  ok "Volumes supprimés. Relancer: ./forensic.sh start"
}

# ──────────────────────────────────────────────────────────────
#  RESET TOTAL
# ──────────────────────────────────────────────────────────────
reset() {
  echo ""
  warn "⚠️  ATTENTION: supprime TOUTES les données (volumes + certificats)"
  read -rp "Taper RESET pour confirmer: " c
  if [ "$c" != "RESET" ]; then echo "Annulé."; exit 0; fi
  docker compose down --remove-orphans --volumes 2>/dev/null || true
  docker volume ls -q | grep -iE "forensic|fp-final|^fp_" | xargs -r docker volume rm 2>/dev/null || true
  rm -f config/nginx/ssl/forensic.crt config/nginx/ssl/forensic.key \
        config/nginx/ssl/fingerprint.txt 2>/dev/null || true
  ok "Reset complet. Relancer: ./forensic.sh start"
}

# ──────────────────────────────────────────────────────────────
#  URLS
# ──────────────────────────────────────────────────────────────
urls() {
  local IP aws_pub
  IP=$(fp_detect_public_host 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
  aws_pub=$(_fp_aws_public_ipv4 2>/dev/null || true)
  local FP
  FP=$(cat config/nginx/ssl/fingerprint.txt 2>/dev/null | head -1 || echo "—")
  echo ""
  echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║              ACCÈS À LA PLATEFORME v2.1 (HTTPS)                  ║${NC}"
  echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC} ${GREEN}Portail CERT${NC}              https://${IP}/"
  echo -e "${CYAN}║${NC}   admin / F0r3ns1c_Portal_2024!  (ou grep CERT_PORTAL_SECRET .env)"
  echo -e "${CYAN}║${NC} ${GREEN}Portail IT${NC} (TLS chiffré)   https://${IP}/it/?token=<TOKEN>"
  echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC} ${GREEN}OpenSearch Dashboards${NC}    https://${IP}/dashboards/"
  echo -e "${CYAN}║${NC} ${GREEN}Grafana${NC}                   https://${IP}/grafana/"
  echo -e "${CYAN}║${NC}   admin / F0r3ns1c_GF_2024!"
  echo -e "${CYAN}║${NC} ${GREEN}OpenCTI${NC}                   https://${IP}/cti/"
  echo -e "${CYAN}║${NC}   admin@forensic.local / F0r3ns1c_CTI_2024!"
  echo -e "${CYAN}║${NC} ${GREEN}TheHive${NC}                   https://${IP}/thehive/"
  echo -e "${CYAN}║${NC}   admin@thehive.local / secret"
  echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC} ${YELLOW}Timesketch${NC}    (port dédié) http://${IP}:5000/"
  echo -e "${CYAN}║${NC}   admin / F0r3ns1c_TS_2024!"
  echo -e "${CYAN}║${NC} ${YELLOW}MISP${NC}          (port dédié) http://${IP}:8090/"
  echo -e "${CYAN}║${NC}   admin@forensic.local / F0r3ns1c_MISP_2024!"
  echo -e "${CYAN}║${NC} ${YELLOW}Cortex${NC}                    http://${IP}:9003/  (setup org au 1er accès)"
  echo -e "${CYAN}║${NC} ${YELLOW}MinIO Console${NC}             http://${IP}:9001/"
  echo -e "${CYAN}║${NC}   forensicadmin / F0r3ns1c_Minio_2024!"
  echo -e "${CYAN}║${NC} ${YELLOW}Portainer${NC}                 https://${IP}:9443/"
  echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  🔒 Cert auto-signé — accepter l'avertissement navigateur"
  echo -e "${CYAN}║${NC}  Fingerprint: ${FP}"
  if _fp_is_ipv4 "$aws_pub" 2>/dev/null && [ "$aws_pub" != "$IP" ]; then
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ☁️  AWS : accès navigateur via IP publique ${aws_pub}"
    echo -e "${CYAN}║${NC}  Ouvrir le groupe de sécurité : TCP 80, 443 (et 5000 si Timesketch direct)"
  fi
  echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  Logstash → Beats :5044  JSON :5045  Syslog :5140/udp  HEC :5555"
  echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${YELLOW}⚡ Si données existantes → ./forensic.sh fix-data${NC}"
  echo -e "${YELLOW}⚡ Si portails à mettre à jour → ./forensic.sh update-portals${NC}"
}

# ──────────────────────────────────────────────────────────────
#  DISPATCH
# ──────────────────────────────────────────────────────────────
case "${1:-help}" in
  start|all)      start ;;
  -full-start|full-start|full) full_start_orchestrator ;;
  full-stop)      stop ;;
  full-restart)   restart ;;
  check-health)   health ;;
  rebuild)        full_start_orchestrator ;;
  open-ui|ui)     open_ui ;;
  start-logs)     start_logs "${2:-100}" ;;
  ui-campaign)    python3 "$DIR/scripts/ui_campaign_verify.py" ;;
  qa-ultra|ultra-qa) bash "$DIR/scripts/run-ultra-qa-campaign.sh" ;;
  osd-feature-campaign) python3 "$DIR/scripts/osd_feature_campaign.py" ;;
  osd-browser-verify) python3 "$DIR/scripts/osd_browser_verify.py" ;;
  osd-all-phases-test) python3 "$DIR/scripts/osd_all_phases_test.py" ;;
  zone1-osd-verify) python3 "$DIR/scripts/zone1_osd_verify.py" && python3 "$DIR/scripts/osd_panel_data_verify.py" ;;
  zone2-obs-setup) python3 "$DIR/scripts/opensearch_observability_setup.py" ;;
  zone2-obs-verify) python3 "$DIR/scripts/zone2_obs_verify.py" ;;
  zone3-plugins-setup) python3 "$DIR/scripts/opensearch_plugins_zone3_setup.py" ;;
  zone3-plugins-verify) python3 "$DIR/scripts/zone3_plugins_verify.py" ;;
  zone3-ui-check) bash "$DIR/scripts/zone3_ui_check.sh" ;;
  zone4-mgmt-setup) python3 "$DIR/scripts/opensearch_management_zone4_setup.py" ;;
  zone4-mgmt-verify) python3 "$DIR/scripts/zone4_management_verify.py" ;;
  zone4-ui-check) bash "$DIR/scripts/zone4_ui_check.sh" ;;
  analyst-targets-fix) python3 "$DIR/scripts/osd_analyst_targets_fix.py" ;;
  analyst-targets-verify) python3 "$DIR/scripts/osd_ui_targets_verify.py" ;;
  opensearch-drilldown-setup|os-drilldown-setup)
    python3 "$DIR/scripts/opensearch_drilldown_setup.py" || exit 1
    ok "Drill-down FP appliqué"
    ;;
  opensearch-drilldown-verify|os-drilldown-verify)
    python3 "$DIR/scripts/opensearch_drilldown_verify.py" || exit 1
    ok "Drill-down verify OK"
    ;;
  opensearch-cross-pivot-ir|os-cross-pivot-ir)
    ./forensic.sh opensearch-drilldown-setup || exit 1
    python3 "$DIR/scripts/opensearch_cross_pivot_ir_setup.py" || exit 1
    ok "Cross-tool + Pivot + IR déployés"
    ;;
  opensearch-cross-pivot-ir-verify|os-cross-pivot-ir-verify)
    python3 "$DIR/scripts/opensearch_cross_pivot_ir_verify.py" || exit 1
    ok "Cross-pivot-IR verify OK"
    ;;
  infra-recover-core|infra-recover)
    bash "$DIR/scripts/infra_recover_core.sh" || exit 1
    ok "Infra recover core OK"
    ;;
  nomenclature-inventory|nomenclature-inv)
    python3 "$DIR/scripts/nomenclature_inventory.py" || exit 1
    ok "Inventaire → /tmp/fp-nomenclature-inventory.json"
    ;;
  nomenclature-plan)
    python3 "$DIR/scripts/nomenclature_inventory.py" || exit 1
    python3 "$DIR/scripts/nomenclature_refactor_plan.py" || exit 1
    ok "Plan → config/nomenclature_refactor_plan.yaml"
    ;;
  nomenclature-apply|nomenclature-refactor)
    python3 "$DIR/scripts/nomenclature_refactor_apply.py" || exit 1
    ok "Nomenclature appliquée (backup dans backups/nomenclature/)"
    ;;
  nomenclature-rollback)
    latest="$(ls -1dt "$DIR/backups/nomenclature/"* 2>/dev/null | head -1)"
    if [ -z "$latest" ]; then err "Aucun backup nomenclature"; exit 1; fi
    find "$latest" -type f | while read -r f; do
      rel="${f#"$latest"/}"
      install -D "$f" "$DIR/$rel"
    done
    ok "Rollback depuis $latest"
    ;;
  cluster-repair|os-cluster-repair)
    python3 "$DIR/scripts/cluster_repair.py" || exit 1
    ok "Cluster repair OK"
    ;;
  enterprise-setup|os-enterprise-setup)
    python3 "$DIR/scripts/opensearch_enterprise_setup.py" || exit 1
    ok "Enterprise modules déployés"
    ;;
  enterprise-verify|os-enterprise-verify)
    python3 "$DIR/scripts/enterprise_verify.py" || exit 1
    ok "Enterprise verify OK"
    ;;
  analyst-playbook-setup|playbook-setup)
    python3 "$DIR/scripts/analyst_playbook_setup.py" || exit 1
    ok "Analyst Playbook déployé"
    ;;
  analyst-playbook-verify|playbook-verify)
    python3 "$DIR/scripts/analyst_playbook_verify.py" || exit 1
    ok "Analyst Playbook verify OK"
    ;;
  soc-manager-playbook-setup|soc-playbook-setup)
    python3 "$DIR/scripts/soc_manager_playbook_setup.py" || exit 1
    ok "SOC Manager Playbook déployé"
    ;;
  soc-manager-playbook-verify|soc-playbook-verify)
    python3 "$DIR/scripts/soc_manager_playbook_verify.py" || exit 1
    ok "SOC Manager Playbook verify OK"
    ;;
  incident-commander-playbook-setup|ic-playbook-setup)
    python3 "$DIR/scripts/incident_commander_playbook_setup.py" || exit 1
    ok "Incident Commander Playbook déployé"
    ;;
  incident-commander-playbook-verify|ic-playbook-verify)
    python3 "$DIR/scripts/incident_commander_playbook_verify.py" || exit 1
    ok "Incident Commander Playbook verify OK"
    ;;
  soc-director-playbook-setup|sd-playbook-setup)
    python3 "$DIR/scripts/soc_director_playbook_setup.py" || exit 1
    ok "SOC Director Playbook déployé"
    ;;
  soc-director-playbook-verify|sd-playbook-verify)
    python3 "$DIR/scripts/soc_director_playbook_verify.py" || exit 1
    ok "SOC Director Playbook verify OK"
    ;;
  ti-lead-playbook-setup|ti-playbook-setup)
    python3 "$DIR/scripts/ti_lead_playbook_setup.py" || exit 1
    ok "TI Lead Playbook déployé"
    ;;
  ti-lead-playbook-verify|ti-playbook-verify)
    python3 "$DIR/scripts/ti_lead_playbook_verify.py" || exit 1
    ok "TI Lead Playbook verify OK"
    ;;
  dfir-senior-playbook-setup|dfir-playbook-setup)
    python3 "$DIR/scripts/dfir_senior_playbook_setup.py" || exit 1
    ok "DFIR Senior Playbook déployé"
    ;;
  dfir-senior-playbook-verify|dfir-playbook-verify)
    python3 "$DIR/scripts/dfir_senior_playbook_verify.py" || exit 1
    ok "DFIR Senior Playbook verify OK"
    ;;
  purple-team-playbook-setup|pt-playbook-setup)
    python3 "$DIR/scripts/purple_team_playbook_setup.py" || exit 1
    ok "Purple Team Playbook déployé"
    ;;
  purple-team-playbook-verify|pt-playbook-verify)
    python3 "$DIR/scripts/purple_team_playbook_verify.py" || exit 1
    ok "Purple Team Playbook verify OK"
    ;;
  th-lead-playbook-setup|thl-playbook-setup)
    python3 "$DIR/scripts/th_lead_playbook_setup.py" || exit 1
    ok "Threat Hunting Lead Playbook déployé"
    ;;
  th-lead-playbook-verify|thl-playbook-verify)
    python3 "$DIR/scripts/th_lead_playbook_verify.py" || exit 1
    ok "Threat Hunting Lead Playbook verify OK"
    ;;
  soc-automation-playbook-setup|soca-playbook-setup)
    python3 "$DIR/scripts/soc_automation_playbook_setup.py" || exit 1
    ok "SOC Automation Playbook déployé"
    ;;
  soc-automation-playbook-verify|soca-playbook-verify)
    python3 "$DIR/scripts/soc_automation_playbook_verify.py" || exit 1
    ok "SOC Automation Playbook verify OK"
    ;;
  cti-fusion-playbook-setup|ctf-playbook-setup)
    python3 "$DIR/scripts/cti_fusion_playbook_setup.py" || exit 1
    ok "CTI Fusion Playbook déployé"
    ;;
  cti-fusion-playbook-verify|ctf-playbook-verify)
    python3 "$DIR/scripts/cti_fusion_playbook_verify.py" || exit 1
    ok "CTI Fusion Playbook verify OK"
    ;;
  global-soc-command-center-setup|gscc-setup)
    python3 "$DIR/scripts/global_soc_command_center_setup.py" || exit 1
    ok "Global SOC Command Center déployé"
    ;;
  global-soc-command-center-verify|gscc-verify)
    python3 "$DIR/scripts/global_soc_command_center_verify.py" || exit 1
    ok "Global SOC Command Center verify OK"
    ;;
  cyber-crisis-management-setup|ccm-setup)
    python3 "$DIR/scripts/cyber_crisis_management_setup.py" || exit 1
    ok "Cyber Crisis Management déployé"
    ;;
  cyber-crisis-management-verify|ccm-verify)
    python3 "$DIR/scripts/cyber_crisis_management_verify.py" || exit 1
    ok "Cyber Crisis Management verify OK"
    ;;
  nation-state-cti-playbook-setup|nsc-playbook-setup)
    python3 "$DIR/scripts/nation_state_cti_playbook_setup.py" || exit 1
    ok "Nation-State CTI Playbook déployé"
    ;;
  nation-state-cti-playbook-verify|nsc-playbook-verify)
    python3 "$DIR/scripts/nation_state_cti_playbook_verify.py" || exit 1
    ok "Nation-State CTI Playbook verify OK"
    ;;
  autonomous-soc-playbook-setup|asoc-playbook-setup)
    python3 "$DIR/scripts/autonomous_soc_playbook_setup.py" || exit 1
    ok "Autonomous SOC Playbook déployé"
    ;;
  autonomous-soc-playbook-verify|asoc-playbook-verify)
    python3 "$DIR/scripts/autonomous_soc_playbook_verify.py" || exit 1
    ok "Autonomous SOC Playbook verify OK"
    ;;
  soc-director-executive-playbook-setup|sde-playbook-setup)
    python3 "$DIR/scripts/soc_director_executive_playbook_setup.py" || exit 1
    ok "SOC Director Executive Playbook déployé"
    ;;
  soc-director-executive-playbook-verify|sde-playbook-verify)
    python3 "$DIR/scripts/soc_director_executive_playbook_verify.py" || exit 1
    ok "SOC Director Executive Playbook verify OK"
    ;;
  red-team-lead-playbook-setup|rtl-playbook-setup)
    python3 "$DIR/scripts/red_team_lead_playbook_setup.py" || exit 1
    ok "Red Team Lead Playbook déployé"
    ;;
  red-team-lead-playbook-verify|rtl-playbook-verify)
    python3 "$DIR/scripts/red_team_lead_playbook_verify.py" || exit 1
    ok "Red Team Lead Playbook verify OK"
    ;;
  blue-team-lead-playbook-setup|btl-playbook-setup)
    python3 "$DIR/scripts/blue_team_lead_playbook_setup.py" || exit 1
    ok "Blue Team Lead Playbook déployé"
    ;;
  blue-team-lead-playbook-verify|btl-playbook-verify)
    python3 "$DIR/scripts/blue_team_lead_playbook_verify.py" || exit 1
    ok "Blue Team Lead Playbook verify OK"
    ;;
  cti-fusion-global-playbook-setup|ctfg-playbook-setup)
    python3 "$DIR/scripts/cti_fusion_global_playbook_setup.py" || exit 1
    ok "CTI Fusion Global Playbook déployé"
    ;;
  cti-fusion-global-playbook-verify|ctfg-playbook-verify)
    python3 "$DIR/scripts/cti_fusion_global_playbook_verify.py" || exit 1
    ok "CTI Fusion Global Playbook verify OK"
    ;;
  parsing-master-setup|parsing-setup)
    python3 "$DIR/scripts/parsing_master_setup.py" || exit 1
    ok "Parsing Master déployé"
    ;;
  parsing-master-verify|parsing-verify)
    python3 "$DIR/scripts/parsing_master_verify.py" || exit 1
    ok "Parsing Master verify OK"
    ;;
  parsing-master-full-setup|parsing-full-setup)
    python3 "$DIR/scripts/parsing_master_full_setup.py" || exit 1
    ok "Parsing Master Full Spectrum déployé"
    ;;
  parsing-master-full-verify|parsing-full-verify)
    python3 "$DIR/scripts/parsing_master_full_verify.py" || exit 1
    ok "Parsing Master Full verify OK"
    ;;
  fp-playbooks-bars-patch|playbooks-bars-patch)
    python3 "$DIR/scripts/fp_playbooks_bars_patch.py" || exit 1
    ok "Barres 18 playbooks patchées"
    ;;
  parsing-playbook-ecs-apply|playbook-ecs-apply)
    python3 "$DIR/scripts/parsing_playbook_ecs_apply.py" || exit 1
    ok "Requêtes ECS playbooks synchronisées"
    ;;
  hunting-parsing-verify)
    python3 "$DIR/scripts/hunting_parsing_verify.py" || exit 1
    ok "Hunting parsing verify OK"
    ;;
  purple-team-parsing-verify)
    python3 "$DIR/scripts/purple_team_parsing_verify.py" || exit 1
    ok "Purple Team parsing verify OK"
    ;;
  dfir-parsing-verify)
    python3 "$DIR/scripts/dfir_parsing_verify.py" || exit 1
    ok "DFIR parsing verify OK"
    ;;
  cti-parsing-verify)
    python3 "$DIR/scripts/cti_parsing_verify.py" || exit 1
    ok "CTI parsing verify OK"
    ;;
  soc-parsing-verify)
    python3 "$DIR/scripts/soc_parsing_verify.py" || exit 1
    ok "SOC parsing verify OK"
    ;;
  incident-parsing-verify)
    python3 "$DIR/scripts/incident_parsing_verify.py" || exit 1
    ok "Incident parsing verify OK"
    ;;
  parsing-master-full-integration-verify|parsing-integration-verify)
    python3 "$DIR/scripts/parsing_master_full_integration_verify.py" || exit 1
    ok "Parsing integration verify OK"
    ;;
  parsing-master-full-inventory|parsing-full-inventory)
    python3 "$DIR/scripts/parsing_master_full_inventory.py" || exit 1
    ok "Inventaire parsing full OK"
    ;;
  parsing-master-full-mappings|parsing-full-mappings)
    python3 "$DIR/scripts/parsing_master_full_mappings_fix.py" || exit 1
    ok "Mappings parsing full corrigés"
    ;;
  parsing-inventory)
    python3 "$DIR/scripts/parsing_inventory.py" || exit 1
    ok "Inventaire parsing OK"
    ;;
  parsing-mappings-fix)
    python3 "$DIR/scripts/parsing_mappings_fix.py" || exit 1
    ok "Mappings parsing corrigés"
    ;;
  ir-auto-case)
    python3 "$DIR/scripts/ir_auto_case.py" || exit 1
    ok "IR auto-case terminé"
    ;;
  stop)           stop ;;
  restart)        restart ;;
  status)         status ;;
  health)         health ;;
  logs)           logs "$@" ;;
  backup)         backup ;;
  urls)           urls ;;
  reset)          reset ;;
  fix-opensearch) fix_opensearch ;;
  align-host|align-public-host)
    if [ -x "$DIR/scripts/align-public-host.sh" ]; then
      bash "$DIR/scripts/align-public-host.sh"
    else
      err "scripts/align-public-host.sh absent"; exit 1
    fi
    ;;
  repair-velociraptor|repair-vr|fix-vr)
    if [ -x "$DIR/scripts/repair-velociraptor-access.sh" ]; then
      bash "$DIR/scripts/repair-velociraptor-access.sh"
    else
      err "scripts/repair-velociraptor-access.sh absent"; exit 1
    fi
    ;;
  repair-env|fix-env)
    if [ -x "$DIR/scripts/repair-env-file.sh" ]; then
      bash "$DIR/scripts/repair-env-file.sh" --reset-portal
    else
      err "scripts/repair-env-file.sh absent"; exit 1
    fi
    ;;
  reset-portal-admin)
    if [ -x "$DIR/scripts/reset-portal-admin.sh" ]; then
      bash "$DIR/scripts/reset-portal-admin.sh"
    else
      err "scripts/reset-portal-admin.sh absent"; exit 1
    fi
    ;;
  diagnose-vr|diagnose-velociraptor)
    if [ -x "$DIR/scripts/diagnose-velociraptor-502.sh" ]; then
      bash "$DIR/scripts/diagnose-velociraptor-502.sh"
    else
      err "scripts/diagnose-velociraptor-502.sh absent"; exit 1
    fi
    ;;
  fix-data)       fix_existing_data ;;
  update-portals) update_portals ;;
  reload-nginx)   reload_nginx ;;
  tls|tls-setup)  FP_TLS_BUILD=1 setup_tls ;;
  misp-init)      bash "$DIR/scripts/misp-init.sh" ;;
  pre-start)      pre_start ;;
  install|pre-install)
    if command -v pre_install >/dev/null 2>&1; then
      pre_install
    else
      err "Module installer.sh manquant"; exit 1
    fi
    ;;
  cleanup-processes)
    if command -v cleanup_processes >/dev/null 2>&1; then cleanup_processes; fi
    ;;
  cleanup-ports)
    if command -v cleanup_ports >/dev/null 2>&1; then cleanup_ports; fi
    ;;
  cleanup-network) cleanup_network ;;
  network-repair|net-repair|fix-network)
    if command -v fp_network_repair >/dev/null 2>&1; then
      fp_network_repair || exit 1
    else
      err "Module installer.sh manquant"; exit 1
    fi
    ;;
  tests|start-tests)
    if command -v fp_start_tests >/dev/null 2>&1; then fp_start_tests; fi
    ;;
  diagnose|diag)
    if command -v fp_diagnose_logs >/dev/null 2>&1; then fp_diagnose_logs; fi
    ;;
  auto-repair|repair)
    if command -v fp_auto_repair_loop >/dev/null 2>&1; then fp_auto_repair_loop; fi
    ;;
  timesketch-setup|ts-setup) timesketch_setup ;;
  timesketch-master-setup|ts-master-setup) timesketch_master_setup ;;
  timesketch-master-verify|ts-master-verify) timesketch_master_verify ;;
  timesketch-ui-verify|ts-ui-verify) timesketch_ui_verify ;;
  timesketch-playbook-setup|ts-playbook-setup) timesketch_playbook_setup ;;
  timesketch-playbook-verify|ts-playbook-verify) timesketch_playbook_verify ;;
  timesketch-zones-setup|ts-zones-setup) timesketch_zones_setup ;;
  timesketch-zones-verify|ts-zones-verify) timesketch_zones_verify ;;
  timesketch-full-zones-integration-verify|ts-zones-full-verify) timesketch_full_zones_integration_verify ;;
  timesketch-premium-setup|ts-premium-setup) python3 "$DIR/scripts/timesketch_premium_setup.py" ;;
  crosspivot-setup|cp-setup) crosspivot_setup ;;
  crosspivot-verify|cp-verify) crosspivot_verify ;;
  crosspivot-ui-verify|cp-ui-verify) crosspivot_ui_verify ;;
  ts-cti-fusion-setup|ts-cti-setup) ts_cti_fusion_setup ;;
  ts-cti-fusion-verify|ts-cti-verify) ts_cti_fusion_verify ;;
  ts-cti-fusion-ui-verify|ts-cti-ui-verify) ts_cti_fusion_ui_verify ;;
  ts-incident-setup|ts-ic-setup) ts_incident_commander_setup ;;
  ts-incident-verify|ts-ic-verify) ts_incident_commander_verify ;;
  ts-incident-ui-verify|ts-ic-ui-verify) ts_incident_commander_ui_verify ;;
  ts-purple-team-setup|ts-purple-setup) ts_purple_team_setup ;;
  ts-purple-team-verify|ts-purple-verify) ts_purple_team_verify ;;
  ts-purple-team-ui-verify|ts-purple-ui-verify) ts_purple_team_ui_verify ;;
  sigma-master-setup) sigma_master_setup ;;
  sigma-master-verify) sigma_master_verify ;;
  sigma-master-ui-verify) sigma_master_ui_verify ;;
  ti-master-setup) ti_master_setup ;;
  ti-master-verify) ti_master_verify ;;
  ti-master-ui-verify) ti_master_ui_verify ;;
  analyzers-master-setup) analyzers_master_setup ;;
  analyzers-master-verify) analyzers_master_verify ;;
  analyzers-master-ui-verify) analyzers_master_ui_verify ;;
  visualizations-master-setup) visualizations_master_setup ;;
  visualizations-master-verify) visualizations_master_verify ;;
  visualizations-master-ui-verify) visualizations_master_ui_verify ;;
  soc-autonomous-run|soc-auto-run) soc_autonomous_run ;;
  soc-autonomous-verify|soc-auto-verify) soc_autonomous_verify ;;
  soc-autonomous-ui-verify|soc-auto-ui-verify) soc_autonomous_ui_verify ;;
  platform-health-dashboard-setup|platform-health-setup) platform_health_dashboard_setup ;;
  platform-health-dashboard-verify|platform-health-verify) platform_health_dashboard_verify ;;
  dashboard-metrics-extract|dash-metrics-extract) dashboard_metrics_extract ;;
  dashboard-panels-check|dash-panels-check) dashboard_panels_check ;;
  dashboard-metrics-compare|dash-metrics-compare) dashboard_metrics_compare ;;
  dashboard-metrics-verify|dash-metrics-verify) dashboard_metrics_verify ;;
  dashboard-qa|dashboard-qa-full|dash-qa-full) dashboard_qa_full ;;
  fp-consolidation-master|fp-consolidation) fp_consolidation_master ;;
  fp-consolidation-verify) fp_consolidation_verify ;;
  fp-audit-global|fp-audit) fp_audit_global ;;
  fp-audit-global-verify) fp_audit_global_verify ;;
  fp-e2e-tests|fp-e2e) fp_e2e_tests ;;
  fp-e2e-tests-verify) fp_e2e_tests_verify ;;
  fp-ui-tests|fp-ui) fp_ui_tests ;;
  fp-ui-tests-verify) fp_ui_tests_verify ;;
  timesketch-advanced|ts-advanced) timesketch_advanced ;;
  timesketch-e2e|ts-e2e) timesketch_e2e ;;
  timesketch-deep|ts-deep) timesketch_deep_test ;;
  observability-deep|obs-deep|os-gf-deep) observability_deep_test ;;
  opensearch-deep|os-deep) opensearch_deep_test ;;
  grafana-deep|gf-deep) grafana_deep_test ;;
  grafana-timesketch|gf-ts) grafana_timesketch ;;
  grafana-timesketch-verify|gf-ts-verify) grafana_timesketch_verify ;;
  grafana-master-setup|gf-master-setup) grafana_master_setup ;;
  grafana-master-verify|gf-master-verify) grafana_master_verify ;;
  grafana-master-ui-verify|gf-master-ui-verify) grafana_master_ui_verify ;;
  opencti-master-setup|octi-master-setup) opencti_master_setup ;;
  opencti-master-verify|octi-master-verify) opencti_master_verify ;;
  opencti-master-ui-verify|octi-master-ui-verify) opencti_master_ui_verify ;;
  misp-master-setup|misp-master-setup) misp_master_setup ;;
  misp-master-verify|misp-master-verify) misp_master_verify ;;
  misp-master-ui-verify|misp-master-ui-verify) misp_master_ui_verify ;;
  thehive-master-setup|th-master-setup) thehive_master_setup ;;
  thehive-master-verify|th-master-verify) thehive_master_verify ;;
  thehive-master-ui-verify|th-master-ui-verify) thehive_master_ui_verify ;;
  cortex-master-setup|cx-master-setup) cortex_master_setup ;;
  cortex-master-verify|cx-master-verify) cortex_master_verify ;;
  cortex-master-ui-verify|cx-master-ui-verify) cortex_master_ui_verify ;;
  minio-master-setup|mi-master-setup) minio_master_setup ;;
  minio-master-verify|mi-master-verify) minio_master_verify ;;
  minio-master-ui-verify|mi-master-ui-verify) minio_master_ui_verify ;;
  portal-cert-master-setup|pc-master-setup) portal_cert_master_setup ;;
  portal-cert-master-verify|pc-master-verify) portal_cert_master_verify ;;
  portal-cert-master-ui-verify|pc-master-ui-verify) portal_cert_master_ui_verify ;;
  portal-auth-ui-verify|pc-auth-ui-verify) portal_auth_ui_verify ;;
  opensearch-advanced|os-advanced) opensearch_advanced ;;
  opensearch-dashboards|os-dashboards|os-fp-osd) opensearch_dashboards_fp ;;
  opensearch-verify|os-verify|os-fp-verify) opensearch_fp_verify ;;
  opensearch-siem|os-siem) opensearch_siem ;;
  opensearch-ti-sync|os-ti-sync) opensearch_ti_sync ;;
  opensearch-siem-ti-rules|os-ti-rules) opensearch_siem_ti_rules ;;
  opensearch-siem-ti-verify|os-ti-verify) opensearch_siem_ti_verify ;;
  opensearch-dashboards-ti|os-dashboards-ti) opensearch_dashboards_ti ;;
  opensearch-siem-ti|os-siem-ti) opensearch_siem_ti ;;
  opensearch-siem-rules-mass|os-rules-mass) opensearch_siem_rules_mass ;;
  opensearch-dashboards-obs|os-dashboards-obs) opensearch_dashboards_obs ;;
  opensearch-siem-full-verify|os-siem-full-verify) opensearch_siem_full_verify ;;
  opensearch-siem-full|os-siem-full) opensearch_siem_full ;;
  *)
    echo -e "${CYAN}Forensic Platform v2.1${NC}"
    echo ""
    echo "  start | all       ⚡ FAST-BOOT — deps + réseau + up (--no-build --pull never) + status"
    echo "  -full-start       🚀 ORCHESTRATEUR — bootstrap vierge + install + build + test + rapport"
    echo "  full-start | full 🏗️  alias -full-start (orchestrateur complet)"
    echo "  rebuild           🏗️  alias -full-start (orchestrateur complet)"
    echo "  install           PHASE 0 — Pré-installation packages + sysctl + groupe docker"
    echo "  cleanup-processes PHASE 2 — Tuer anciens processus FP"
    echo "  cleanup-ports     PHASE 2 — Vérifier/libérer ports critiques (FP_KILL_PORTS=1 pour kill)"
    echo "  cleanup-network   PHASE 2 — Nettoyer réseaux Docker conflictuels"
    echo "  network-repair    PHASE 2bis — Réparation profonde réseau FP (Address in use)"
    echo "  tests             PHASE 6 — Lancer les tests automatiques de santé"
    echo "  diagnose | diag   PHASE 5bis — Scanner les logs containers (patterns d'erreur)"
    echo "  auto-repair       PHASE 6bis — Boucle auto-réparation (3 retries max)"
    echo "  status            PHASE 4 — Statut global (containers + endpoints + réseaux + ports)"
    echo "  open-ui | ui      Ouvrir dashboards dans Cursor (FP_START_OPEN_UI=cursor|xdg|both|0)"
    echo "  start-logs [n]    Logs services critiques (défaut tail=100)"
    echo "  ui-campaign       Tests UI/fonctionnels complets (OSD, GF, TS, portails, CTI)"
    echo "  qa-ultra          Campagne QA ULTRA-AGRESSIVE (47 specs Playwright + API + 15 analystes)"
    echo "  osd-all-phases-test  Tests toutes phases OSD (routes + TI + détection)"
    echo "  stop              Arrêter tous les services"
    echo "  restart           Redémarrer"
    echo "  status            État des containers"
    echo "  health            Vérifier tous les endpoints"
    echo "  logs [service]    Logs temps réel"
    echo "  backup            Sauvegarder PostgreSQL"
    echo "  urls              Afficher URLs + credentials"
    echo "  update-portals    Rebuild cert-portal + it-portal (--no-cache)"
    echo "  fix-data          ⚡ Corriger mapping données existantes + reset MISP"
    echo "  misp-init         🔑 Reset credentials MISP manuellement"
    echo "  reload-nginx      🔄 Recharger config Nginx"
    echo "  tls | tls-setup   🔒 TLS auto (CA + cert IP + config.json + nginx + validation)"
    echo "  timesketch-setup           ⚙️  Config + démarrage Timesketch (prérequis Master)"
    echo "  timesketch-master-setup    🚀 Timesketch Master (ECS + fusion + playbooks)"
    echo "  timesketch-master-verify   ✅ Verify API Master (ECS + fusion + analyzers)"
    echo "  timesketch-ui-verify       🖥️  Verify UI Master (explore/stories/aggregations)"
    echo "  timesketch-playbook-setup  📋 Playbooks DFIR/SOC/CTI (saved searches + stories)"
    echo "  timesketch-playbook-verify ✅ Verify playbooks Timesketch"
    echo "  timesketch-zones-setup       🧩 Setup 11 zones Timesketch (timelines→viz)"
    echo "  timesketch-zones-verify      ✅ Verify par zone"
    echo "  timesketch-full-zones-integration-verify  ✅ Verify global 11 zones"
    echo "  crosspivot-setup       🔀 Cross-Pivot OS↔Timesketch (boutons + liens)"
    echo "  crosspivot-verify      ✅ Verify pivots API"
    echo "  crosspivot-ui-verify   🖥️  Verify UI OSD + Timesketch"
    echo "  ts-cti-fusion-setup    🛡️  Timesketch CTI Fusion (timeline FP-CTI-Fusion + pivots)"
    echo "  ts-cti-fusion-verify   ✅ Verify CTI Fusion API (ECS ti.* + analyzers)"
    echo "  ts-cti-fusion-ui-verify 🖥️  Verify CTI Fusion UI (Timesketch + OSD)"
    echo "  ts-incident-setup      🚨 Timesketch Incident Commander (timeline IR + pivots)"
    echo "  ts-incident-verify     ✅ Verify Incident Commander API (ir.phase + pivots)"
    echo "  ts-incident-ui-verify  🖥️  Verify Incident Commander UI (Timesketch + OSD)"
    echo "  ts-purple-team-setup   🟣 Timesketch Purple Team (simulation + MITRE + pivots)"
    echo "  ts-purple-team-verify  ✅ Verify Purple Team API (purple.* + mitre.*)"
    echo "  ts-purple-team-ui-verify 🖥️  Verify Purple Team UI (Timesketch + OSD)"
    echo "  sigma-master-setup     📐 Sigma Master (règles + index + analyzer)"
    echo "  sigma-master-verify    ✅ Verify Sigma Master API"
    echo "  sigma-master-ui-verify 🖥️  Verify Sigma Master UI"
    echo "  ti-master-setup        🛡️  TI Master (OpenCTI + MISP + FP-TI)"
    echo "  ti-master-verify       ✅ Verify TI Master API"
    echo "  ti-master-ui-verify    🖥️  Verify TI Master UI"
    echo "  analyzers-master-setup ⚙️  Analyzers Master (sigma/domain/feature/misp)"
    echo "  analyzers-master-verify ✅ Verify Analyzers Master API"
    echo "  analyzers-master-ui-verify 🖥️ Verify Analyzers Master UI"
    echo "  visualizations-master-setup 📊 Visualizations Master (pack premium)"
    echo "  visualizations-master-verify ✅ Verify Visualizations Master API"
    echo "  visualizations-master-ui-verify 🖥️ Verify Visualizations Master UI"
    echo "  soc-autonomous-run       🤖 SOC Autonomous — health cycle + corrections"
    echo "  soc-autonomous-verify    ✅ Verify agrégé (tous modules)"
    echo "  soc-autonomous-ui-verify 🖥️ Verify UI globale OSD + Timesketch"
    echo "  platform-health-dashboard-setup  🏥 Dashboard FP — Platform Health"
    echo "  platform-health-dashboard-verify ✅ Verify Platform Health (OSD + index)"
    echo "  dashboard-metrics-extract      📊 Extraire métriques dashboards (DOM Playwright)"
    echo "  dashboard-panels-check         🧩 Vérifier panels / pages blanches (Playwright)"
    echo "  dashboard-metrics-compare      ⚖️  Comparer métriques (règles strictes)"
    echo "  dashboard-metrics-verify       🔒 Rapport + FAIL si incohérence (validation humaine)"
    echo "  dashboard-qa                   🔁 Campagne complète extract→panels→compare→verify"
    echo "  fp-consolidation-master        📦 Pack Final Consolidation (22 verify + intégrations)"
    echo "  fp-consolidation-verify        ✅ Verify consolidation (0 erreur)"
    echo "  fp-audit-global                🔍 Audit global éditeur → docs/FP_AUDIT_GLOBAL_REPORT.md"
    echo "  fp-audit-global-verify         ✅ Verify rapport audit complet"
    echo "  fp-e2e-tests                   🧪 Pack E2E (ingestion → SOC)"
    echo "  fp-e2e-tests-verify            ✅ Verify E2E (0 erreur)"
    echo "  fp-ui-tests                    🖥️  Pack UI QA (tous parcours)"
    echo "  fp-ui-tests-verify             ✅ Verify UI (0 erreur)"
    echo "  timesketch-advanced  ⚡ Activer Timesketch avancé (Sigma/TI/analyzers + patches)"
    echo "  timesketch-e2e       🧪 Test E2E Timesketch avancé (ingest + analyzers + API)"
    echo "  timesketch-deep      🔬 Deep test Sigma/TI/UI (corrige config manquante)"
    echo "  observability-deep   🔬 Deep test OpenSearch + Grafana (cluster, OSD, datasources)"
    echo "  opensearch-deep      🔬 Deep test OpenSearch seul"
    echo "  grafana-deep         🔬 Deep test Grafana seul"
    echo "  grafana-timesketch   📊 Dashboards Grafana Timesketch (POINT 4)"
    echo "  grafana-timesketch-verify  ✅ Vérifier dashboards Timesketch (API + données)"
    echo "  grafana-master-setup      🏢 Grafana Master — datasources + dashboards + alerting"
    echo "  grafana-master-verify     ✅ Verify Grafana Master (API)"
    echo "  grafana-master-ui-verify  🖥️ Verify UI Grafana (toutes zones)"
    echo "  opencti-master-setup      🛡️ OpenCTI Master — connecteurs + graphe + import/export"
    echo "  opencti-master-verify     ✅ Verify OpenCTI Master (API)"
    echo "  opencti-master-ui-verify  🖥️ Verify UI OpenCTI (16 zones)"
    echo "  misp-master-setup         🛡️ MISP Master — feeds + galaxies + CTI fusion"
    echo "  misp-master-verify        ✅ Verify MISP Master (API)"
    echo "  misp-master-ui-verify     🖥️ Verify UI MISP (12 zones)"
    echo "  thehive-master-setup      🛡️ TheHive Master — cases + playbooks + intégrations"
    echo "  thehive-master-verify     ✅ Verify TheHive Master (API)"
    echo "  thehive-master-ui-verify  🖥️ Verify UI TheHive (14 zones)"
    echo "  cortex-master-setup       🧠 Cortex Master — analyzers + responders + jobs + CTI"
    echo "  cortex-master-verify      ✅ Verify Cortex Master (API)"
    echo "  cortex-master-ui-verify   🖥️ Verify UI Cortex (10 zones)"
    echo "  minio-master-setup        📦 MinIO Master — buckets premium + RBAC + lifecycle"
    echo "  minio-master-verify       ✅ Verify MinIO Master (API)"
    echo "  minio-master-ui-verify    🖥️ Verify UI MinIO (9 zones)"
    echo "  portal-cert-master-setup  🌐 Portal CERT/IT Master — 11 zones éditeur"
    echo "  portal-cert-master-verify ✅ Verify Portal CERT Master (API)"
    echo "  portal-cert-master-ui-verify 🖥️ Verify UI Portal CERT (11 zones)"
    echo "  opensearch-advanced  🔧 SIEM — ILM, templates, platform-logs"
    echo "  opensearch-dashboards  📊 Import dashboards OpenSearch Dashboards FP"
    echo "  opensearch-verify    ✅ Vérification OpenSearch SIEM"
    echo "  opensearch-siem      🚀 SIEM complet (advanced + dashboards + verify)"
    echo "  opensearch-ti-sync   🔄 Sync IOC OpenCTI + MISP → OpenSearch"
    echo "  opensearch-siem-ti   🛡️  SIEM TI complet (sync + pipeline + alertes + OSD)"
    echo "  opensearch-siem-ti-rules  ⚠️  Alertes OpenSearch TI (ti_match)"
    echo "  opensearch-siem-ti-verify ✅ Vérification SIEM TI"
    echo "  opensearch-dashboards-ti  📊 Dashboards IOC (4 vues SIEM)"
    echo "  opensearch-dashboards-obs 📊 Dashboard Observability pipeline"
    echo "  opensearch-siem-rules-mass 🛡️  700+ règles détection (Alerting + catalogue)"
    echo "  opensearch-siem-full-verify ✅ Vérification SIEM complète"
    echo "  opensearch-siem-full      🚀 SIEM haut de gamme (tout en une fois)"
    echo "  infra-recover-core          🔁 Postgres/Redis/Cassandra + TS worker (conflit IP Docker)"
    echo "  nomenclature-inventory      📋 Inventaire nomenclature (anti-régression)"
    echo "  nomenclature-plan           📝 Plan de renommage YAML"
    echo "  nomenclature-apply          🏷️  Appliquer nomenclature + rebuild + backup"
    echo "  nomenclature-rollback       ↩️  Restaurer dernier backup nomenclature"
    echo "  cluster-repair            🔧 Réparation shards / index patterns FP"
    echo "  enterprise-setup          🏢 MITRE + Sigma + Hunts + Fusion + CTI + UX"
    echo "  enterprise-verify         ✅ Vérification modules Enterprise"
    echo "  analyst-playbook-setup    📘 Analyst Playbook (dashboard + notebook + side panel)"
    echo "  analyst-playbook-verify   ✅ Vérification Analyst Playbook"
    echo "  soc-manager-playbook-setup    👔 SOC Manager Playbook"
    echo "  soc-manager-playbook-verify   ✅ Vérification SOC Manager"
    echo "  incident-commander-playbook-setup  🚨 Incident Commander Playbook"
    echo "  incident-commander-playbook-verify ✅ Vérification Incident Commander"
    echo "  soc-director-playbook-setup   🎯 SOC Director Playbook"
    echo "  soc-director-playbook-verify  ✅ Vérification SOC Director"
    echo "  ti-lead-playbook-setup        🛡️  TI Lead Playbook"
    echo "  ti-lead-playbook-verify       ✅ Vérification TI Lead"
    echo "  dfir-senior-playbook-setup    🔬 DFIR Senior Playbook"
    echo "  dfir-senior-playbook-verify   ✅ Vérification DFIR Senior"
    echo "  purple-team-playbook-setup    🟣 Purple Team Playbook"
    echo "  purple-team-playbook-verify   ✅ Vérification Purple Team"
    echo "  th-lead-playbook-setup        🏹 Threat Hunting Lead Playbook"
    echo "  th-lead-playbook-verify       ✅ Vérification TH Lead"
    echo "  soc-automation-playbook-setup ⚙️  SOC Automation Playbook"
    echo "  soc-automation-playbook-verify ✅ Vérification SOC Automation"
    echo "  cti-fusion-playbook-setup     🔗 CTI Fusion Center Playbook"
    echo "  cti-fusion-playbook-verify    ✅ Vérification CTI Fusion"
    echo "  parsing-master-setup          📋 Parsing Master v1 (pipelines + normalisation)"
    echo "  parsing-master-verify         ✅ Vérification parsing v1"
    echo "  parsing-master-full-setup     📋 Parsing Master Full Spectrum (tous logs)"
    echo "  parsing-master-full-verify    ✅ Vérification parsing full (0 problème)"
    echo "  parsing-playbook-ecs-apply    🔗 Sync requêtes ECS hunts/playbooks"
    echo "  hunting-parsing-verify        🏹 Verify parsing ↔ Threat Hunting"
    echo "  purple-team-parsing-verify    🟣 Verify parsing ↔ Purple Team"
    echo "  dfir-parsing-verify           🔬 Verify parsing ↔ DFIR"
    echo "  cti-parsing-verify            🛡️  Verify parsing ↔ CTI"
    echo "  soc-parsing-verify            👔 Verify parsing ↔ SOC dashboards"
    echo "  incident-parsing-verify       🚨 Verify parsing ↔ Incident Commander"
    echo "  parsing-master-full-integration-verify  ✅ Verify intégration globale"
    echo "  parsing-master-full-inventory 📊 Inventaire full → docs/PARSING_FULL_INVENTORY.md"
    echo "  parsing-inventory             📊 Inventaire champs / indices FP (v1)"
    echo "  reset             ⚠️  Supprimer TOUTES les données"
    echo "  fix-opensearch    ⚡ Corriger erreur Lucene codec OpenSearch"
    echo "  repair-vr         ⚡ Réparer Velociraptor (502 / sidecar GUI)"
    echo "  repair-env        ⚡ Réparer .env corrompu + reset admin portail"
    echo "  reset-portal-admin  Réinitialiser admin CERT (users.json)"
    echo "  align-host        🌐 Réaligner IP hôte (portails, TLS, nginx, VR)"
    ;;
esac
