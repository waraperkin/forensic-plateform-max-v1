# ==============================================================
#  deploy-modes.sh — Déploiements modulaires Forensic Platform
# ==============================================================
# Sourcé par forensic.sh — fournit :
#   fp_deploy_mode <mode>
#   fp_deploy_list_modes
#   fp_deploy_help
#
# Modes opérationnels (chaque mode démarre un sous-ensemble cohérent) :
#   portals           Portails CERT + IT (+ redis, minio, OpenSearch, nginx)
#   sekoia            Sekoia Extended Platform (portails + control-plane + monitor)
#   portals-sekoia    Alias explicite de sekoia
#   portals-forensic  Portails + outils forensic (OSD, OpenCTI, Timesketch,
#                     TheHive, MISP, Cortex, Grafana, Logstash, Velociraptor…)
#   full              Stack complète (délègue à full_start_orchestrator / -full-start)
# ==============================================================

FP_DEPLOY_MODES_LOADED=1

fp_deploy_help() {
  cat <<'HELP'
Modes de déploiement modulaires :

  ./forensic.sh deploy portals
      Portails CERT/IT uniquement (redis, MinIO, OpenSearch, nginx).
      URLs : /  et  /it/

  ./forensic.sh deploy sekoia
      Sekoia Extended Platform opérationnelle (UI /sekoia via cert-portal,
      control-plane + monitor + OpenSearch + MinIO + nginx).

  ./forensic.sh deploy portals-sekoia
      Portails CERT/IT + Sekoia Extended Platform (alias de sekoia).

  ./forensic.sh deploy portals-forensic
      Portails CERT/IT + outils forensic (OpenSearch/OSD, MinIO, OpenCTI,
      Timesketch, TheHive, MISP, Cortex, Grafana, Logstash, Velociraptor…).
      Sans couche Sekoia.

  ./forensic.sh deploy full
      Stack complète — équivalent à ./forensic.sh -full-start

  ./forensic.sh deploy --list
      Affiche les modes et les services associés.

Chaque mode est autonome : préflight TLS/.env, réseaux externes, build
des images nécessaires, attente santé, vérification des endpoints du mode.
HELP
}

# Services socle communs à tous les modes partiels
_fp_deploy_core_services() {
  echo "redis minio minio-init opensearch-node1 opensearch-node2 opensearch-init cert-portal it-portal nginx"
}

_fp_deploy_sekoia_services() {
  echo "$(_fp_deploy_core_services) sekoia-controlplane sekoia-monitor"
}

_fp_deploy_forensic_services() {
  # Socle + chaîne DFIR/CTI/observabilité (sans Sekoia)
  echo "$(_fp_deploy_core_services) \
postgres rabbitmq cassandra \
opensearch-dashboards logstash ingest-worker filebeat \
timesketch-web timesketch-worker timesketch-init \
opencti connector-mitre connector-cve connector-opencti-datasets \
misp-db misp thehive cortex thehive-init \
grafana prometheus loki tempo \
velociraptor-bridge helk-bridge helk-sigma-runner ti-sync"
}

fp_deploy_list_modes() {
  echo "Modes disponibles :"
  echo "  portals           → $(_fp_deploy_core_services)"
  echo "  sekoia            → $(_fp_deploy_sekoia_services)"
  echo "  portals-sekoia    → $(_fp_deploy_sekoia_services)"
  echo "  portals-forensic  → $(_fp_deploy_forensic_services)"
  echo "  full              → stack complète (-full-start)"
}

_fp_deploy_normalize_mode() {
  local m
  m=$(echo "${1:-}" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
  case "$m" in
    portal|portails|cert|cert-it|cert-portal|it-portal) echo "portals" ;;
    sekoia|sep|sekoia-extended|sekoia-platform) echo "sekoia" ;;
    portals-sekoia|portals+sekoia|cert-sekoia|sekoia-portals) echo "portals-sekoia" ;;
    portals-forensic|forensic|dfir|outils|tools) echo "portals-forensic" ;;
    full|all|complete|-full-start|full-start) echo "full" ;;
    *) echo "$m" ;;
  esac
}

_fp_deploy_services_for_mode() {
  case "$1" in
    portals) echo "$(_fp_deploy_core_services)" ;;
    sekoia|portals-sekoia) echo "$(_fp_deploy_sekoia_services)" ;;
    portals-forensic) echo "$(_fp_deploy_forensic_services)" ;;
    *) return 1 ;;
  esac
}

_fp_deploy_compose() {
  local compose="${FP_COMPOSE:-docker compose}"
  # Accès .env root-only : préférer sudo -E docker si nécessaire
  if [ -f "$DIR/.env" ] && [ ! -r "$DIR/.env" ]; then
    if command -v sudo >/dev/null 2>&1; then
      compose="sudo -E docker compose"
    fi
  fi
  ( cd "$DIR" && $compose "$@" )
}

_fp_deploy_ensure_prereqs() {
  step "Déploiement modulaire — prérequis"
  if ! docker ps >/dev/null 2>&1; then
    err "Docker inaccessible — rejoindre le groupe docker ou utiliser sudo"
    return 1
  fi
  if [ -f "$DIR/.env" ]; then
    if [ ! -r "$DIR/.env" ] || [ ! -w "$DIR/.env" ]; then
      warn ".env permissions insuffisantes — tentative chown/chmod (wara:docker 660)"
      chmod 660 "$DIR/.env" 2>/dev/null || true
      chgrp docker "$DIR/.env" 2>/dev/null || true
      if { [ ! -r "$DIR/.env" ] || [ ! -w "$DIR/.env" ]; } && command -v sudo >/dev/null 2>&1; then
        sudo chown "$(id -u):docker" "$DIR/.env" 2>/dev/null || true
        sudo chmod 660 "$DIR/.env" 2>/dev/null || true
      fi
    fi
  fi
  if [ ! -f "$DIR/.env" ]; then
    warn ".env absent — génération secrets / repair-env"
    if declare -F repair_env >/dev/null 2>&1; then
      repair_env || true
    elif [ -x "$DIR/scripts/generate-secrets.sh" ]; then
      bash "$DIR/scripts/generate-secrets.sh" || true
    fi
  fi
  if declare -F pre_start >/dev/null 2>&1; then
    pre_start || true
  fi
  if declare -F _fp_bootstrap_external_networks >/dev/null 2>&1; then
    _fp_bootstrap_external_networks || warn "Réseaux externes partiels"
  else
    docker network inspect helk_net >/dev/null 2>&1 \
      || docker network create --driver bridge --subnet 172.30.0.0/24 helk_net >/dev/null 2>&1 || true
    docker network inspect velociraptor_net >/dev/null 2>&1 \
      || docker network create --driver bridge --subnet 172.31.0.0/24 velociraptor_net >/dev/null 2>&1 || true
  fi
  # TLS minimal pour nginx
  if [ ! -f "$DIR/config/nginx/ssl/forensic.crt" ] || [ ! -f "$DIR/config/nginx/ssl/forensic.key" ]; then
    warn "Certificats TLS absents — tentative tls-setup"
    if declare -F tls_setup >/dev/null 2>&1; then
      tls_setup || true
    elif [ -x "$DIR/scripts/tls-setup.sh" ]; then
      bash "$DIR/scripts/tls-setup.sh" || true
    fi
  fi
  # Volume externe Velociraptor (requis par compose même si sidecar absent)
  if ! docker volume inspect velociraptor-sidecar_velociraptor-data >/dev/null 2>&1; then
    docker volume create velociraptor-sidecar_velociraptor-data >/dev/null 2>&1 || true
  fi
  # Chemins VR / logs accessibles (sinon generate-config / tee échouent en non-root)
  local d
  for d in "$DIR/logs" "$DIR/velociraptor/config" "$DIR/velociraptor/clients" "$DIR/velociraptor/data"; do
    mkdir -p "$d" 2>/dev/null || true
    if [ ! -w "$d" ]; then
      chmod -R u+w "$d" 2>/dev/null || true
    fi
    if [ ! -w "$d" ]; then
      warn "Chemin non accessible en écriture : $d (sidecars peuvent échouer)"
    fi
  done
  return 0
}

_fp_deploy_container_id() {
  local svc="$1" cid=""
  cid=$(_fp_deploy_compose ps -q "$svc" 2>/dev/null | head -1)
  if [ -n "$cid" ]; then echo "$cid"; return 0; fi
  # Fallbacks noms historiques (OpenSearch)
  case "$svc" in
    opensearch-node1) docker inspect -f "{{.Id}}" forensic-opensearch-1 2>/dev/null && return 0 ;;
    opensearch-node2) docker inspect -f "{{.Id}}" forensic-opensearch-2 2>/dev/null && return 0 ;;
  esac
  docker inspect -f "{{.Id}}" "forensic-${svc}" 2>/dev/null && return 0
  docker inspect -f "{{.Id}}" "$svc" 2>/dev/null && return 0
  return 1
}

_fp_deploy_wait_healthy() {
  local svc="$1" timeout="${2:-180}" elapsed=0 status cid
  while [ "$elapsed" -lt "$timeout" ]; do
    cid=$(_fp_deploy_container_id "$svc" || true)
    if [ -z "$cid" ]; then
      status="missing"
    else
      status=$(docker inspect -f "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" "$cid" 2>/dev/null || echo "missing")
    fi
    case "$status" in
      healthy) return 0 ;;
      running)
        # Sans healthcheck Docker, "running" = OK
        return 0
        ;;
    esac
    sleep 5
    elapsed=$((elapsed + 5))
  done
  warn "Timeout santé : $svc (dernier état=$status)"
  return 1
}

_fp_deploy_verify_http() {
  local path="$1" expect="${2:-200|302|301|401|403}" label="${3:-$path}"
  local code port
  port="${FP_HTTPS_PORT:-443}"
  code=$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 20 \
    "https://127.0.0.1:${port}${path}" 2>/dev/null || echo "000")
  if echo "$code" | grep -qE "^($expect)$"; then
    ok "HTTP $label → $code"
    return 0
  fi
  err "HTTP $label → $code (attendu $expect)"
  return 1
}

_fp_deploy_verify_mode() {
  local mode="$1" fail=0
  step "Vérification opérationnelle — mode $mode"
  _fp_deploy_verify_http "/nginx-health" "200" "nginx-health" || fail=1
  _fp_deploy_verify_http "/" "200|302|401|403" "portail CERT" || fail=1
  _fp_deploy_verify_http "/it/" "200|302|401|403" "portail IT" || fail=1

  case "$mode" in
    sekoia|portals-sekoia)
      _fp_deploy_verify_http "/sekoia" "200|302|401|403" "Sekoia UI" || fail=1
      if docker exec forensic-sekoia-controlplane \
          python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8901/health',timeout=4)" \
          >/dev/null 2>&1; then
        ok "sekoia-controlplane /health"
      else
        err "sekoia-controlplane /health KO"
        fail=1
      fi
      ;;
    portals-forensic)
      _fp_deploy_verify_http "/dashboards/" "200|302|401|403" "OpenSearch Dashboards" || fail=1
      _fp_deploy_verify_http "/cti/" "200|302|401|403" "OpenCTI" || fail=1
      _fp_deploy_verify_http "/minio/" "200|302|401|403" "MinIO console" || fail=1
      _fp_deploy_verify_http "/timesketch/" "200|302|401|403" "Timesketch" || fail=1
      _fp_deploy_verify_http "/thehive/" "200|302|401|403" "TheHive" || fail=1
      _fp_deploy_verify_http "/misp/" "200|302|401|403" "MISP" || fail=1
      _fp_deploy_verify_http "/grafana/" "200|302|401|403" "Grafana" || fail=1
      ;;
  esac

  return "$fail"
}

_fp_deploy_print_urls() {
  local mode="$1" host port
  host=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "localhost")
  port="${FP_HTTPS_PORT:-443}"
  local base="https://${host}"
  [ "$port" = "443" ] || base="https://${host}:${port}"

  echo ""
  echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  Mode déployé : ${GREEN}${mode}${NC}"
  echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  CERT          ${base}/"
  echo -e "${CYAN}║${NC}  IT            ${base}/it/"
  case "$mode" in
    sekoia|portals-sekoia)
      echo -e "${CYAN}║${NC}  Sekoia SEP    ${base}/sekoia"
      ;;
    portals-forensic)
      echo -e "${CYAN}║${NC}  Dashboards    ${base}/dashboards/"
      echo -e "${CYAN}║${NC}  OpenCTI       ${base}/cti/"
      echo -e "${CYAN}║${NC}  Timesketch    ${base}/timesketch/"
      echo -e "${CYAN}║${NC}  TheHive       ${base}/thehive/"
      echo -e "${CYAN}║${NC}  MISP          ${base}/misp/"
      echo -e "${CYAN}║${NC}  Grafana       ${base}/grafana/"
      echo -e "${CYAN}║${NC}  MinIO         ${base}/minio/"
      echo -e "${CYAN}║${NC}  Velociraptor  ${base}/velociraptor/  (sidecar)"
      ;;
  esac
  echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
}

_fp_deploy_start_sidecars_if_needed() {
  local mode="$1"
  case "$mode" in
    portals-forensic|full)
      if [ -x "$DIR/scripts/setup-sidecars.sh" ]; then
        step "Sidecars HELK / Velociraptor"
        mkdir -p "$DIR/logs" 2>/dev/null || true
        if [ ! -w "$DIR/logs" ]; then
          export FP_LOG_START="/tmp/fp-deploy-${mode}.log"
          warn "logs/ non accessible — journal sidecar → $FP_LOG_START"
        fi
        bash "$DIR/scripts/setup-sidecars.sh" || warn "setup-sidecars partiel — VR/HELK peuvent être absents"
      fi
      ;;
  esac
}

fp_deploy_mode() {
  local raw="${1:-}" mode services svc_list
  if [ -z "$raw" ] || [ "$raw" = "help" ] || [ "$raw" = "-h" ] || [ "$raw" = "--help" ]; then
    fp_deploy_help
    return 0
  fi
  if [ "$raw" = "--list" ] || [ "$raw" = "list" ]; then
    fp_deploy_list_modes
    return 0
  fi

  mode="$(_fp_deploy_normalize_mode "$raw")"
  case "$mode" in
    full)
      step "Mode full — délégation à -full-start"
      if declare -F full_start_orchestrator >/dev/null 2>&1; then
        full_start_orchestrator
        return $?
      fi
      err "full_start_orchestrator indisponible"
      return 1
      ;;
    portals|sekoia|portals-sekoia|portals-forensic) ;;
    *)
      err "Mode inconnu : $raw"
      fp_deploy_list_modes
      return 1
      ;;
  esac

  services="$(_fp_deploy_services_for_mode "$mode")" || {
    err "Impossible de résoudre les services pour $mode"
    return 1
  }
  # Normaliser espaces
  # shellcheck disable=SC2086
  set -- $services
  svc_list="$*"

  echo -e "${CYAN}▶ Déploiement mode ${GREEN}${mode}${CYAN}${NC}"
  info "Services : $svc_list"

  _fp_deploy_ensure_prereqs || return 1

  step "Démarrage des services du mode"
  # Build conditionnel : FP_DEPLOY_BUILD=1 force --build ; sinon build seulement
  # si une image locale manque (évite de recréer OpenSearch à chaque deploy).
  local build_flag="" need_build=0
  if [ "${FP_DEPLOY_BUILD:-0}" = "1" ]; then
    build_flag="--build"
  else
    local s
    for s in $svc_list; do
      case "$s" in
        minio-init|opensearch-init|timesketch-init|thehive-init) continue ;;
      esac
      if ! _fp_deploy_compose images -q "$s" 2>/dev/null | grep -q .; then
        # fallback : image absente du daemon
        if ! docker image ls --format "{{.Repository}}:{{.Tag}}" | grep -qE "forensic|${s}" ; then
          need_build=1
          break
        fi
      fi
    done
    # Images buildées localement critiques
    for s in cert-portal it-portal sekoia-controlplane sekoia-monitor; do
      echo " $svc_list " | grep -q " $s " || continue
      if ! docker image inspect "forensic-plateform-max-v1-${s}:latest" >/dev/null 2>&1 \
        && ! docker image inspect "forensic-plateform-max-v1-${s}" >/dev/null 2>&1; then
        need_build=1
        break
      fi
    done
    [ "$need_build" = "1" ] && build_flag="--build"
  fi
  [ -n "$build_flag" ] && info "Build images activé ($build_flag)" || info "Démarrage sans rebuild (FP_DEPLOY_BUILD=1 pour forcer)"

  # Démarrage par phases pour les gros modes (socle d’abord)
  local phase1 phase2
  phase1="$(_fp_deploy_core_services)"
  case "$mode" in
    portals)
      # shellcheck disable=SC2086
      if ! _fp_deploy_compose up -d $build_flag $svc_list; then
        warn "compose up : nouvel essai dans 20s"
        sleep 20
        _fp_deploy_compose up -d $svc_list || { err "docker compose up échoué"; return 1; }
      fi
      ;;
    sekoia|portals-sekoia)
      # shellcheck disable=SC2086
      _fp_deploy_compose up -d $build_flag $phase1 || true
      _fp_deploy_wait_healthy opensearch-node1 300 || true
      # shellcheck disable=SC2086
      if ! _fp_deploy_compose up -d $build_flag sekoia-controlplane sekoia-monitor $phase1; then
        warn "compose up sekoia : nouvel essai"
        sleep 20
        _fp_deploy_compose up -d sekoia-controlplane sekoia-monitor $phase1 || { err "docker compose up échoué"; return 1; }
      fi
      ;;
    portals-forensic)
      # shellcheck disable=SC2086
      _fp_deploy_compose up -d $build_flag $phase1 || true
      _fp_deploy_wait_healthy opensearch-node1 300 || true
      _fp_deploy_wait_healthy redis 120 || true
      _fp_deploy_wait_healthy minio 120 || true
      # Reste du mode (sans re-toucher inutilement le socle)
      phase2=$(echo "$svc_list" | tr " " "\n" | grep -vxF -f <(echo "$phase1" | tr " " "\n") | tr "\n" " ")
      # shellcheck disable=SC2086
      if ! _fp_deploy_compose up -d $build_flag $phase2; then
        warn "compose up forensic partiel — attente OpenCTI puis nouvel essai"
        _fp_deploy_wait_healthy opencti 420 || true
        sleep 15
        # shellcheck disable=SC2086
        _fp_deploy_compose up -d $phase2 || warn "compose up forensic : certains sidecars peuvent être absents"
      fi
      ;;
  esac

  step "Attente santé des services critiques"
  local critical="redis minio opensearch-node1 cert-portal it-portal nginx"
  case "$mode" in
    sekoia|portals-sekoia) critical="$critical sekoia-controlplane" ;;
    portals-forensic) critical="$critical opensearch-dashboards opencti" ;;
  esac
  local c fail_wait=0
  for c in $critical; do
    _fp_deploy_wait_healthy "$c" 300 || fail_wait=1
  done

  _fp_deploy_start_sidecars_if_needed "$mode"

  # Alignements légers post-démarrage (admin portail, buckets)
  if [ -x "$DIR/scripts/ensure-portal-admin.sh" ]; then
    bash "$DIR/scripts/ensure-portal-admin.sh" >/dev/null 2>&1 || true
  fi

  local verify_rc=0
  _fp_deploy_verify_mode "$mode" || verify_rc=$?
  _fp_deploy_print_urls "$mode"

  if [ "$verify_rc" -ne 0 ] || [ "$fail_wait" -ne 0 ]; then
    warn "Déploiement $mode terminé avec avertissements — vérifier les logs"
    return 1
  fi
  ok "Mode $mode opérationnel"
  return 0
}
