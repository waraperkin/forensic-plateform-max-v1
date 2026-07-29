#!/bin/bash
# ==============================================================
#  installer.sh — Module installateur + orchestrateur FP
# ==============================================================
# Sourcé par forensic.sh — fournit :
#   - fp_log_init / fp_log
#   - pre_install (PHASE 1)
#   - cleanup_processes / cleanup_ports (PHASE 2)
#   - status_full (PHASE 4)
#   - fp_start_tests (PHASE 6)
#   - fp_bootstrap_fresh_machine (orchestrateur phase 0 — machine vierge)
#   - fp_verify_system / fp_verify_monorepo (orchestrateur -full-start)
#   - fp_full_start_health_global / fp_full_start_extended_tests / fp_full_start_final_report
#
# Idempotent — réexécutable sans erreur ni régression.
# Ne tue jamais le script (return au lieu de exit).

if [ -n "${DIR:-}" ] && [ -f "${DIR}/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "${DIR}/scripts/lib/host-ip.sh"
elif [ -f "$(dirname "${BASH_SOURCE[0]}")/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$(dirname "${BASH_SOURCE[0]}")/host-ip.sh"
fi
if [ -n "${DIR:-}" ] && [ -f "${DIR}/scripts/lib/vr-gui-check.sh" ]; then
  # shellcheck source=/dev/null
  . "${DIR}/scripts/lib/vr-gui-check.sh"
elif [ -f "$(dirname "${BASH_SOURCE[0]}")/vr-gui-check.sh" ]; then
  # shellcheck source=/dev/null
  . "$(dirname "${BASH_SOURCE[0]}")/vr-gui-check.sh"
fi
if [ -n "${DIR:-}" ] && [ -f "${DIR}/scripts/lib/platform-host.sh" ]; then
  # shellcheck source=/dev/null
  . "${DIR}/scripts/lib/platform-host.sh"
elif [ -f "$(dirname "${BASH_SOURCE[0]}")/platform-host.sh" ]; then
  # shellcheck source=/dev/null
  . "$(dirname "${BASH_SOURCE[0]}")/platform-host.sh"
fi

# Hérite des couleurs et helpers de forensic.sh (info/ok/warn/err/step).
# Si appelé en standalone, on fournit des fallbacks.
# Ne pas tester `command -v info` : /usr/bin/info (GNU) existe sur Debian et masque le helper.
if [[ $(type -t info 2>/dev/null || echo "") != "function" ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BLUE='\033[0;34m'; NC='\033[0m'
  info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
  ok()  { echo -e "${GREEN}[ OK ]${NC} $*"; }
  warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
  err() { echo -e "${RED}[ERR ]${NC} $*"; }
  step(){ echo -e "\n${BLUE}━━━ $* ━━━${NC}"; }
fi

FP_LOG_DIR="${FP_LOG_DIR:-$DIR/logs}"
FP_LOG_START="${FP_LOG_DIR}/forensic_start.log"
FP_LOG_INSTALL="${FP_LOG_DIR}/forensic_install.log"
FP_LOG_NETWORK="${FP_LOG_DIR}/forensic_network.log"

# ──────────────────────────────────────────────────────────────
#  PHASE 5 — LOGGING
# ──────────────────────────────────────────────────────────────
fp_log_init() {
  mkdir -p "$FP_LOG_DIR" 2>/dev/null || true
  : > /dev/null 2>&1 # no-op safety
  for f in "$FP_LOG_START" "$FP_LOG_INSTALL" "$FP_LOG_NETWORK"; do
    touch "$f" 2>/dev/null || true
  done
}

fp_log() {
  # $1=channel(start|install|network) $2..=message
  local ch="$1"; shift || true
  local target
  case "$ch" in
    install) target="$FP_LOG_INSTALL" ;;
    network) target="$FP_LOG_NETWORK" ;;
    *)       target="$FP_LOG_START" ;;
  esac
  local ts
  ts=$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date)
  echo "[$ts] $*" >> "$target" 2>/dev/null || true
}

# Wrapper sudo non-interactif : passe en silencieux si pas de sudo NOPASSWD
_fp_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return $?
  fi
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      sudo -n "$@"
      return $?
    fi
    fp_log install "sudo non-interactif indisponible pour: $*"
    return 1
  fi
  fp_log install "sudo absent — impossible: $*"
  return 1
}

# ──────────────────────────────────────────────────────────────
#  WRAPPER DOCKER — accès robuste (user / sudo / démarrage daemon)
# ──────────────────────────────────────────────────────────────
# FP_DOCKER et FP_COMPOSE sont définis par fp_ensure_docker().
FP_DOCKER="${FP_DOCKER:-docker}"
FP_COMPOSE="${FP_COMPOSE:-docker compose}"

_fp_docker() { ${FP_DOCKER} "$@"; }
_fp_compose() { ${FP_COMPOSE} "$@"; }

_fp_docker_ok() {
  _fp_docker ps >/dev/null 2>&1
}

# Vérifie que docker ps répond. Ne touche PAS à systemd ni au daemon.
# Retourne 0 si OK, 1 sinon (message clair pour l'utilisateur).
fp_ensure_docker() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  fp_log_init

  if ! command -v docker >/dev/null 2>&1; then
    err "Binaire docker introuvable dans PATH"
    err "  (installation Docker hors scope de forensic.sh — vérifier l'hôte)"
    fp_log install "docker binary missing"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 1
  fi

  if docker ps >/dev/null 2>&1; then
    FP_DOCKER="docker"
    FP_COMPOSE="docker compose"
    ok "Docker accessible (docker ps OK)"
    fp_log install "docker OK"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 0
  fi

  # Fallback lecture seule via sudo -n (sans systemctl, sans modifier /etc)
  if _fp_sudo docker ps >/dev/null 2>&1; then
    FP_DOCKER="sudo -n docker"
    FP_COMPOSE="sudo -n docker compose"
    warn "Docker accessible via sudo -n (groupe docker : newgrp docker ou nouveau terminal)"
    fp_log install "docker OK (sudo -n)"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 0
  fi

  err "Docker inaccessible — docker ps échoue"
  err "  Vérifier que dockerd répond sur cet hôte, puis : docker ps"
  err "  Si groupe docker : newgrp docker  (ou rouvrir le terminal)"
  fp_log install "docker INACCESSIBLE (docker ps failed)"
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 1
}

# Rebind UP/DOWN forensic.sh si fp_ensure_docker a basculé sur sudo
fp_bind_compose_cmds() {
  if [ "${FP_DOCKER:-docker}" != "docker" ]; then
    UP="${FP_COMPOSE} up -d"
    DOWN="${FP_COMPOSE} down --remove-orphans"
  fi
}

# ──────────────────────────────────────────────────────────────
#  PHASE 1 — PRE-INSTALLATION (packages + groupe docker + sysctl)
# ──────────────────────────────────────────────────────────────
# Mapping commande → package apt
_fp_pkg_for() {
  case "$1" in
    docker)      echo "docker.io" ;;
    python3)     echo "python3" ;;
    pip3)        echo "python3-pip" ;;
    jq)          echo "jq" ;;
    curl)        echo "curl" ;;
    sysctl)      echo "procps" ;;
    openssl)     echo "openssl" ;;
    ifconfig)    echo "net-tools" ;;
    netstat)     echo "net-tools" ;;
    lsof)        echo "lsof" ;;
    *)           echo "$1" ;;
  esac
}

_fp_check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

pre_install() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "PHASE 1/6 — Pré-installation (packages + permissions + sysctl)"
  fp_log_init
  fp_log install "=== pre_install start ==="

  local required=(python3 pip3 jq curl sysctl openssl ifconfig lsof)
  local missing=()
  local found=()
  for cmd in "${required[@]}"; do
    if _fp_check_cmd "$cmd"; then
      found+=("$cmd")
    else
      missing+=("$cmd")
    fi
  done

  if [ "${#found[@]}" -gt 0 ]; then
    ok "Présents: ${found[*]}"
    fp_log install "présents: ${found[*]}"
  fi

  # docker compose v2 (sous-commande, pas binaire isolé)
  if _fp_check_cmd docker; then
    if _fp_docker compose version >/dev/null 2>&1 || docker compose version >/dev/null 2>&1; then
      ok "docker compose v2 OK"
      fp_log install "docker compose v2 OK"
    else
      warn "docker compose v2 absent — package docker-compose-plugin recommandé"
      missing+=("docker-compose-plugin")
    fi
  fi

  # Installation auto si packages manquants
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "Manquants: ${missing[*]} — installation auto"
    fp_log install "manquants: ${missing[*]}"

    local pkgs=()
    for cmd in "${missing[@]}"; do
      pkgs+=("$(_fp_pkg_for "$cmd")")
    done
    # dédoublonnage
    local pkgs_uniq
    pkgs_uniq=$(printf '%s\n' "${pkgs[@]}" | awk '!s[$0]++')

    if command -v apt-get >/dev/null 2>&1; then
      info "apt-get install: $pkgs_uniq"
      if _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$FP_LOG_INSTALL" 2>&1; then
        fp_log install "apt-get update OK"
      else
        warn "apt-get update échoué — voir $FP_LOG_INSTALL"
        fp_log install "apt-get update ÉCHEC"
      fi
      # shellcheck disable=SC2086
      if _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs_uniq >> "$FP_LOG_INSTALL" 2>&1; then
        ok "Packages installés"
        fp_log install "install OK"
      else
        warn "Installation partielle — détail: $FP_LOG_INSTALL"
        fp_log install "install ÉCHEC"
      fi
    elif command -v dnf >/dev/null 2>&1; then
      # shellcheck disable=SC2086
      _fp_sudo dnf install -y $pkgs_uniq >> "$FP_LOG_INSTALL" 2>&1 || \
        warn "dnf install échoué — voir $FP_LOG_INSTALL"
    elif command -v yum >/dev/null 2>&1; then
      # shellcheck disable=SC2086
      _fp_sudo yum install -y $pkgs_uniq >> "$FP_LOG_INSTALL" 2>&1 || \
        warn "yum install échoué — voir $FP_LOG_INSTALL"
    else
      warn "Aucun gestionnaire de packages connu (apt/dnf/yum) — installer manuellement: $pkgs_uniq"
      fp_log install "no package manager found"
    fi
  else
    ok "Tous les packages requis sont présents"
  fi

  # Docker : contrôle léger ici ; fp_ensure_docker() est appelé dans start()
  if _fp_check_cmd docker; then
    if docker ps >/dev/null 2>&1; then
      ok "Docker accessible"
      fp_log install "docker accessible (user)"
    elif _fp_sudo docker ps >/dev/null 2>&1; then
      ok "Docker accessible via sudo"
      fp_log install "docker accessible (sudo)"
    else
      info "Docker sera vérifié/démarré automatiquement à la phase suivante"
      fp_log install "docker check deferred to start()"
    fi
  fi

  # sysctl vm.max_map_count (déjà géré par pre_start mais on couvre standalone)
  local mc
  mc=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)
  if [ "$mc" -lt 262144 ]; then
    info "vm.max_map_count=$mc → tentative 262144"
    if sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
      ok "vm.max_map_count=262144"
      fp_log install "sysctl vm.max_map_count=262144 OK"
    elif _fp_sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
      ok "vm.max_map_count=262144 (sudo)"
      fp_log install "sysctl sudo OK"
    else
      warn "sysctl impossible — exécuter manuellement: sudo sysctl -w vm.max_map_count=262144"
      fp_log install "sysctl ÉCHEC"
    fi
  else
    ok "vm.max_map_count=$mc ✓"
  fi

  # ulimit nofile (utile pour OpenSearch)
  local nof
  nof=$(ulimit -n 2>/dev/null || echo 0)
  if [ "$nof" -lt 65536 ]; then
    info "ulimit -n=$nof — recommandé 65536 (configurable dans /etc/security/limits.conf)"
    fp_log install "ulimit -n=$nof (low)"
  fi

  fp_log install "=== pre_install end ==="
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# ──────────────────────────────────────────────────────────────
#  PHASE 2 — NETTOYAGE AVANT START
# ──────────────────────────────────────────────────────────────
cleanup_processes() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "PHASE 2/6 — Nettoyage anciens processus FP"
  fp_log start "=== cleanup_processes start ==="

  # docker compose down silencieux (n'arrête pas les containers d'autres projets)
  # NOTE: désactivé par défaut pour préserver l'état — activable via FP_CLEAN_DOWN=1
  if [ "${FP_CLEAN_DOWN:-0}" = "1" ]; then
    info "docker compose down (FP_CLEAN_DOWN=1)"
    docker compose down --remove-orphans >> "$FP_LOG_START" 2>&1 || true
    fp_log start "docker compose down exécuté"
  else
    info "docker compose down sauté (FP_CLEAN_DOWN=0) — préserve l'état"
  fi

  # Tuer les containers en état "Restarting" ou "Created" qui bloquent les ports
  local stuck
  stuck=$(_fp_docker ps -a --filter "name=forensic" --filter "status=restarting" --format '{{.Names}}' 2>/dev/null || true)
  if [ -n "$stuck" ]; then
    warn "Containers en restart-loop: $stuck — kill"
    while IFS= read -r c; do
      [ -z "$c" ] && continue
      _fp_docker kill "$c" >/dev/null 2>&1 || true
      fp_log start "kill stuck container: $c"
    done <<< "$stuck"
  fi

  fp_log start "=== cleanup_processes end ==="
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

cleanup_ports() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "PHASE 2/6 — Vérification ports critiques FP"
  fp_log start "=== cleanup_ports start ==="

  # Ports FP critiques + plage portails
  local ports=(9200 5601 3000 3001 3002 5432 6379 9042 15672 5000 5044 5045 5140 8080 8090 9000 9001 9002 9003 9700)

  local occupied=()
  for p in "${ports[@]}"; do
    if _fp_port_owned_by_fp_container "$p"; then
      continue
    fi
    if _fp_port_in_use "$p"; then
      occupied+=("$p")
    fi
  done

  if [ "${#occupied[@]}" -eq 0 ]; then
    ok "Ports critiques libres ou détenus par containers FP"
    fp_log start "ports OK"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 0
  fi

  warn "Ports occupés par des processus non-FP: ${occupied[*]}"
  fp_log start "ports occupés: ${occupied[*]}"

  if [ "${FP_KILL_PORTS:-0}" != "1" ]; then
    warn "Pour libérer auto : FP_KILL_PORTS=1 ./forensic.sh start"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 0
  fi

  for p in "${occupied[@]}"; do
    local pids
    pids=$(lsof -ti ":${p}" -sTCP:LISTEN 2>/dev/null || true)
    if [ -z "$pids" ] && command -v fuser >/dev/null 2>&1; then
      pids=$(fuser "${p}/tcp" 2>/dev/null || true)
    fi
    if [ -n "$pids" ]; then
      warn "Kill PID(s) $pids sur port $p"
      # shellcheck disable=SC2086
      kill -TERM $pids 2>/dev/null || _fp_sudo kill -TERM $pids 2>/dev/null || true
      sleep 1
      # shellcheck disable=SC2086
      kill -9 $pids 2>/dev/null || _fp_sudo kill -9 $pids 2>/dev/null || true
      fp_log start "killed PID(s) $pids on port $p"
    fi
  done
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

_fp_port_in_use() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$"
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -i ":${p}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | grep -qE "[:.]${p} "
    return $?
  fi
  return 1
}

_fp_port_owned_by_fp_container() {
  local p="$1"
  # Cherche le port simple (:p->) ou dans une plage (:a-b->) où a <= p <= b
  local ports
  ports=$(docker ps --filter "name=forensic" --format '{{.Ports}}' 2>/dev/null) || return 1
  [ -z "$ports" ] && return 1
  # Match direct
  echo "$ports" | grep -qE "[:.]${p}->|^${p}->| ${p}/tcp" && return 0
  # Match plage (ex: 5044-5046->)
  local hit
  hit=$(echo "$ports" | grep -oE '[0-9]+-[0-9]+->' | sed 's/->$//' || true)
  if [ -n "$hit" ]; then
    local range a b
    while IFS= read -r range; do
      a="${range%-*}"
      b="${range#*-}"
      if [ "$p" -ge "$a" ] 2>/dev/null && [ "$p" -le "$b" ] 2>/dev/null; then
        return 0
      fi
    done <<< "$hit"
  fi
  return 1
}

# Wrapper qui appelle aussi cleanup_network existant si défini ailleurs.
fp_cleanup_all() {
  cleanup_processes
  cleanup_ports
  if command -v cleanup_network >/dev/null 2>&1; then
    cleanup_network 2>&1 | tee -a "$FP_LOG_NETWORK" >/dev/null
  fi
}

# ──────────────────────────────────────────────────────────────
#  PHASE 2bis — RÉPARATION RÉSEAU DOCKER FP (Address already in use)
# ──────────────────────────────────────────────────────────────
# Objectif :
#   - garantir que `fp-final2_forensic-net` existe avec le bon subnet
#     AVANT `docker compose up`, sans collision avec d'autres réseaux.
#   - le subnet par défaut est 172.25.0.0/16 (déclaré dans docker-compose.yml,
#     38+ containers en IP statique). On essaie d'abord de le libérer.
#   - fallback automatique : si 172.25.0.0/16 reste indisponible,
#     migration vers 172.26 / 172.27 / 172.28 avec patch sed du
#     docker-compose.yml (backup .bak.<ts> + rollback documenté).
# Variables :
#   FP_NET_NAME              (def: fp-final2_forensic-net)
#   FP_NET_DEFAULT_SUBNET    (def: 172.25.0.0/16)
#   FP_NET_FALLBACKS         (def: "172.26.0.0/16 172.27.0.0/16 172.28.0.0/16")
#   FP_NET_FORCE_MIGRATE=1   désactive le maintien sur 172.25
#   FP_NET_NO_PATCH=1        interdit la modification du docker-compose.yml

FP_NET_NAME="${FP_NET_NAME:-}"
FP_NET_LOGICAL_NAME="${FP_NET_LOGICAL_NAME:-forensic-net}"

_fp_detect_compose_project() {
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    echo "$COMPOSE_PROJECT_NAME"
  else
    basename "${DIR:-.}"
  fi
}

_fp_init_net_names() {
  local proj
  proj="${FP_COMPOSE_PROJECT:-$(_fp_detect_compose_project)}"
  FP_COMPOSE_PROJECT="$proj"
  if [ -z "$FP_NET_NAME" ]; then
    FP_NET_NAME="${proj}_${FP_NET_LOGICAL_NAME}"
  fi
}
FP_NET_DEFAULT_SUBNET="${FP_NET_DEFAULT_SUBNET:-172.25.0.0/16}"
FP_NET_FALLBACKS="${FP_NET_FALLBACKS:-172.26.0.0/16 172.27.0.0/16 172.28.0.0/16}"

_fp_net_log() { fp_log network "$*"; }

# Renvoie le subnet déclaré dans docker-compose.yml pour le réseau forensic-net
_fp_net_compose_subnet() {
  local f="$DIR/docker-compose.yml"
  [ -f "$f" ] || { echo ""; return 1; }
  # Extraction robuste : extrait directement l'IP/mask par regex,
  # peu importe la décoration YAML autour (- subnet: "x.y.z.w/n" → x.y.z.w/n)
  awk '
    /^networks:/                  { in_nets=1; next }
    in_nets && /^[^ ]/            { in_nets=0 }
    in_nets && /^  forensic-net:/ { in_fn=1; next }
    in_fn && /^  [a-zA-Z]/        { in_fn=0 }
    in_fn && /subnet:/ {
      if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/)) {
        print substr($0, RSTART, RLENGTH); exit
      }
    }
  ' "$f"
}

# Inspecte le subnet d'un réseau Docker (vide si réseau absent)
_fp_net_get_subnet() {
  local net="$1"
  _fp_docker network inspect "$net" \
    --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true
}

# Liste les réseaux Docker (autres que ceux passés en argument) qui occupent
# un subnet donné. Affiche "<name>|<containers_count>" par ligne.
_fp_net_holders_of_subnet() {
  local subnet="$1" exclude="${2:-}"
  local names
  names=$(_fp_docker network ls --format '{{.Name}}' 2>/dev/null) || return 0
  local n sn cnt
  while IFS= read -r n; do
    [ -z "$n" ] && continue
    [ "$n" = "$exclude" ] && continue
    sn=$(_fp_net_get_subnet "$n")
    if [ "$sn" = "$subnet" ]; then
      cnt=$(_fp_docker network inspect "$n" \
        --format '{{len .Containers}}' 2>/dev/null || echo 0)
      echo "$n|$cnt"
    fi
  done <<< "$names"
}

# Vérifie qu'un subnet est disponible (= aucun autre réseau Docker ne l'utilise).
# Si occupé par un réseau VIDE et hors-FP → on essaie de le supprimer.
# Retour : 0 = disponible / 1 = occupé (réseau non vidable).
_fp_net_subnet_free() {
  local subnet="$1" exclude="${2:-}"
  local holders
  holders=$(_fp_net_holders_of_subnet "$subnet" "$exclude")
  if [ -z "$holders" ]; then
    return 0
  fi
  local line name cnt
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    name="${line%|*}"
    cnt="${line#*|}"
    if [ "$cnt" = "0" ]; then
      _fp_net_log "subnet $subnet occupé par réseau vide '$name' → suppression"
      if _fp_docker network rm "$name" >/dev/null 2>&1; then
        info "Réseau orphelin '$name' supprimé (subnet $subnet libéré)" >&2
      else
        warn "Impossible de supprimer '$name' (subnet $subnet)" >&2
        _fp_net_log "rm $name ÉCHEC"
        return 1
      fi
    else
      warn "Subnet $subnet occupé par '$name' ($cnt container(s) actifs)" >&2
      _fp_net_log "subnet $subnet bloqué par $name ($cnt containers)"
      return 1
    fi
  done <<< "$holders"
  return 0
}

# Patche docker-compose.yml : remplace 172.<old_a>.X.Y → 172.<new_a>.X.Y
# Ne touche pas aux autres champs. Backup .bak.<ts> conservé.
_fp_net_patch_compose() {
  local from_subnet="$1" to_subnet="$2"
  local f="$DIR/docker-compose.yml"
  [ -f "$f" ] || return 1
  if [ "${FP_NET_NO_PATCH:-0}" = "1" ]; then
    warn "FP_NET_NO_PATCH=1 — refus de patcher docker-compose.yml"
    return 1
  fi
  local from_oct to_oct
  from_oct=$(echo "$from_subnet" | awk -F. '{print $1"."$2}')
  to_oct=$(echo "$to_subnet" | awk -F. '{print $1"."$2}')
  if [ -z "$from_oct" ] || [ -z "$to_oct" ]; then
    return 1
  fi
  local ts bak
  ts=$(date +%Y%m%d_%H%M%S)
  bak="${f}.bak.netmig.${ts}"
  cp "$f" "$bak" || return 1
  _fp_net_log "patch compose : $from_oct.* → $to_oct.* (backup: $bak)"
  # Remplacement strict : seulement les occurrences du préfixe + un point (.)
  # → évite de toucher à d'autres IPs (10.x, 192.x, etc.)
  sed -i "s|\\b${from_oct}\\.|${to_oct}.|g" "$f"
  if grep -qE "\\b${to_oct}\\." "$f"; then
    ok "docker-compose.yml patché : $from_oct.* → $to_oct.*  (rollback: cp $bak $f)"
    return 0
  fi
  warn "Patch sed inopérant — restauration"
  cp "$bak" "$f" 2>/dev/null || true
  return 1
}

# Trouve le premier subnet de la liste FP_NET_FALLBACKS qui est libre.
_fp_net_pick_fallback() {
  local exclude="${1:-}"
  local s
  for s in $FP_NET_FALLBACKS; do
    if _fp_net_subnet_free "$s" "$exclude"; then
      echo "$s"
      return 0
    fi
  done
  return 1
}

# Fonction principale demandée par le brief
fp_network_repair() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e

  step "PHASE 2bis — Réparation réseau Docker FP ($FP_NET_NAME)"
  fp_log_init
  _fp_init_net_names
  _fp_net_log "=== fp_network_repair start (project=$FP_COMPOSE_PROJECT net=$FP_NET_NAME) ==="

  if ! command -v docker >/dev/null 2>&1; then
    err "docker introuvable — impossible de réparer le réseau"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 1
  fi

  # Docker DOIT être accessible avant toute opération réseau
  if ! fp_ensure_docker; then
    err "Docker inaccessible — réparation réseau impossible (pas de migration subnet)"
    _fp_net_log "ÉCHEC : docker inaccessible"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 1
  fi
  fp_bind_compose_cmds 2>/dev/null || true

  # 1) Subnet déclaré dans docker-compose.yml (source de vérité)
  local compose_subnet target_subnet existing_subnet
  compose_subnet=$(_fp_net_compose_subnet)
  if [ -n "$compose_subnet" ]; then
    info "Subnet docker-compose.yml : $compose_subnet"
    _fp_net_log "compose subnet = $compose_subnet"
    target_subnet="$compose_subnet"
  else
    warn "Subnet absent du compose — fallback à FP_NET_DEFAULT_SUBNET=$FP_NET_DEFAULT_SUBNET"
    target_subnet="$FP_NET_DEFAULT_SUBNET"
  fi

  # 2) Inspecter le réseau existant
  existing_subnet=$(_fp_net_get_subnet "$FP_NET_NAME")
  local existing_label=""
  local expected_label="${FP_NET_LOGICAL_NAME:-forensic-net}"
  if [ -n "$existing_subnet" ]; then
    existing_label=$(_fp_net_get_compose_label "$FP_NET_NAME")
    info "Réseau '$FP_NET_NAME' présent — subnet : $existing_subnet · label : '${existing_label:-<absent>}'"
    _fp_net_log "réseau existant subnet=$existing_subnet label='${existing_label}'"
    # Détection du label Compose incorrect ou absent → recréation forcée
    if [ "$existing_label" != "$expected_label" ]; then
      warn "Label Compose incorrect ou absent (attendu : '$expected_label')"
      warn "  → cause typique de l'erreur : 'network found but has incorrect label com.docker.compose.network'"
      _fp_net_log "label INCORRECT (got='$existing_label' want='$expected_label') → suppression+recréation"
      _fp_net_force_remove "$FP_NET_NAME"
      existing_subnet=""
    fi
  else
    info "Réseau '$FP_NET_NAME' absent — sera créé"
    _fp_net_log "réseau absent"
  fi

  # 3) Si forçage migration → on saute direct à la phase fallback
  if [ "${FP_NET_FORCE_MIGRATE:-0}" = "1" ]; then
    warn "FP_NET_FORCE_MIGRATE=1 — migration forcée vers fallback subnet"
    _fp_net_force_remove "$FP_NET_NAME"
    local _fb_rc=0
    _fp_net_try_fallback "$target_subnet" || _fb_rc=$?
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return "$_fb_rc"
  fi

  # 4) Vérifier si le subnet cible est libre (hors réseau FP existant)
  if ! _fp_net_subnet_free "$target_subnet" "$FP_NET_NAME"; then
    warn "Subnet $target_subnet bloqué par un autre réseau Docker"
    _fp_net_log "conflit subnet $target_subnet — tentative fallback"
    _fp_net_force_remove "$FP_NET_NAME"
    local _fb_rc=0
    _fp_net_try_fallback "$target_subnet" || _fb_rc=$?
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return "$_fb_rc"
  fi

  # 5) Le subnet cible est libre. Si le réseau existe avec un mauvais subnet → recréer.
  if [ -n "$existing_subnet" ] && [ "$existing_subnet" != "$target_subnet" ]; then
    warn "Réseau '$FP_NET_NAME' a un subnet incompatible ($existing_subnet ≠ $target_subnet) — recréation"
    _fp_net_log "subnet incohérent → suppression"
    _fp_net_force_remove "$FP_NET_NAME"
    existing_subnet=""
  fi

  # 6) Recréer si nécessaire
  if [ -z "$existing_subnet" ]; then
    local create_rc=0
    _fp_net_create "$FP_NET_NAME" "$target_subnet" || create_rc=$?
    if [ "$create_rc" -eq 0 ]; then
      ok "Réseau '$FP_NET_NAME' créé ($target_subnet)"
      _fp_net_log "réseau créé subnet=$target_subnet"
    elif [ "$create_rc" -eq 2 ]; then
      err "Docker inaccessible lors de la création réseau — pas de fallback subnet"
      _fp_net_log "create abort: docker down (rc=2)"
      if [ "$_had_e" -eq 1 ]; then set -e; fi
      return 1
    elif [ "$create_rc" -eq 3 ]; then
      warn "Subnet $target_subnet en conflit — fallback automatique"
      _fp_net_log "subnet conflict → fallback"
      _fp_net_force_remove "$FP_NET_NAME"
      _fp_net_try_fallback "$target_subnet" || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
    else
      warn "Création directe échouée (rc=$create_rc) — 2e tentative"
      _fp_net_force_remove "$FP_NET_NAME"
      create_rc=0
      _fp_net_create "$FP_NET_NAME" "$target_subnet" || create_rc=$?
      if [ "$create_rc" -eq 0 ]; then
        ok "Réseau '$FP_NET_NAME' créé ($target_subnet)"
        _fp_net_log "réseau créé (2e tentative) subnet=$target_subnet"
      elif [ "$create_rc" -eq 2 ]; then
        err "Docker inaccessible — pas de fallback subnet"
        if [ "$_had_e" -eq 1 ]; then set -e; fi
        return 1
      else
        warn "2e tentative échouée — essai création via docker compose"
        if _fp_net_create_via_compose; then
          ok "Réseau '$FP_NET_NAME' créé via docker compose"
          _fp_net_log "réseau créé via compose"
        else
          warn "Compose fallback échoué — fallback subnet alternatif"
          _fp_net_try_fallback "$target_subnet" || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
        fi
      fi
    fi
  else
    ok "Réseau '$FP_NET_NAME' OK ($existing_subnet)"
    _fp_net_log "réseau OK (idempotent)"
  fi

  # 7) Test bloquant final : le réseau DOIT exister avec le bon subnet ET le bon label
  local final_subnet final_label
  final_subnet=$(_fp_net_get_subnet "$FP_NET_NAME")
  final_label=$(_fp_net_get_compose_label "$FP_NET_NAME")
  if [ -z "$final_subnet" ]; then
    err "Réseau '$FP_NET_NAME' introuvable après réparation"
    _fp_net_log "ÉCHEC FINAL : réseau introuvable"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 1
  fi
  if [ "$final_label" != "$expected_label" ]; then
    err "Réseau présent mais label Compose toujours incorrect ('$final_label' ≠ '$expected_label')"
    _fp_net_log "ÉCHEC FINAL : label incorrect"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 1
  fi
  ok "Réseau prêt : $FP_NET_NAME ($final_subnet · label='$final_label')"

  # Purge des containers qui pointent encore vers l'ancien NetworkID (évite
  # l'erreur "network <id> not found" au prochain compose up).
  _fp_net_purge_stale_containers "$FP_NET_NAME"

  _fp_net_log "=== fp_network_repair end : $FP_NET_NAME ($final_subnet, label=$final_label) ==="

  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# Supprime un réseau Docker proprement :
#  - déconnecte les containers running (préserve leur état)
#  - supprime (`docker rm -f`) les containers en état Created/Exited attachés au
#    réseau, car ils gardent une référence à l'ancien NetworkID. Sans ça,
#    docker compose lèvera : "failed to set up container networking: network
#    <old_id> not found" au prochain `up`. Les containers seront recréés
#    proprement par `docker compose up`.
_fp_net_force_remove() {
  local net="$1"
  _fp_docker network inspect "$net" >/dev/null 2>&1 || return 0
  local net_id
  net_id=$(_fp_docker network inspect "$net" --format '{{.Id}}' 2>/dev/null || true)
  _fp_net_log "force_remove $net (id=$net_id)"

  local running_cids stopped_cids
  running_cids=$(_fp_docker network inspect "$net" \
    --format '{{range $k,$v := .Containers}}{{$k}} {{end}}' 2>/dev/null || true)
  stopped_cids=$(_fp_docker ps -a --filter "network=${net}" \
    --filter "status=exited" --filter "status=created" \
    --format '{{.ID}}' 2>/dev/null || true)

  if [ -n "$running_cids" ]; then
    local c
    for c in $running_cids; do
      _fp_docker network disconnect -f "$net" "$c" >/dev/null 2>&1 || true
      _fp_net_log "disconnect $c de $net"
    done
  fi

  if [ -n "$stopped_cids" ]; then
    local c name
    for c in $stopped_cids; do
      name=$(_fp_docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's|^/||')
      case "$name" in
        forensic-*)
          _fp_docker rm -f "$c" >/dev/null 2>&1 && _fp_net_log "rm stopped container $name ($c)"
          ;;
      esac
    done
  fi

  if _fp_docker network rm "$net" >/dev/null 2>&1; then
    info "Réseau '$net' supprimé"
    _fp_net_log "rm $net OK"
    return 0
  fi
  warn "Échec suppression '$net' — tentative prune"
  _fp_docker network prune -f >/dev/null 2>&1 || true
  if _fp_docker network inspect "$net" >/dev/null 2>&1; then
    _fp_net_log "rm $net ÉCHEC après prune"
    return 1
  fi
  _fp_net_log "rm $net OK (via prune)"
  return 0
}

# Nettoyage défensif des containers FP qui référencent un réseau Docker
# inexistant (cas après suppression du réseau, ou crash docker). Appelable
# avant tout `docker compose up`. Touche uniquement les containers en état
# Created/Exited, jamais les containers running.
_fp_net_purge_stale_containers() {
  local net_name="${1:-$FP_NET_NAME}"
  # ID du réseau courant (si présent)
  local current_id
  current_id=$(_fp_docker network inspect "$net_name" --format '{{.Id}}' 2>/dev/null || true)

  local cs
  cs=$(_fp_docker ps -a --filter "name=forensic" --filter "status=exited" \
       --format '{{.ID}}' 2>/dev/null || true)
  cs="$cs $(_fp_docker ps -a --filter "name=forensic" --filter "status=created" \
       --format '{{.ID}}' 2>/dev/null || true)"

  local c name nets stale=0
  for c in $cs; do
    [ -z "$c" ] && continue
    name=$(_fp_docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's|^/||')
    [ -z "$name" ] && continue
    nets=$(_fp_docker inspect --format \
      '{{range $k,$v := .NetworkSettings.Networks}}{{$v.NetworkID}}|{{$k}} {{end}}' \
      "$c" 2>/dev/null || true)
    local entry net_id net_alias
    for entry in $nets; do
      [ -z "$entry" ] && continue
      net_id="${entry%%|*}"
      net_alias="${entry##*|}"
      if [ "$net_alias" = "$net_name" ] && [ -n "$current_id" ] && [ "$net_id" != "$current_id" ]; then
        info "Container stale détecté : $name (référence ancien NetworkID)"
        _fp_docker rm -f "$c" >/dev/null 2>&1 && \
          _fp_net_log "purge stale $name (old_id=$net_id != current=$current_id)"
        stale=$((stale+1))
      fi
    done
  done
  if [ "$stale" -gt 0 ]; then
    info "$stale container(s) stale purgé(s) — seront recréés par compose"
  fi
  return 0
}

# Crée un réseau Docker avec un subnet précis ET les labels Compose corrects.
# Sans ces labels, docker compose émet :
#   "network <name> was found but has incorrect label com.docker.compose.network"
# et refuse de l'utiliser.
# Fallback : laisser Compose créer le réseau (labels natifs, sans warning)
_fp_net_create_via_compose() {
  _fp_net_log "create via compose up --no-start postgres"
  _fp_compose up --no-start --no-recreate postgres >> "$FP_LOG_NETWORK" 2>&1
  local sn
  sn=$(_fp_net_get_subnet "$FP_NET_NAME")
  [ -n "$sn" ]
}

# Retour : 0=OK  2=docker inaccessible  3=conflit subnet  1=autre erreur
_fp_net_create() {
  local net="$1" subnet="$2"
  local compose_logical="${FP_NET_LOGICAL_NAME:-forensic-net}"
  local project="${FP_COMPOSE_PROJECT:-fp-final2}"
  local err_out rc=0 ver

  ver=$(_fp_compose version --short 2>/dev/null || echo unknown)

  rc=0
  err_out=$(_fp_docker network create \
      --driver bridge \
      --subnet "$subnet" \
      --label "com.docker.compose.network=${compose_logical}" \
      --label "com.docker.compose.project=${project}" \
      --label "com.docker.compose.version=${ver}" \
      "$net" 2>&1) || rc=$?
  if [ "${rc:-0}" -eq 0 ]; then
    return 0
  fi
  _fp_net_log "create(v1) rc=${rc}: $err_out"

  rc=0
  err_out=$(_fp_docker network create \
    --driver bridge \
    --subnet "$subnet" \
    --label "com.docker.compose.network=${compose_logical}" \
    --label "com.docker.compose.project=${project}" \
    "$net" 2>&1) || rc=$?
  if [ "${rc:-0}" -eq 0 ]; then
    return 0
  fi
  _fp_net_log "create(v2) rc=${rc}: $err_out"

  if echo "$err_out" | grep -qiE "permission denied|cannot connect|Is the docker daemon|connection refused|Got permission denied"; then
    return 2
  fi
  if echo "$err_out" | grep -qiE "already exists| overlaps |Pool overlaps|cannot allocate|address already in use"; then
    return 3
  fi
  return 1
}

_fp_net_get_compose_label() {
  local net="$1"
  _fp_docker network inspect "$net" \
    --format '{{ index .Labels "com.docker.compose.network" }}' 2>/dev/null || true
}

# Restaure docker-compose.yml depuis le backup .bak.netmig le plus récent
_fp_net_rollback_compose() {
  local latest
  latest=$(ls -t "$DIR"/docker-compose.yml.bak.netmig.* 2>/dev/null | head -1)
  if [ -n "$latest" ] && [ -f "$latest" ]; then
    cp "$latest" "$DIR/docker-compose.yml"
    warn "Rollback docker-compose.yml ← $latest"
    _fp_net_log "rollback compose from $latest"
    return 0
  fi
  return 1
}

# Fallback : tester 172.26/27/28 et patcher le compose si nécessaire
_fp_net_try_fallback() {
  local from_subnet="$1"
  local pick patched=0
  pick=$(_fp_net_pick_fallback "$FP_NET_NAME")
  if [ -z "$pick" ]; then
    err "Aucun subnet fallback disponible parmi : $FP_NET_FALLBACKS"
    _fp_net_log "aucun fallback disponible"
    return 1
  fi
  warn "Migration subnet : $from_subnet → $pick"
  _fp_net_log "migration $from_subnet → $pick"
  if [ "$from_subnet" != "$pick" ]; then
    if ! _fp_net_patch_compose "$from_subnet" "$pick"; then
      err "Patch docker-compose.yml impossible — abandon migration"
      _fp_net_log "patch compose ÉCHEC"
      return 1
    fi
    patched=1
  fi
  _fp_net_subnet_free "$pick" "$FP_NET_NAME" || true
  local create_rc=0
  _fp_net_create "$FP_NET_NAME" "$pick" || create_rc=$?
  if [ "$create_rc" -eq 0 ]; then
    ok "Réseau recréé avec subnet fallback : $pick"
    _fp_net_log "réseau créé ($pick)"
    return 0
  fi
  err "Création du réseau avec subnet $pick ÉCHEC (rc=$create_rc)"
  _fp_net_log "création réseau ($pick) ÉCHEC rc=$create_rc"
  if [ "$patched" -eq 1 ]; then
    _fp_net_rollback_compose || warn "Rollback compose manuel : cp docker-compose.yml.bak.netmig.* docker-compose.yml"
  fi
  return 1
}

# ──────────────────────────────────────────────────────────────
#  PHASE 4 — STATUS GLOBAL ENRICHI
# ──────────────────────────────────────────────────────────────
status_full() {
  # Neutralise set -e/pipefail localement pour éviter de couper l'affichage
  # sur le moindre curl/docker en échec.
  local _had_e=0 _had_p=0
  case $- in *e*) _had_e=1;; esac
  set +e
  if shopt -qo pipefail 2>/dev/null; then
    _had_p=1
    set +o pipefail
  fi
  step "STATUS GLOBAL — Plateforme Forensic"
  fp_log_init

  echo ""
  echo -e "${CYAN}── Containers Docker (filter: forensic-*) ──${NC}"
  if command -v docker >/dev/null 2>&1; then
    local total up dps
    total=$(docker ps -a --filter "name=forensic" -q 2>/dev/null | wc -l | tr -d ' ')
    up=$(docker ps --filter "name=forensic" --filter "status=running" -q 2>/dev/null | wc -l | tr -d ' ')
    echo "  Total: $total · Running: $up"
    # Capture en variable pour éviter SIGPIPE sous set -o pipefail
    dps=$(docker ps -a --filter "name=forensic" \
      --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true)
    if [ -n "$dps" ]; then
      echo "$dps" | head -n 60 | sed 's/^/  /' || true
    fi
  else
    warn "docker absent"
  fi

  echo ""
  echo -e "${CYAN}── Endpoints critiques ──${NC}"
  _fp_status_endpoint "OpenSearch cluster"       "http://localhost:9200/_cluster/health"
  _fp_status_endpoint "OpenSearch Dashboards"    "http://localhost:5601/dashboards/api/status"
  _fp_status_endpoint "Grafana"                  "http://localhost:3001/api/health"
  _fp_status_endpoint "Timesketch /login"        "http://localhost:5000/login"
  _fp_status_endpoint "Portail CERT direct"      "http://localhost:3000/api/health"
  _fp_status_endpoint "Portail IT direct"        "http://localhost:3002/api/health"
  _fp_status_endpoint "Nginx HTTPS"              "https://localhost/" "k"

  echo ""
  echo -e "${CYAN}── Cluster OpenSearch ──${NC}"
  local osh=""
  osh=$(curl -sf --max-time 5 "http://localhost:9200/_cluster/health" 2>/dev/null || true)
  if [ -n "$osh" ]; then
    local stat docs nodes
    stat=$(echo "$osh" | grep -oE '"status":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
    nodes=$(echo "$osh" | grep -oE '"number_of_nodes":[0-9]*' | head -1 | sed 's/.*:\([0-9]*\)/\1/')
    docs=$(echo "$osh" | grep -oE '"active_shards":[0-9]*' | head -1 | sed 's/.*:\([0-9]*\)/\1/')
    case "$stat" in
      green)  echo -e "  ${GREEN}● $stat${NC} · nodes=$nodes shards=$docs" ;;
      yellow) echo -e "  ${YELLOW}● $stat${NC} · nodes=$nodes shards=$docs" ;;
      *)      echo -e "  ${RED}● $stat${NC} · nodes=$nodes shards=$docs" ;;
    esac
  else
    echo -e "  ${RED}● injoignable${NC}"
  fi

  echo ""
  echo -e "${CYAN}── Réseaux Docker FP ──${NC}"
  if command -v docker >/dev/null 2>&1; then
    local nls
    nls=$(docker network ls --filter "name=forensic" \
      --format 'table {{.Name}}\t{{.Driver}}\t{{.Scope}}' 2>/dev/null || true)
    [ -n "$nls" ] && echo "$nls" | sed 's/^/  /'
    local nets
    nets=$(docker network ls --filter "name=forensic" --format '{{.Name}}' 2>/dev/null)
    if [ -n "$nets" ]; then
      while IFS= read -r net; do
        [ -z "$net" ] && continue
        local sn
        sn=$(docker network inspect "$net" \
          --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)
        [ -n "$sn" ] && echo "  └─ $net : $sn"
      done <<< "$nets"
    fi
  fi

  echo ""
  echo -e "${CYAN}── Ports critiques (LISTEN) ──${NC}"
  local p
  for p in 9200 5601 3000 3001 3002 5000 5432 6379 9042 15672 8080 8090 9000 9001 9002 9003 443 80; do
    if _fp_port_in_use "$p"; then
      local owner
      if _fp_port_owned_by_fp_container "$p"; then
        owner="forensic-*"
        echo -e "  ${GREEN}✓${NC} ${p} (${owner})"
      else
        owner="autre processus"
        echo -e "  ${YELLOW}?${NC} ${p} (${owner})"
      fi
    fi
  done

  echo ""
  echo -e "${CYAN}── Logs récents ──${NC}"
  for log in "$FP_LOG_START" "$FP_LOG_INSTALL" "$FP_LOG_NETWORK"; do
    if [ -s "$log" ]; then
      echo "  $log : $(wc -l < "$log" 2>/dev/null | tr -d ' ') lignes"
    fi
  done
  echo ""
  # Rétablir les flags shell tels qu'ils étaient
  [ "$_had_p" -eq 1 ] && set -o pipefail
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

_fp_status_endpoint() {
  local name="$1" url="$2" insecure="${3:-}"
  # On retire -f pour capturer proprement le %{http_code} même sur 4xx/5xx
  local opts="-s -o /dev/null --max-time 6"
  [ "$insecure" = "k" ] && opts="-sk -o /dev/null --max-time 6"
  local code
  # set -e safe : on neutralise l'exit de curl (timeout / connect refused)
  # shellcheck disable=SC2086
  code=$(curl $opts -w '%{http_code}' "$url" 2>/dev/null || echo "")
  [ -z "$code" ] && code="000"
  if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ] || [ "$code" = "307" ] || [ "$code" = "308" ]; then
    echo -e "  ${GREEN}✓${NC} $name  ($code)"
  elif [ "$code" = "401" ] || [ "$code" = "403" ]; then
    echo -e "  ${YELLOW}~${NC} $name  ($code · auth requise mais service UP)"
  else
    echo -e "  ${RED}✗${NC} $name  ($code · $url)"
  fi
}

# ──────────────────────────────────────────────────────────────
#  PHASE 6 — TESTS AUTOMATIQUES (après start)
# ──────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────
#  PHASE 5bis — DIAGNOSTIC LOGS CONTAINERS
# ──────────────────────────────────────────────────────────────
# Scanne les logs des containers critiques et détecte les patterns d'erreur
# connus pour proposer une action corrective dans la boucle auto-repair.
# Affiche un rapport synthétique et alimente $FP_DIAG_HINT (variable globale)
# avec un mot-clé indiquant la nature du problème détecté :
#   - "network_label" → label Compose incorrect / Address already in use
#   - "network_subnet" → conflit subnet
#   - "opensearch_red" → cluster OS rouge ou max_map_count
#   - "container_restart" → boucle de redémarrage
#   - "port_conflict" → port déjà bind
#   - ""                → aucun problème spécifique détecté
FP_DIAG_HINT=""

fp_diagnose_logs() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "DIAGNOSTIC — Scan logs containers critiques"
  fp_log_init
  fp_log start "=== fp_diagnose_logs start ==="
  FP_DIAG_HINT=""

  if ! command -v docker >/dev/null 2>&1; then
    warn "docker absent — diagnostic impossible"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 0
  fi

  # Patterns critiques par container
  local containers=(
    "forensic-opensearch-1"
    "forensic-opensearch-2"
    "forensic-opensearch-dashboards"
    "forensic-timesketch-web"
    "forensic-grafana"
    "forensic-cert-portal"
    "forensic-postgres"
    "forensic-rabbitmq"
  )

  local c logs hits=0
  for c in "${containers[@]}"; do
    docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$c" || continue
    logs=$(docker logs --tail 100 "$c" 2>&1 || true)

    # 1) Erreurs réseau (label, address in use)
    if echo "$logs" | grep -qiE "incorrect label|com\.docker\.compose\.network|network .* was found but"; then
      warn "[$c] erreur 'incorrect label' détectée"
      fp_log start "diag: $c → network_label"
      FP_DIAG_HINT="network_label"
      hits=$((hits+1))
    fi
    if echo "$logs" | grep -qiE "address already in use|bind: address already"; then
      warn "[$c] 'Address already in use' détecté"
      fp_log start "diag: $c → port_or_network conflict"
      [ -z "$FP_DIAG_HINT" ] && FP_DIAG_HINT="network_subnet"
      hits=$((hits+1))
    fi
    # 2) OpenSearch RED + max_map_count
    if [ "$c" = "forensic-opensearch-1" ] || [ "$c" = "forensic-opensearch-2" ]; then
      if echo "$logs" | grep -qiE "max virtual memory|max_map_count.*too low|bootstrap checks failed"; then
        warn "[$c] vm.max_map_count insuffisant"
        fp_log start "diag: $c → max_map_count"
        FP_DIAG_HINT="opensearch_sysctl"
        hits=$((hits+1))
      fi
      if echo "$logs" | grep -qiE "Could not assign|CodecCorruption|fatal error in thread"; then
        warn "[$c] erreur OpenSearch fatale détectée"
        fp_log start "diag: $c → opensearch_red"
        FP_DIAG_HINT="opensearch_red"
        hits=$((hits+1))
      fi
    fi
  done

  # 3) Containers en restart-loop
  local stuck
  stuck=$(docker ps -a --filter "name=forensic" --filter "status=restarting" \
    --format '{{.Names}}' 2>/dev/null || true)
  if [ -n "$stuck" ]; then
    warn "Containers en restart-loop détectés :"
    while IFS= read -r c; do
      [ -z "$c" ] && continue
      echo "  • $c"
      fp_log start "diag: restart-loop $c"
    done <<< "$stuck"
    [ -z "$FP_DIAG_HINT" ] && FP_DIAG_HINT="container_restart"
    hits=$((hits+1))
  fi

  if [ "$hits" -eq 0 ]; then
    ok "Aucun pattern d'erreur connu détecté dans les logs critiques"
    fp_log start "diag: clean"
  else
    info "Diagnostic : $hits indice(s) — hint='$FP_DIAG_HINT'"
  fi
  fp_log start "=== fp_diagnose_logs end (hits=$hits hint='$FP_DIAG_HINT') ==="

  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# ──────────────────────────────────────────────────────────────
#  PHASE 6bis — BOUCLE AUTO-RÉPARATION (3 tentatives max)
# ──────────────────────────────────────────────────────────────
# Appelée en fin de start() pour valider l'état final et tenter une
# auto-réparation si des KO sont détectés. Limitée à FP_RETRY_MAX=3 itérations
# (configurable) pour éviter les boucles infinies.
#
# Variables :
#   FP_RETRY_MAX     (def: 3)
#   FP_RETRY_SLEEP   (def: 15s entre 2 tentatives)
#
# Stratégie : pour chaque hint détecté, applique le correctif minimal
# adapté avant de relancer fp_start_tests :
#   network_label / network_subnet → fp_network_repair + restart services
#   opensearch_sysctl              → ré-applique sysctl + restart opensearch
#   opensearch_red                 → restart opensearch + wait
#   container_restart              → cleanup_processes + compose up -d
#   port_conflict                  → cleanup_ports (FP_KILL_PORTS=1) + restart

fp_auto_repair_loop() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "AUTO-RÉPARATION — Boucle de validation (max ${FP_RETRY_MAX:-3} tentatives)"
  fp_log start "=== fp_auto_repair_loop start ==="

  local max="${FP_RETRY_MAX:-3}"
  local sleep_s="${FP_RETRY_SLEEP:-15}"
  local attempt=1
  local last_ok=0
  local last_fail=0

  while [ "$attempt" -le "$max" ]; do
    info "Tentative $attempt/$max — exécution des tests"
    fp_log start "auto_repair attempt=$attempt"

    # Exécute les tests synchrones
    if _fp_run_tests_silent; then
      ok "Validation OK à la tentative $attempt/$max"
      fp_log start "auto_repair attempt=$attempt → ALL OK"
      if [ "$_had_e" -eq 1 ]; then set -e; fi
      return 0
    fi

    # KO → diagnostic des logs
    warn "Échecs détectés — analyse des logs containers"
    fp_diagnose_logs

    if [ "$attempt" -ge "$max" ]; then
      err "Nombre max de tentatives atteint ($max)"
      _fp_print_final_diagnostic
      fp_log start "auto_repair ÉCHEC FINAL après $max tentatives"
      if [ "$_had_e" -eq 1 ]; then set -e; fi
      return 1
    fi

    if [ "$attempt" -ge 2 ] && command -v fp_finalize_platform_access >/dev/null 2>&1; then
      warn "Application correctif : alignement IP / MISP / HELK / VR / nginx"
      fp_finalize_platform_access || true
    fi

    # Application du correctif selon le hint
    case "$FP_DIAG_HINT" in
      network_label|network_subnet)
        warn "Application correctif : réparation réseau Docker"
        fp_log start "auto_repair: fp_network_repair"
        fp_network_repair || true
        # Restart des containers attachés au réseau
        info "Redémarrage des services impactés"
        docker compose up -d 2>&1 | tee -a "$FP_LOG_START" >/dev/null || true
        ;;
      opensearch_sysctl)
        warn "Application correctif : sysctl vm.max_map_count"
        sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || \
          _fp_sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || \
          warn "sysctl impossible sans sudo NOPASSWD"
        docker restart forensic-opensearch-1 forensic-opensearch-2 >/dev/null 2>&1 || true
        ;;
      opensearch_red)
        warn "Application correctif : redémarrage OpenSearch"
        docker restart forensic-opensearch-1 forensic-opensearch-2 >/dev/null 2>&1 || true
        ;;
      container_restart)
        warn "Application correctif : kill restart-loops + relance compose"
        cleanup_processes || true
        docker compose up -d 2>&1 | tee -a "$FP_LOG_START" >/dev/null || true
        ;;
      port_conflict)
        warn "Application correctif : libération ports (FP_KILL_PORTS=1)"
        FP_KILL_PORTS=1 cleanup_ports || true
        docker compose up -d 2>&1 | tee -a "$FP_LOG_START" >/dev/null || true
        ;;
      *)
        warn "Aucun hint actionnable — simple retry après ${sleep_s}s"
        ;;
    esac

    info "Attente ${sleep_s}s pour stabilisation"
    sleep "$sleep_s"
    attempt=$((attempt+1))
  done

  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 1
}

# Exécute les tests fp_start_tests en mode silencieux (capture stdout)
# et retourne 0 si TOUT est OK, sinon 1. Évite de polluer la sortie en cas
# de boucle.
_fp_run_tests_silent() {
  local out fails
  out=$(fp_start_tests 2>&1)
  echo "$out"
  fails=$(echo "$out" | grep -cE "→ [0-9]+ \(attendu" || true)
  if [ "$fails" -eq 0 ] && echo "$out" | grep -q "0 KO"; then
    return 0
  fi
  return 1
}

# Affiche un diagnostic final clair quand l'auto-repair a échoué
_fp_print_final_diagnostic() {
  echo ""
  echo -e "${RED}━━━ DIAGNOSTIC FINAL (auto-repair épuisé) ━━━${NC}"
  echo "  Containers en restart-loop :"
  docker ps -a --filter "name=forensic" --filter "status=restarting" \
    --format '    • {{.Names}}  ({{.Status}})' 2>/dev/null || true
  echo ""
  echo "  Containers exited récemment :"
  docker ps -a --filter "name=forensic" --filter "status=exited" \
    --format '    • {{.Names}}  ({{.Status}})' 2>/dev/null | head -10
  echo ""
  echo "  Logs disponibles :"
  echo "    tail -50 logs/forensic_start.log"
  echo "    tail -50 logs/forensic_network.log"
  echo "    tail -50 logs/forensic_install.log"
  echo "    docker logs forensic-opensearch-1 --tail 30"
  echo "    docker logs forensic-timesketch-web --tail 30"
  echo ""
}

fp_start_tests() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "PHASE 6/6 — Tests automatiques (santé + réseaux + ports)"
  fp_log start "=== fp_start_tests start ==="

  local ok_count=0 fail_count=0 vr_port
  vr_port=$(fp_vr_gui_port 2>/dev/null || echo "18000")
  # Format : "nom|url|codes_acceptés (csv)|opts"
  # codes_acceptés = liste de codes considérés OK (200, 30x redirects, 401/403
  # signifient "service UP mais auth requise" → considéré UP)
  local checks=(
    "OpenSearch cluster|http://localhost:9200/_cluster/health|200|"
    "OpenSearch Dashboards|http://localhost:5601/dashboards/api/status|200,302|"
    "Grafana|http://localhost:3001/api/health|200|"
    "Timesketch login|http://localhost:5000/login|200,301,302,308|"
    "Portail CERT|http://localhost:3000/api/health|200|"
    "Velociraptor direct|http://localhost:${vr_port}/velociraptor/|200,301,302,307,308,401|"
  )
  local entry
  for entry in "${checks[@]}"; do
    local name url expects insecure
    IFS='|' read -r name url expects insecure <<< "$entry"
    # On ne suit pas les redirects ici (-L) : on veut savoir quel code le
    # service répond directement, pour différencier "UP" vs "down/forwarded".
    local opts="-s --max-time 8"
    [ "$insecure" = "k" ] && opts="-sk --max-time 8"
    local code=""
    # shellcheck disable=SC2086
    code=$(curl $opts -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "")
    [ -z "$code" ] && code="000"
    # Match code dans la liste CSV
    if echo ",$expects," | grep -q ",$code,"; then
      ok "$name → $code"
      fp_log start "test $name OK ($code)"
      ok_count=$((ok_count+1))
    else
      warn "$name → $code (attendu ∈ {$expects})"
      fp_log start "test $name FAIL ($code, expected $expects)"
      fail_count=$((fail_count+1))
    fi
  done

  # Cluster OpenSearch = GREEN ou YELLOW (red = fail). On distingue "red"
  # de "injoignable" pour un diagnostic plus précis.
  local osh=""
  osh=$(curl -sf --max-time 5 "http://localhost:9200/_cluster/health" 2>/dev/null || true)
  if [ -z "$osh" ]; then
    warn "Cluster OpenSearch injoignable (curl échec)"
    fp_log start "cluster injoignable"
    fail_count=$((fail_count+1))
  elif echo "$osh" | grep -qE '"status":"(green|yellow)"'; then
    local st
    st=$(echo "$osh" | grep -oE '"status":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
    ok "Cluster OpenSearch healthy (status=$st)"
    fp_log start "cluster $st"
    ok_count=$((ok_count+1))
  else
    local st
    st=$(echo "$osh" | grep -oE '"status":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
    warn "Cluster OpenSearch status=$st (attendu green|yellow)"
    fp_log start "cluster $st (FAIL)"
    fail_count=$((fail_count+1))
  fi

  # Velociraptor via nginx HTTPS (détecte 502 si sidecar GUI absent)
  local vr_host vr_code
  vr_host=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "127.0.0.1")
  vr_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 12 \
    "https://${vr_host}/velociraptor/" 2>/dev/null || echo "000")
  if echo ",200,301,302,307,308,401," | grep -q ",${vr_code},"; then
    ok "Velociraptor nginx → $vr_code"
    fp_log start "test Velociraptor nginx OK ($vr_code)"
    ok_count=$((ok_count+1))
  else
    warn "Velociraptor nginx → $vr_code (attendu 200|30x|401 — 502 = sidecar absent)"
    fp_log start "test Velociraptor nginx FAIL ($vr_code)"
    fail_count=$((fail_count+1))
  fi

  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^velociraptor-server$'; then
    ok "velociraptor-server → running"
    ok_count=$((ok_count+1))
  else
    warn "velociraptor-server → ABSENT (cause 502 /velociraptor/)"
    fail_count=$((fail_count+1))
  fi

  local portal_user portal_pass portal_code portal_host
  portal_host=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "127.0.0.1")
  portal_user=$(grep -E '^PORTAL_ADMIN_USER=' "${DIR:-.}/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || echo "admin")
  portal_pass=$(grep -E '^CERT_PORTAL_SECRET=' "${DIR:-.}/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || echo "")
  portal_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 12 \
    -X POST "http://127.0.0.1:${FP_CERT_PORTAL_PORT:-3000}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${portal_user}\",\"password\":\"${portal_pass}\"}" 2>/dev/null || echo "000")
  if [ "$portal_code" = "200" ]; then
    ok "Portail CERT login → OK (${portal_user})"
    ok_count=$((ok_count+1))
  else
    warn "Portail CERT login → $portal_code (attendu 200 — voir ensure-portal-admin / .env)"
    fail_count=$((fail_count+1))
  fi

  echo ""
  info "Bilan tests: ${ok_count} OK · ${fail_count} KO"
  fp_log start "bilan tests: OK=$ok_count FAIL=$fail_count"

  if [ "$_had_e" -eq 1 ]; then set -e; fi
  [ "$fail_count" -eq 0 ]
}

# ──────────────────────────────────────────────────────────────
#  PHASE 0 — Bootstrap machine vierge (clone GitHub sans .env/certs)
# ──────────────────────────────────────────────────────────────
_fp_bootstrap_ensure_openssl() {
  if command -v openssl >/dev/null 2>&1; then
    ok "openssl: $(openssl version 2>/dev/null | awk '{print $1,$2}')"
    return 0
  fi
  warn "openssl absent — installation automatique..."
  fp_log install "openssl missing — apt install"
  if command -v apt-get >/dev/null 2>&1; then
    _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$FP_LOG_INSTALL" 2>&1 || true
    if _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y openssl >> "$FP_LOG_INSTALL" 2>&1; then
      ok "openssl installé"
      return 0
    fi
  elif command -v dnf >/dev/null 2>&1; then
    _fp_sudo dnf install -y openssl >> "$FP_LOG_INSTALL" 2>&1 && ok "openssl installé" && return 0
  fi
  err "openssl requis — installer manuellement (apt install openssl)"
  return 1
}

_fp_bootstrap_env_file() {
  local root="${DIR:-.}"
  if [ ! -f "$root/.env.example" ]; then
    err ".env.example absent — git pull depuis v2/main"
    return 1
  fi
  if ! grep -qE '^POSTGRES_PASSWORD=' "$root/.env.example" 2>/dev/null; then
    err ".env.example invalide (clés traduites ?) — git pull, ne pas traduire les noms de variables"
    return 1
  fi
  if [ ! -f "$root/.env" ]; then
    cp "$root/.env.example" "$root/.env"
    ok ".env créé depuis .env.example"
    fp_log install ".env created from .env.example"
  else
    ok ".env présent"
  fi
  if ! grep -qE '^POSTGRES_PASSWORD=' "$root/.env" 2>/dev/null \
    || ! grep -qE '^PUBLIC_HOST=' "$root/.env" 2>/dev/null; then
    warn ".env avec clés non canoniques (traduction / corruption) — régénération depuis .env.example"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    cp "$root/.env" "$root/.env.corrupt.${ts}.bak"
    cp "$root/.env.example" "$root/.env"
    ok ".env sauvegardé → .env.corrupt.${ts}.bak puis recréé depuis .env.example"
    fp_log install ".env repaired from corrupt keys"
    export FP_RECREATE_CERT_PORTAL=1
  fi
  _fp_bootstrap_env_complete || return 1
  return 0
}

# Remplit TOUTES les variables critiques vides + valide qu'aucune n'est vide.
_fp_bootstrap_env_complete() {
  local root="${DIR:-.}" ip url_host rc=0
  ip=$(fp_detect_public_host 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
  url_host=$(fp_detect_public_ip 2>/dev/null || echo "$ip")
  [ -f "$root/.env" ] || { err ".env introuvable"; return 1; }
  if ! command -v python3 >/dev/null 2>&1; then
    err "python3 requis pour le bootstrap .env"
    return 1
  fi
  python3 - "$root/.env" "$ip" "$url_host" <<'PY'
import re, secrets, uuid, base64, sys, pathlib
path = pathlib.Path(sys.argv[1])
ip = (sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1").strip().splitlines()[0].strip()
url_host = (sys.argv[3] if len(sys.argv) > 3 else ip).strip().splitlines()[0].strip()
raw = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
lines = [ln for ln in raw.split("\n") if ln.strip() != "" or ln == ""]

PLACEHOLDER_HOST = "192.0.2.9"
HOST_KEYS = (
    "PUBLIC_HOST", "TIMESKETCH_EXTERNAL_URL", "MISP_PUBLIC_BASE_URL",
    "GRAFANA_ROOT_URL", "GRAFANA_DOMAIN", "GRAFANA_ALLOWED_ORIGINS",
    "GRAFANA_CSRF_ORIGINS", "GRAFANA_CORS_ORIGIN",
)

def host_default(k: str, ip: str) -> str:
    return {
        "PUBLIC_HOST": ip,
        "TIMESKETCH_EXTERNAL_URL": f"https://{ip}/timesketch",
        "MISP_PUBLIC_BASE_URL": f"https://{ip}/misp",
        "GRAFANA_ROOT_URL": f"https://{ip}/grafana/",
        "GRAFANA_DOMAIN": ip,
        "GRAFANA_ALLOWED_ORIGINS": f"https://{ip},http://{ip},https://localhost,http://localhost",
        "GRAFANA_CSRF_ORIGINS": f"https://{ip},http://{ip},https://localhost,http://localhost",
        "GRAFANA_CORS_ORIGIN": f"https://{ip},http://{ip},https://localhost,http://localhost",
    }[k]

def is_documentation_ip(val: str) -> bool:
    return val.startswith(("192.0.2.", "198.51.100.", "203.0.113."))

def should_patch_host(k: str, val: str) -> bool:
    if k not in HOST_KEYS:
        return False
    if val == "":
        return True
    if val == PLACEHOLDER_HOST or PLACEHOLDER_HOST in val:
        return True
    if is_documentation_ip(val):
        return True
    # Ne pas écraser localhost/hostname explicite (Docker Desktop Windows)
    if k == "PUBLIC_HOST" and val in ("localhost", "127.0.0.1"):
        return False
    if "localhost" in val and host in ("127.0.0.1", "localhost"):
        return False
    import re
    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", val)
    if ips and host not in val:
        return True
    return False

CRITICAL = [
    "POSTGRES_PASSWORD", "REDIS_PASSWORD",
    "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
    "TIMESKETCH_PASSWORD", "TIMESKETCH_SECRET_KEY",
    "OPENCTI_ADMIN_PASSWORD", "OPENCTI_ADMIN_TOKEN", "OPENCTI_ENCRYPTION_KEY",
    "OPENCTI_HEALTHCHECK_ACCESS_KEY",
    "RABBITMQ_DEFAULT_PASS",
    "MISP_ADMIN_PASSWORD", "MISP_ADMIN_API_KEY", "MISP_ENCRYPTION_KEY",
    "MYSQL_ROOT_PASSWORD", "MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD",
    "GRAFANA_ADMIN_PASSWORD",
    "THEHIVE_SECRET", "THEHIVE_ADMIN_PASSWORD", "THEHIVE_API_KEY",
    "CORTEX_SECRET", "CORTEX_ADMIN_PASSWORD", "CORTEX_API_KEY",
    "CERT_PORTAL_SECRET", "IT_PORTAL_SECRET", "PORTAINER_ADMIN_PASSWORD",
]

# Connecteurs OpenCTI internes (docker-compose.opencti.yml) — UUID requis même si vides dans l'exemple.
# ThreatFox/SSL Blacklist/MITRE ATLAS/DISARM sont des feeds gratuits sans clé
# API : leurs conteneurs démarrent systématiquement et crash-loopent si
# CONNECTOR_ID est vide (VALIDATION_ERROR input.id null).
OPENCTI_CONNECTOR_IDS = [
    "CONNECTOR_EXPORT_FILE_STIX_ID", "CONNECTOR_EXPORT_FILE_CSV_ID",
    "CONNECTOR_EXPORT_FILE_TXT_ID", "CONNECTOR_IMPORT_FILE_STIX_ID",
    "CONNECTOR_IMPORT_DOCUMENT_ID", "CONNECTOR_DNS_TWIST_ID",
    "CONNECTOR_EXPORT_REPORT_PDF_ID", "CONNECTOR_MITRE_ID",
    "CONNECTOR_CVE_ID", "CONNECTOR_OPENCTI_DATASETS_ID",
    "CONNECTOR_THREATFOX_ID", "CONNECTOR_ABUSE_SSL_ID",
    "CONNECTOR_MITRE_ATLAS_ID", "CONNECTOR_DISARM_ID",
]

OPTIONAL_EMPTY_PREFIXES = (
    "ALIENVAULT_", "ABUSEIPDB_", "SHODAN_", "IPINFO_", "CYBER_MONITOR_",
    "SEKOIA_API_", "SEKOIA_UI_", "S1_API_", "CISA_KEV_",
)

# Clés .env corrompues (traduction FR / renommage manuel) → clés Docker canoniques
ENV_ALIASES = {
    "MOT_DE_PASSE_POSTGRES": "POSTGRES_PASSWORD",
    "MOT_DE_PASSE_RACINE_MINIO": "MINIO_ROOT_PASSWORD",
    "MOT_DE_PASSE_ADMIN_MISP": "MISP_ADMIN_PASSWORD",
    "MOT_DE_PASSE_ADMIN_VELOCIRAPTOR": "VELOCIRAPTOR_ADMIN_PASSWORD",
    "CLÉ_DE_CRYPTION_OPENCTI": "OPENCTI_ENCRYPTION_KEY",
    "CLE_DE_CRYPTION_OPENCTI": "OPENCTI_ENCRYPTION_KEY",
    "CLÉ_API_ADMIN_MISP": "MISP_ADMIN_API_KEY",
    "CLE_API_ADMIN_MISP": "MISP_ADMIN_API_KEY",
    "CLÉ_API_ALIENVAULT": "ALIENVAULT_API_KEY",
    "CLE_API_ALIENVAULT": "ALIENVAULT_API_KEY",
    "CLÉ_API_ABUSEIPDB": "ABUSEIPDB_API_KEY",
    "CLE_API_ABUSEIPDB": "ABUSEIPDB_API_KEY",
    "CLÉ_API_SEKOIA": "SEKOIA_API_KEY",
    "CLE_API_SEKOIA": "SEKOIA_API_KEY",
    "URL_BASE_PUBLIC_MISP": "MISP_PUBLIC_BASE_URL",
    "URL_API_VELOCIRAPTOR": "VELOCIRAPTOR_API_URL",
    "HÔTE_PUBLIC": "PUBLIC_HOST",
    "HOTE_PUBLIC": "PUBLIC_HOST",
    "NOM_HÔTE_PUBLIC": "PUBLIC_HOSTNAME",
    "NOM_HOTE_PUBLIC": "PUBLIC_HOSTNAME",
    "GRAFANA_AUTORISATION_ORIGINES": "GRAFANA_ALLOWED_ORIGINS",
}

CANONICAL_REQUIRED = ("POSTGRES_PASSWORD", "PUBLIC_HOST", "CERT_PORTAL_SECRET")

# P-04 : chaque déploiement génère des secrets ALÉATOIRES forts — plus de
# mots de passe labo partagés entre installations (F0r3ns1c_*). Les scripts
# de test doivent lire les valeurs depuis .env, jamais de constantes.
NON_SECRET_KEYS = ("PORTAL_ADMIN_USER",)

def gen_secret(k: str) -> str:
    if k in NON_SECRET_KEYS:
        return "admin"
    if k == "OPENCTI_ENCRYPTION_KEY":
        return base64.b64encode(secrets.token_bytes(32)).decode()
    if k == "MISP_ENCRYPTION_KEY":
        return secrets.token_hex(16)
    # MISP exige une authkey hex 40 chars (20 octets)
    if k == "MISP_ADMIN_API_KEY":
        return secrets.token_hex(20)
    if k.endswith("_ID") or "TOKEN" in k:
        return str(uuid.uuid4())
    if k in ("CORTEX_SECRET", "THEHIVE_API_KEY", "CORTEX_API_KEY"):
        return secrets.token_hex(16 if "API" in k else 32)
    if "SECRET" in k or "PASSWORD" in k or "KEY" in k:
        return f"Fp_{secrets.token_urlsafe(24)}"
    return f"Fp_{secrets.token_urlsafe(12)}"

def is_optional(k: str) -> bool:
    return any(k.startswith(p) for p in OPTIONAL_EMPTY_PREFIXES)

def parse_val(v: str) -> str:
    v = v.strip().strip('"').strip("'")
    return v

def format_env_val(v: str) -> str:
    """Réécrit une valeur .env en quotant si nécessaire (espaces, #, etc.)."""
    if v is None:
        return ""
    s = str(v)
    if s == "":
        return ""
    # Déjà correctement quotée
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s
    if any(c in s for c in (' ', '\t', '#', '"', "'", '$', '`', '\\', '\n')):
        esc = s.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{esc}"'
    return s

def is_legacy_env_key(k: str) -> bool:
    if k in ENV_ALIASES or k.startswith("CONNECTEUR_"):
        return True
    legacy_prefixes = (
        "MOT_DE_PASSE_", "CLÉ_", "CLE_", "URL_BASE_", "URL_API_",
        "NOM_HÔTE_", "NOM_HOTE_", "GRAFANA_AUTORISATION_",
    )
    return any(k.startswith(p) for p in legacy_prefixes)

def canon_env_key(k: str):
    if k in ENV_ALIASES:
        return ENV_ALIASES[k]
    if k.startswith("CONNECTEUR_"):
        return "CONNECTOR_" + k[len("CONNECTEUR_"):]
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
        return k
    return None

existing = {}
alias_migrated = set()
order = []
for line in lines:
    stripped = line.strip()
    if stripped == "" or stripped.startswith("#"):
        order.append(line)
        continue
    if "=" not in line:
        order.append(line)
        continue
    k, _, v = line.partition("=")
    k = k.strip()
    val = parse_val(v)
    canon = canon_env_key(k)
    if canon is None:
        order.append(line)
        continue
    if k != canon:
        alias_migrated.add(canon)
    if canon == "POSTGRES_DB" and val.lower() in ("médical", "medical"):
        val = "forensic"
    existing[canon] = val
    order.append(line)

access_mode = (existing.get("FP_ACCESS_MODE") or "ip").strip().lower()
if access_mode == "ip":
    host = url_host or ip
else:
    host = (existing.get("PUBLIC_HOSTNAME") or "").strip() or url_host or ip

DEFAULTS = {
    "POSTGRES_USER": "forensic",
    "POSTGRES_DB": "forensic",
    "MINIO_ROOT_USER": "forensicadmin",
    "MYSQL_DATABASE": "misp",
    "MYSQL_USER": "misp",
    "TIMESKETCH_USER": "admin",
    "RABBITMQ_DEFAULT_USER": "opencti",
    "RABBITMQ_DEFAULT_VHOST": "opencti",
    "OPENCTI_ADMIN_EMAIL": "admin@forensic.local",
    "MISP_ADMIN_EMAIL": "admin@forensic.local",
    "THEHIVE_ADMIN_LOGIN": "admin",
    "VELOCIRAPTOR_ADMIN_USER": "admin",
    # P-04 : aucun secret dans DEFAULTS — générés aléatoirement plus bas (SECRET_LIKE)
    "PORTAL_ADMIN_USER": "admin",
    "PUBLIC_HOST": host,
    "TIMESKETCH_EXTERNAL_URL": f"https://{host}/timesketch",
    "MISP_PUBLIC_BASE_URL": f"https://{host}/misp",
    "GRAFANA_ROOT_URL": f"https://{host}/grafana/",
    "GRAFANA_DOMAIN": host,
    "GRAFANA_ALLOWED_ORIGINS": f"https://{host},http://{host},https://localhost,http://localhost",
    "GRAFANA_CSRF_ORIGINS": f"https://{host},http://{host},https://localhost,http://localhost",
    "GRAFANA_CORS_ORIGIN": f"https://{host},http://{host},https://localhost,http://localhost",
}

# Appliquer defaults + génération secrets pour valeurs vides
for k, dv in DEFAULTS.items():
    if k not in existing or existing[k] == "":
        existing[k] = dv

# Secrets : générés aléatoirement si clé migrée depuis alias FR ou valeur vide (P-04)
SECRET_LIKE = tuple(s for s in tuple(CRITICAL) + tuple(DEFAULTS.keys()) + tuple(existing.keys())
                    if any(t in s for t in ("SECRET", "PASSWORD", "KEY", "TOKEN")))
for k in SECRET_LIKE:
    if k in alias_migrated or not existing.get(k):
        existing[k] = gen_secret(k)

# Toujours remplacer les placeholders IP lab (192.0.2.9) par l'IP détectée
for k in HOST_KEYS:
    if should_patch_host(k, existing.get(k, "")):
        existing[k] = host_default(k, host)

for k in list(existing.keys()) + list(CRITICAL):
    if k not in existing:
        existing[k] = ""
    if existing[k] != "":
        continue
    if is_optional(k):
        continue
    if k.endswith("_ID") and k.startswith("CONNECTOR_"):
        existing[k] = str(uuid.uuid4())
        continue
    if any(s in k for s in ("PASSWORD", "PASS", "SECRET", "TOKEN", "KEY")):
        existing[k] = gen_secret(k)
    elif k in DEFAULTS:
        existing[k] = DEFAULTS[k]

for k in OPENCTI_CONNECTOR_IDS:
    if k not in existing or existing[k] == "":
        existing[k] = str(uuid.uuid4())

# Clés critiques absentes du fichier
for k in CRITICAL:
    if k not in existing or existing[k] == "":
        if not is_optional(k):
            existing[k] = gen_secret(k)

missing = [k for k in CRITICAL if not existing.get(k)]
if missing:
    print("CRITICAL_MISSING:" + ",".join(missing), file=sys.stderr)
    sys.exit(1)

missing_canon = [k for k in CANONICAL_REQUIRED if not existing.get(k)]
if missing_canon:
    print("CANONICAL_MISSING:" + ",".join(missing_canon), file=sys.stderr)
    sys.exit(2)

# Réécrire .env (clés canoniques uniquement — supprime lignes traduites / orphelines)
out = []
seen = set()
for line in lines:
    if line.strip() == "":
        out.append("")
        continue
    if line.lstrip().startswith("#"):
        out.append(line)
        continue
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
    if m:
        k = m.group(1)
        if is_legacy_env_key(k):
            continue
        if k in existing:
            out.append(f"{k}={format_env_val(existing[k])}")
            seen.add(k)
        else:
            out.append(line)
    # sinon : ligne orpheline (ex. clés accentuées / CSV cassées) — ignorée
for k, v in sorted(existing.items()):
    if is_legacy_env_key(k):
        continue
    if k not in seen:
        out.append(f"{k}={format_env_val(v)}")
path.write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"OK vars={len(existing)} critical={len(CRITICAL)}")
PY
  rc=$?
  if [ "$rc" -ne 0 ]; then
    err "Variables .env critiques manquantes — bootstrap arrêté"
    fp_log install ".env validation FAIL"
    return 1
  fi
  ok "Variables .env complètes et validées (secrets + MySQL/MISP/MinIO/portails)"
  fp_log install ".env complete OK ip=$ip"
  return 0
}

_fp_bootstrap_patch_env_host() {
  # Conservé pour compatibilité — le patch IP est intégré à _fp_bootstrap_env_complete.
  :
}

_fp_bootstrap_apt_extras() {
  local pkgs=() p
  # python3-yaml : génération config Velociraptor ; python3-requests : scripts
  # hôte (opensearch_collect_platform_logs.py, repair-timesketch*, tests e2e,
  # misp_login_ok) — sinon ImportError sur VM fraîche et opensearch_advanced.sh
  # échoue (exit 1) en fin de déploiement.
  for p in python3-yaml python3-requests; do
    dpkg -s "$p" >/dev/null 2>&1 || pkgs+=("$p")
  done
  [ "${#pkgs[@]}" -eq 0 ] && { ok "Packages extras présents (python3-yaml, python3-requests)"; return 0; }
  warn "Installation packages extras: ${pkgs[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >> "$FP_LOG_INSTALL" 2>&1 \
      && ok "Packages extras installés" || warn "Installation packages extras partielle (${pkgs[*]})"
  else
    warn "apt-get absent — installer manuellement: ${pkgs[*]:-python3-yaml python3-requests}"
  fi
  return 0
}

_fp_bootstrap_external_networks() {
  local docker_bin="${FP_DOCKER:-docker}"
  local nets=(helk_net:172.30.0.0/24 velociraptor_net:172.31.0.0/24) entry name cidr
  for entry in "${nets[@]}"; do
    name="${entry%%:*}"; cidr="${entry#*:}"
    if $docker_bin network inspect "$name" >/dev/null 2>&1; then
      ok "Réseau $name déjà présent"
    elif $docker_bin network create --driver bridge --subnet "$cidr" "$name" >> "$FP_LOG_INSTALL" 2>&1; then
      ok "Réseau $name créé ($cidr)"
    else
      warn "Création réseau $name échouée (peut exister avec autre subnet)"
    fi
  done
  return 0
}

_fp_bootstrap_patch_helk_lab_configs() {
  local root="${DIR:-.}" ip="$1" f
  for f in "$root/helk/config/lab/filebeat-lab.yml" "$root/helk/config/lab/winlogbeat-lab.yml"; do
    [ -f "$f" ] || continue
    sed -i -E "s/hosts: \\[\"[0-9.]+:15514\"\\]/hosts: [\"${ip}:15514\"]/" "$f" 2>/dev/null || true
  done
}

_fp_regenerate_velociraptor_config() {
  local root="${DIR:-.}" host need=0 rc=0
  host=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "localhost")
  host=$(fp_normalize_host "$host" 2>/dev/null || echo "$host")
  local cfg="$root/velociraptor/config/server.config.yaml"
  if [ ! -f "$cfg" ]; then
    need=1
  elif grep -q '10\.78\.0\.9' "$cfg" 2>/dev/null; then
    need=1
  elif ! grep -q "$host" "$cfg" 2>/dev/null; then
    need=1
  elif grep -q ':8001/' "$cfg" 2>/dev/null && [ "${FP_VR_NGINX_ONLY:-1}" = "1" ]; then
    need=1
  elif ! grep -q 'use_plain_http: true' "$cfg" 2>/dev/null; then
    need=1
  elif ! grep -q '/velociraptor/app/index.html' "$cfg" 2>/dev/null; then
    need=1
  elif grep -q '127\.0\.0\.1' "$cfg" 2>/dev/null; then
    need=1
  fi
  if [ "$need" -eq 1 ] && [ -x "$root/velociraptor/scripts/generate-config.sh" ]; then
    FP_VR_NGINX_ONLY=1 PUBLIC_HOST="$host" bash "$root/velociraptor/scripts/generate-config.sh" \
      >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 \
      && ok "Velociraptor config régénérée ($host)" \
      || { warn "Velociraptor config — échec (voir logs/forensic_install.log)"; rc=1; }
  fi
  if [ -f "$cfg" ] && grep -q '10\.78\.0\.9' "$cfg" 2>/dev/null; then
    err "Velociraptor server.config.yaml contient encore l'IP lab 192.0.2.9"
    return 1
  fi
  return "$rc"
}

_fp_bootstrap_validate_host_configs() {
  local root="${DIR:-.}" host ip rc=0
  host=$(fp_url_identity 2>/dev/null || echo "")
  ip=$(fp_detect_public_ip 2>/dev/null || echo "")
  if [ -f "$root/velociraptor/config/server.config.yaml" ] \
    && grep -q '10\.78\.0\.9' "$root/velociraptor/config/server.config.yaml" 2>/dev/null; then
    err "Config Velociraptor non alignée sur l'IP publique (192.0.2.9 résiduel)"
    rc=1
  fi
  if [ -n "$host" ] && [ -f "$root/.env" ] && grep -q '^PUBLIC_HOST=10\.78\.0\.9' "$root/.env" 2>/dev/null; then
    err ".env PUBLIC_HOST encore sur IP lab 192.0.2.9"
    rc=1
  fi
  if [ -n "$host" ] && ! grep -q "$host" "$root/.env" 2>/dev/null; then
    warn ".env PUBLIC_HOST ≠ hôte détecté ($host)"
  fi
  if [ ! -f "$root/config/nginx/static/site-info.html" ]; then
    warn "config/nginx/static/site-info.html absent — fp_prepare_platform_host"
  fi
  [ "$rc" -eq 0 ] && ok "Validation configs hôte (IP ${host:-$ip})"
  return "$rc"
}

_fp_ensure_runtime_host_config() {
  local root="${DIR:-.}" ip
  ip=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "127.0.0.1")
  ip=$(fp_normalize_host "$ip" 2>/dev/null || echo "$ip")
  _fp_bootstrap_env_complete 2>/dev/null || true
  if command -v fp_prepare_platform_host >/dev/null 2>&1; then
    fp_prepare_platform_host 2>/dev/null || true
  fi
  if [ -x "$root/scripts/generate-timesketch-conf.sh" ]; then
    bash "$root/scripts/generate-timesketch-conf.sh" >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 || true
  fi
  _fp_regenerate_velociraptor_config || return 1
  fp_patch_portal_soc_base_urls "$ip" 2>/dev/null || true
  if [ -x "$root/scripts/generate-grafana-ini.sh" ]; then
    bash "$root/scripts/generate-grafana-ini.sh" >> "${FP_LOG_INSTALL:-$root/logs/forensic_install.log}" 2>&1 || true
  fi
  _fp_bootstrap_patch_helk_lab_configs "$ip"
  _fp_bootstrap_validate_host_configs || return 1
  return 0
}

_fp_bootstrap_generate_configs() {
  local root="${DIR:-.}" ip cfg
  ip=$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
  if [ -x "$root/scripts/generate-timesketch-conf.sh" ]; then
    bash "$root/scripts/generate-timesketch-conf.sh" >> "$FP_LOG_INSTALL" 2>&1 \
      && ok "timesketch.conf généré" \
      || warn "timesketch.conf — voir logs/forensic_install.log"
  fi
  for cfg in "$root/portal-cert/public/config.json" "$root/portal-it/public/config.json"; do
    [ -f "$cfg" ] || continue
    if command -v jq >/dev/null 2>&1; then
      jq --arg url "https://${ip}" '.soc_base_url = $url' "$cfg" > "${cfg}.tmp" && mv -f "${cfg}.tmp" "$cfg"
    else
      python3 - "$cfg" "$ip" <<'PY'
import json, sys
p, ip = sys.argv[1], sys.argv[2]
with open(p, encoding="utf-8") as f: d = json.load(f)
d["soc_base_url"] = f"https://{ip}"
with open(p, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=2); f.write("\n")
PY
    fi
  done
  if [ -f "$root/config/nginx/conf.d/forensic.conf" ]; then
    _fp_patch_nginx_server_name "$root/config/nginx/conf.d/forensic.conf" "$ip"
    _fp_patch_nginx_grafana_maps "$root/config/nginx/conf.d/forensic.conf" "$ip"
  fi
  _fp_bootstrap_patch_helk_lab_configs "$ip"
  if command -v fp_prepare_platform_host >/dev/null 2>&1; then
    fp_prepare_platform_host && ok "Pages site + nginx access (IP $ip)" \
      || warn "fp_prepare_platform_host partiel — voir logs/forensic_install.log"
  fi
  _fp_regenerate_velociraptor_config || warn "Velociraptor regen partielle"
  ok "Portails config.json + nginx + timesketch + HELK lab → $ip"
}

_fp_bootstrap_cert_dirs() {
  local root="${DIR:-.}" d
  local dirs=(
    nginx/certs/server
    nginx/certs/ca
    config/nginx/ssl
    config/timesketch
    portal-cert/certs
    portal-it/certs
    helk/certs
    velociraptor/certs
    velociraptor/data
    velociraptor/lab-collections
    logs
  )
  for d in "${dirs[@]}"; do
    mkdir -p "$root/$d"
  done
  ok "Dossiers persistants / certs créés (${#dirs[@]})"
}

_fp_bootstrap_generate_tls() {
  local root="${DIR:-.}" ip rc=0 need=0
  ip=$(fp_detect_public_ip 2>/dev/null || fp_url_identity 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

  if [ ! -f "$root/nginx/certs/ca/ca.crt" ] || [ ! -f "$root/nginx/certs/ca/ca.key" ]; then
    info "Génération CA interne (openssl)..."
    bash "$root/scripts/generate_ca.sh" >> "$FP_LOG_INSTALL" 2>&1 || rc=1
  fi

  if [ ! -f "$root/config/nginx/ssl/forensic.crt" ] || [ ! -f "$root/config/nginx/ssl/forensic.key" ]; then
    need=1
  elif ! _fp_cert_san_contains_ip "$root/config/nginx/ssl/forensic.crt" "$ip"; then
    info "Certificat forensic-platform SAN ≠ $ip — régénération..."
    need=1
  fi
  if [ "$need" -eq 1 ]; then
    info "Génération certificat TLS (CN=forensic-platform, SAN IP=$ip)..."
    bash "$root/scripts/generate_server_cert.sh" "$ip" >> "$FP_LOG_INSTALL" 2>&1 || rc=1
  else
    mkdir -p "$root/nginx/certs/server"
    cp -f "$root/config/nginx/ssl/forensic.crt" "$root/nginx/certs/server/server.crt" 2>/dev/null || true
    cp -f "$root/config/nginx/ssl/forensic.key" "$root/nginx/certs/server/server.key" 2>/dev/null || true
  fi

  [ "$rc" -eq 0 ] && ok "Certificats TLS générés/vérifiés (forensic-platform + IP=$ip)" \
    || warn "Génération TLS partielle — voir logs/forensic_install.log"
  return "$rc"
}

_fp_bootstrap_sync_cert_links() {
  local root="${DIR:-.}" sub d
  local subs=(portal-cert/certs portal-it/certs helk/certs velociraptor/certs)
  for sub in "${subs[@]}"; do
    d="$root/$sub"
    mkdir -p "$d"
    rm -f "$d/ca.crt" "$d/server.crt" "$d/server.key" "$d/forensic.crt" "$d/forensic.key"
    ln -sfn "../../nginx/certs/ca/ca.crt" "$d/ca.crt"
    ln -sfn "../../nginx/certs/server/server.crt" "$d/server.crt"
    ln -sfn "../../nginx/certs/server/server.key" "$d/server.key"
    ln -sfn "../../config/nginx/ssl/forensic.crt" "$d/forensic.crt"
    ln -sfn "../../config/nginx/ssl/forensic.key" "$d/forensic.key"
  done
  ok "Certificats synchronisés → portails / HELK / Velociraptor"
}

_fp_bootstrap_cert_permissions() {
  local root="${DIR:-.}"
  find "$root/nginx/certs" "$root/config/nginx/ssl" \
    "$root/portal-cert/certs" "$root/portal-it/certs" \
    "$root/helk/certs" "$root/velociraptor/certs" \
    -type f -name '*.key' 2>/dev/null | while read -r f; do chmod 600 "$f" 2>/dev/null || true; done
  find "$root/nginx/certs" "$root/config/nginx/ssl" \
    -type f -name '*.crt' 2>/dev/null | while read -r f; do chmod 644 "$f" 2>/dev/null || true; done
  [ -f "$root/nginx/certs/ca/ca.key" ] && chmod 600 "$root/nginx/certs/ca/ca.key" 2>/dev/null || true
  ok "Permissions TLS: *.key=600 · *.crt=644"
}

_fp_bootstrap_verify_nginx_tls() {
  local root="${DIR:-.}" missing=() f
  local required=(
    nginx/certs/server/server.crt
    nginx/certs/server/server.key
    nginx/certs/ca/ca.crt
    config/nginx/ssl/forensic.crt
    config/nginx/ssl/forensic.key
  )
  for f in "${required[@]}"; do
    [ -f "$root/$f" ] || missing+=("$f")
  done

  if [ -f "$root/config/nginx/conf.d/forensic.conf" ]; then
    if grep -q 'ssl_certificate[[:space:]]\+/etc/nginx/ssl/forensic.crt' \
      "$root/config/nginx/conf.d/forensic.conf" 2>/dev/null; then
      ok "nginx/conf.d/forensic.conf → TLS forensic-platform (/etc/nginx/ssl/forensic.crt)"
    else
      warn "nginx/conf.d/forensic.conf — vérifier ssl_certificate / ssl_certificate_key"
    fi
  else
    missing+=("config/nginx/conf.d/forensic.conf")
  fi

  if [ "${#missing[@]}" -gt 0 ]; then
    err "Certificats TLS manquants pour Nginx / portails :"
    printf '    • %s\n' "${missing[@]}"
    err "Relancer : ./forensic.sh -full-start  ou  ./forensic.sh tls"
    return 1
  fi
  ok "Validation TLS Nginx — tous les fichiers requis présents"
  return 0
}

# Point d'entrée phase 0 — machine vierge (sans .env, sans certs, sans openssl)
fp_bootstrap_fresh_machine() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "ORCHESTRATEUR PHASE 0 — Bootstrap machine vierge"
  fp_log_init
  fp_log install "=== fp_bootstrap_fresh_machine ==="

  _fp_bootstrap_ensure_openssl || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
  _fp_bootstrap_apt_extras || true
  _fp_bootstrap_env_file || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
  _fp_bootstrap_patch_env_host
  _fp_bootstrap_cert_dirs
  _fp_bootstrap_generate_tls || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
  _fp_bootstrap_sync_cert_links
  _fp_bootstrap_cert_permissions
  _fp_bootstrap_verify_nginx_tls || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
  _fp_regenerate_velociraptor_config || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
  _fp_bootstrap_generate_configs
  _fp_bootstrap_validate_host_configs || { if [ "$_had_e" -eq 1 ]; then set -e; fi; return 1; }
  if command -v docker >/dev/null 2>&1; then
    fp_ensure_docker >/dev/null 2>&1 || true
    _fp_bootstrap_external_networks || warn "Réseaux externes partiels (helk_net / velociraptor_net)"
  fi

  export FP_TLS_NO_DOCKER=1
  fp_log install "bootstrap fresh machine OK"
  ok "Bootstrap machine vierge terminé (.env + TLS + dossiers)"
  if _fp_is_ipv4 "$(_fp_aws_public_ipv4 2>/dev/null || true)" 2>/dev/null; then
    info "AWS détecté — vérifier le Security Group (TCP 80/443) et utiliser l'IP publique affichée par ./forensic.sh urls"
  fi
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# ──────────────────────────────────────────────────────────────
#  ORCHESTRATEUR FULL-START (./forensic.sh -full-start)
# ──────────────────────────────────────────────────────────────
FP_ORCH_REPORT=()
FP_ORCH_TEST_OK=0
FP_ORCH_TEST_FAIL=0

_fp_orch_note() {
  FP_ORCH_REPORT+=("$1")
  fp_log start "orch: $1"
}

_fp_orch_run_test() {
  local label="$1"; shift
  info "Test: $label"
  if "$@" >> "${FP_LOG_START}" 2>&1; then
    ok "$label"
    FP_ORCH_TEST_OK=$((FP_ORCH_TEST_OK + 1))
    _fp_orch_note "OK: $label"
    return 0
  fi
  warn "$label — échec (voir logs/forensic_start.log)"
  FP_ORCH_TEST_FAIL=$((FP_ORCH_TEST_FAIL + 1))
  _fp_orch_note "FAIL: $label"
  return 1
}

# PHASE 1 — Vérification système (OS, ressources, ports, sudo)
fp_verify_system() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "ORCHESTRATEUR PHASE 1 — Vérification système"
  fp_log_init
  fp_log start "=== fp_verify_system ==="

  local os_ok=0
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
      *debian*|*ubuntu*) os_ok=1; ok "OS compatible: ${PRETTY_NAME:-$ID}" ;;
      *) warn "OS non Debian/Ubuntu (${PRETTY_NAME:-inconnu}) — poursuite sans garantie" ;;
    esac
  else
    warn "/etc/os-release absent — OS non vérifié"
  fi
  [ "$os_ok" -eq 1 ] && _fp_orch_note "OS: ${PRETTY_NAME:-OK}"

  local cpus mem_mb disk_pct
  cpus=$(nproc 2>/dev/null || echo "?")
  mem_mb=$(awk '/MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "?")
  disk_pct=$(df -P "${DIR:-.}" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
  info "CPU: ${cpus} cœurs · RAM: ~${mem_mb} MiB · Disque (${DIR:-.}): ${disk_pct:-?}%"
  if [ "${mem_mb:-0}" != "?" ] && [ "$mem_mb" -lt 4096 ] 2>/dev/null; then
    warn "RAM < 4 Go — démarrage possible mais lent"
  fi
  if [ -n "${disk_pct:-}" ] && [ "$disk_pct" -ge 95 ] 2>/dev/null; then
    warn "Disque quasi plein (${disk_pct}%)"
  fi

  local critical_ports=(9200 5601 3000 9000 8080 8081 80 443)
  local port busy=()
  for port in "${critical_ports[@]}"; do
    if command -v ss >/dev/null 2>&1; then
      ss -tlnH "sport = :$port" 2>/dev/null | grep -q . && busy+=("$port")
    elif command -v lsof >/dev/null 2>&1; then
      lsof -iTCP:"$port" -sTCP:LISTEN -P -n >/dev/null 2>&1 && busy+=("$port")
    fi
  done
  if [ "${#busy[@]}" -gt 0 ]; then
    warn "Ports déjà occupés: ${busy[*]} (cleanup_ports tentera de libérer si FP_KILL_PORTS=1)"
    _fp_orch_note "Ports occupés: ${busy[*]}"
  else
    ok "Ports critiques libres: ${critical_ports[*]}"
  fi

  if [ "$(id -u)" -eq 0 ]; then
    ok "Droits: root"
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    ok "Droits: sudo NOPASSWD"
  elif command -v sudo >/dev/null 2>&1; then
    warn "sudo interactif — l'installation auto apt peut demander un mot de passe"
    _fp_orch_note "sudo: interactif"
  else
    warn "sudo absent — installation packages limitée"
    _fp_orch_note "sudo: absent"
  fi

  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# PHASE 2 — Dépendances étendues (node, npm, wget, unzip, tar…)
fp_install_dependencies_extended() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "ORCHESTRATEUR PHASE 2 — Dépendances étendues"
  fp_log_init

  _fp_pkg_ext() {
    case "$1" in
      node)  echo "nodejs" ;;
      npm)   echo "npm" ;;
      wget)  echo "wget" ;;
      unzip) echo "unzip" ;;
      tar)   echo "tar" ;;
      *)     echo "$1" ;;
    esac
  }

  local extra=(wget unzip tar node npm)
  local missing=()
  local cmd
  for cmd in "${extra[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done

  if [ "${#missing[@]}" -eq 0 ]; then
    ok "Dépendances étendues présentes: ${extra[*]}"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 0
  fi

  warn "Manquants: ${missing[*]} — installation auto"
  local pkgs=() c
  for c in "${missing[@]}"; do pkgs+=("$(_fp_pkg_ext "$c")"); done
  local pkgs_uniq
  pkgs_uniq=$(printf '%s\n' "${pkgs[@]}" | awk '!s[$0]++')

  if command -v apt-get >/dev/null 2>&1; then
    _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$FP_LOG_INSTALL" 2>&1 || true
    # shellcheck disable=SC2086
    _fp_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs_uniq >> "$FP_LOG_INSTALL" 2>&1 \
      && ok "Packages étendus installés" \
      || warn "Installation partielle — voir $FP_LOG_INSTALL"
  else
    warn "apt-get absent — installer manuellement: $pkgs_uniq"
  fi

  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# PHASE 3 — Vérification structure monorepo
fp_verify_monorepo() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "ORCHESTRATEUR PHASE 3 — Vérification monorepo"
  local root="${DIR:-.}"
  local dirs=(helk velociraptor config portal-cert portal-it dashboards scripts tests)
  local missing=() d
  for d in "${dirs[@]}"; do
    if [ ! -d "$root/$d" ]; then
      missing+=("$d")
      err "Dossier manquant: $d/"
    else
      ok "$d/"
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    _fp_orch_note "Monorepo incomplet: ${missing[*]}"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 1
  fi

  [ -f "$root/docker-compose.yml" ] || { err "docker-compose.yml absent"; return 1; }
  local compose="${FP_COMPOSE:-docker compose}"
  if $compose -f "$root/docker-compose.yml" config >/dev/null 2>&1; then
    ok "docker-compose.yml valide"
  else
    err "docker-compose.yml invalide"
    $compose -f "$root/docker-compose.yml" config 2>&1 | tail -20
    return 1
  fi

  [ -x "$root/forensic.sh" ] || chmod +x "$root/forensic.sh" 2>/dev/null || true
  local nfix=0 shf
  for shf in "$root"/scripts/*.sh; do
    [ -f "$shf" ] || continue
    [ -x "$shf" ] || { chmod +x "$shf" 2>/dev/null && nfix=$((nfix + 1)); }
  done
  [ "$nfix" -gt 0 ] && info "$nfix script(s) rendus exécutables"

  ok "Structure monorepo OK"
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# PHASE 5bis — Santé agrégée /api/health/global + services clés
fp_full_start_health_global() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "ORCHESTRATEUR PHASE 5 — Santé globale plateforme"

  local base="${FP_ORCH_BASE_URL:-https://localhost}"
  local n=0 body code rc=0
  while [ "$n" -lt 36 ]; do
    code=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' "$base/api/health/global" 2>/dev/null || echo "000")
    [ "$code" = "200" ] && break
    n=$((n + 1)); sleep 5
  done

  body=$(curl -sk --max-time 12 "$base/api/health/global" 2>/dev/null || true)
  if [ -z "$body" ]; then
    warn "/api/health/global injoignable ($base)"
    _fp_orch_note "health/global: injoignable"
    if [ "$_had_e" -eq 1 ]; then set -e; fi
    return 1
  fi

  if ! echo "$body" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("  (réponse non-JSON)")
    sys.exit(1)
svcs = d.get("services") or d.get("components") or []
if isinstance(svcs, dict):
    svcs = [{"name": k, **(v if isinstance(v, dict) else {"status": v})} for k, v in svcs.items()]
down = degraded = up = 0
for s in svcs:
    st = (s.get("status") or s.get("state") or "").upper()
    name = s.get("name") or s.get("id") or "?"
    if st in ("DOWN", "ERROR", "CRITICAL", "UNHEALTHY"):
        print(f"  ✗ {name}: {st or \"DOWN\"}"); down += 1
    elif st in ("DEGRADED", "WARN", "WARNING"):
        print(f"  ~ {name}: {st}"); degraded += 1
    else:
        print(f"  ✓ {name}: {st or \"UP\"}"); up += 1
print(f"\n  Résumé: {up} UP · {degraded} DEGRADED · {down} DOWN")
sys.exit(0 if down == 0 else 1)
' 2>/dev/null; then
    rc=1
    warn "Santé globale partielle"
  else
    ok "Santé globale OK"
  fi

  local checks=(
    "HELK|${base}/api/helk/status|200"
    "Velociraptor|${base}/api/velociraptor/status|200"
    "Timesketch|http://localhost:5000/login|200,301,302,308"
    "Grafana|${base}/grafana/api/health|200"
    "OpenSearch|http://localhost:9200/_cluster/health|200"
    "MISP|${base}/misp/users/login|200,301,302"
    "TheHive|http://localhost:9002/thehive/api/status|200"
    "Cortex|http://localhost:9003/api/status|200,401"
    "Nginx|${base}/|200,301,302"
  )
  local entry name url expects c
  for entry in "${checks[@]}"; do
    IFS='|' read -r name url expects <<< "$entry"
    c=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "000")
    if echo ",$expects," | grep -q ",$c,"; then
      ok "$name → HTTP $c"
    else
      warn "$name → HTTP $c (attendu ∈ {$expects})"
      rc=1
    fi
  done

  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return "$rc"
}

# PHASE 6 — Tests étendus (API, ingestion, pivots, Playwright, UI)
fp_full_start_extended_tests() {
  local _had_e=0
  case $- in *e*) _had_e=1;; esac
  set +e
  step "ORCHESTRATEUR PHASE 6 — Tests automatiques étendus"
  fp_log start "=== fp_full_start_extended_tests ==="

  if [ -f "$DIR/scripts/global_health_dashboard_verify.py" ]; then
    _fp_orch_run_test "API health global" python3 "$DIR/scripts/global_health_dashboard_verify.py" || true
  fi
  if [ -f "$DIR/scripts/helk_velociraptor_master_verify.py" ]; then
    _fp_orch_run_test "API HELK/VR" python3 "$DIR/scripts/helk_velociraptor_master_verify.py" || true
  fi
  if [ -f "$DIR/scripts/crosspivot_verify.py" ]; then
    _fp_orch_run_test "Pivots SOC (cross-pivot)" python3 "$DIR/scripts/crosspivot_verify.py" || true
  fi
  if [ -x "$DIR/scripts/test_ingest_e2e.sh" ]; then
    _fp_orch_run_test "Ingestion E2E" bash "$DIR/scripts/test_ingest_e2e.sh" || true
  fi
  if [ -f "$DIR/scripts/ui_campaign_verify.py" ]; then
    _fp_orch_run_test "Campagne UI (OSD/Grafana/TS/portails)" python3 "$DIR/scripts/ui_campaign_verify.py" || true
  fi

  if [ "${FP_ORCH_SKIP_PLAYWRIGHT:-0}" != "1" ] && [ -f "$DIR/tests/playwright.config.ts" ]; then
    if command -v npx >/dev/null 2>&1; then
      step "Playwright — projet ui-integration"
      # Machine vierge : @playwright/test et Chromium ne sont pas installés
      if [ ! -d "$DIR/tests/node_modules/@playwright/test" ]; then
        info "Playwright — installation des dépendances (npm install + chromium)"
        (cd "$DIR/tests" && npm install --no-audit --no-fund >/dev/null 2>&1 \
          && npx playwright install --with-deps chromium >/dev/null 2>&1) \
          || warn "Playwright — installation dépendances incomplète"
      fi
      local pw_log="$FP_LOG_DIR/full-start-playwright.log"
      local pw_rc=0
      (
        cd "$DIR/tests" || exit 1
        export BASE_URL="${FP_ORCH_BASE_URL:-https://localhost}"
        # --use-system-ca est interdit dans NODE_OPTIONS sur Node 20 —
        # NODE_EXTRA_CA_CERTS fait confiance à la CA plateforme partout.
        [ -f "$DIR/nginx/certs/ca/ca.crt" ] && export NODE_EXTRA_CA_CERTS="$DIR/nginx/certs/ca/ca.crt"
        PLAYWRIGHT_HTML_OPEN=never npx playwright test \
          --config=playwright.config.ts \
          --project=ui-integration
      ) 2>&1 | tee "$pw_log" || pw_rc=$?
      if [ "$pw_rc" -eq 0 ]; then
        ok "Playwright ui-integration"
        FP_ORCH_TEST_OK=$((FP_ORCH_TEST_OK + 1))
      else
        warn "Playwright ui-integration — échecs (voir $pw_log)"
        FP_ORCH_TEST_FAIL=$((FP_ORCH_TEST_FAIL + 1))
      fi
    else
      warn "npx absent — Playwright ignoré (installer nodejs/npm)"
    fi
  fi

  info "Bilan tests orchestrateur: ${FP_ORCH_TEST_OK} OK · ${FP_ORCH_TEST_FAIL} KO"
  if [ "$_had_e" -eq 1 ]; then set -e; fi
  return 0
}

# PHASE 7 — Rapport final
fp_full_start_final_report() {
  local rc="${1:-0}"
  local end_ts dur min sec
  end_ts=$(date +%s)
  dur=$((end_ts - ${FP_ORCH_START_TS:-end_ts}))
  min=$((dur / 60))
  sec=$((dur % 60))

  echo ""
  echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║${NC}  RAPPORT FINAL — ./forensic.sh -full-start"
  echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
  printf "${BLUE}║${NC}  Durée totale: %dm %02ds\n" "$min" "$sec"
  printf "${BLUE}║${NC}  Tests orchestrateur: %s OK · %s KO\n" "${FP_ORCH_TEST_OK:-0}" "${FP_ORCH_TEST_FAIL:-0}"
  if [ "${#START_OK[@]}" -gt 0 ] 2>/dev/null; then
    printf "${BLUE}║${NC}  Étapes start: %s OK" "${#START_OK[@]}"
    # ${#arr[@]:-0} est une substitution invalide en bash — tester la taille
    # du tableau directement (vaut 0 si vide/non défini sous set -u désactivé)
    if [ "${#START_FAIL[@]}" -gt 0 ] 2>/dev/null; then printf " · %s échecs" "${#START_FAIL[@]}"; fi
    echo ""
  fi
  echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"

  if command -v docker >/dev/null 2>&1; then
    local up total
    total=$(docker ps -a --filter "name=forensic" -q 2>/dev/null | wc -l | tr -d ' ')
    up=$(docker ps --filter "name=forensic" --filter "status=running" -q 2>/dev/null | wc -l | tr -d ' ')
    echo -e "${BLUE}║${NC}  Containers forensic-*: ${up}/${total} running"
    docker ps -a --filter "name=forensic" --filter "status=exited" \
      --format '  ✗ {{.Names}} ({{.Status}})' 2>/dev/null | head -5 \
      | sed "s/^/${BLUE}║${NC}/" || true
    docker ps -a --filter "name=forensic" --filter "status=restarting" \
      --format '  ↻ {{.Names}} ({{.Status}})' 2>/dev/null | head -5 \
      | sed "s/^/${BLUE}║${NC}/" || true
  fi

  if [ "${#FP_ORCH_REPORT[@]}" -gt 0 ]; then
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  Notes:"
    local line
    for line in "${FP_ORCH_REPORT[@]}"; do
      echo -e "${BLUE}║${NC}    • $line"
    done
  fi

  echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${BLUE}║${NC}  Conseils:"
  echo -e "${BLUE}║${NC}    • Statut détaillé : ./forensic.sh status"
  echo -e "${BLUE}║${NC}    • Santé OpenSearch : ./forensic.sh fix-opensearch"
  echo -e "${BLUE}║${NC}    • QA complète     : ./forensic.sh qa-ultra"
  echo -e "${BLUE}║${NC}    • Logs            : tail -50 logs/forensic_start.log"
  echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  if [ "$rc" -eq 0 ] && [ "${FP_ORCH_TEST_FAIL:-0}" -eq 0 ]; then
    ok "FULL-START terminé avec succès"
  else
    warn "FULL-START terminé avec avertissements — validation humaine recommandée"
  fi
  fp_log start "=== full-start report rc=$rc tests_ok=${FP_ORCH_TEST_OK} tests_fail=${FP_ORCH_TEST_FAIL} dur=${dur}s ==="
  return "$rc"
}
