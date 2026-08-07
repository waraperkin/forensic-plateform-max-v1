#!/usr/bin/env bash
# Déploiement automatisé SEP + Ollama Cybercorp (Extended Intelligence).
# Aucune étape UI manuelle pour le câblage Ollama.
#
# ── 1 VM (recommandé lab / petite prod) ──────────────────────────────
#   sudo ./scripts/deploy-ei-stack.sh
#   MODE=single SEP_MODE=portals-sekoia ./scripts/deploy-ei-stack.sh
#
# ── 2 VM ─────────────────────────────────────────────────────────────
#   # VM SEP :
#   MODE=sep ./scripts/deploy-ei-stack.sh
#   # VM Ollama :
#   MODE=ollama ./scripts/deploy-ei-stack.sh
#   # Puis sur VM SEP (après avoir noté IP + clé) :
#   MODE=link OLLAMA_BASE_URL=http://10.0.0.5:11435/v1 OC_API_KEY=xxx \
#     ./scripts/deploy-ei-stack.sh
#
# Variables :
#   MODE=single|sep|ollama|link
#   SEP_MODE=portals-sekoia|full|sekoia   (défaut portals-sekoia)
#   INSTALL_ROOT=/opt
#   FP_DIR / OC_DIR                       chemins locaux
#   SKIP_CLONE=1 / SKIP_PULL=1
#   OLLAMA_BASE_URL / OC_API_KEY          pour MODE=link
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Si lancé depuis le dépôt forensic, DIR = racine dépôt
if [[ -f "$SCRIPT_DIR/../forensic.sh" ]]; then
  FP_DIR="${FP_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
else
  FP_DIR="${FP_DIR:-/opt/forensic-plateform-max-v1}"
fi

INSTALL_ROOT="${INSTALL_ROOT:-/opt}"
OC_DIR="${OC_DIR:-${INSTALL_ROOT}/ollama-cybercorp}"
MODE="${MODE:-single}"
SEP_MODE="${SEP_MODE:-portals-sekoia}"
SKIP_CLONE="${SKIP_CLONE:-0}"
SKIP_PULL="${SKIP_PULL:-0}"
FP_REPO="${FP_REPO:-https://github.com/waraperkin/forensic-plateform-max-v1.git}"
OC_REPO="${OC_REPO:-https://github.com/waraperkin/ollama-cybercorp.git}"

_log() { echo "==> $*"; }
_die() { echo "[!] $*" >&2; exit 1; }

_ensure_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
      && docker ps >/dev/null 2>&1; then
    return 0
  fi
  _log "Installation Docker CE…"
  if [[ "$(id -u)" -eq 0 ]]; then
    curl -fsSL https://get.docker.com | sh
  else
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER" 2>/dev/null || true
  fi
  docker ps >/dev/null 2>&1 || _die "Docker OK mais session à rafraîchir (newgrp docker / reconnect SSH)"
}

_ensure_pkgs() {
  local need=()
  for c in git curl openssl python3; do
    command -v "$c" >/dev/null 2>&1 || need+=("$c")
  done
  if ((${#need[@]})); then
    _log "Paquets manquants : ${need[*]}"
    if command -v apt-get >/dev/null 2>&1; then
      if [[ "$(id -u)" -eq 0 ]]; then
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
      else
        sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
      fi
    else
      _die "Installez : ${need[*]}"
    fi
  fi
}

_clone_or_pull() {
  local url="$1" dest="$2" name="$3"
  if [[ -d "$dest/.git" ]]; then
    if [[ "$SKIP_CLONE" == "1" ]]; then
      _log "$name déjà présent — SKIP_CLONE"
      return 0
    fi
    _log "Mise à jour $name ($dest)"
    git -C "$dest" fetch --prune origin
    git -C "$dest" checkout main 2>/dev/null || git -C "$dest" checkout master
    git -C "$dest" pull --ff-only origin HEAD || git -C "$dest" pull --ff-only
  else
    _log "Clone $name → $dest"
    if [[ -e "$dest" ]] && [[ ! -d "$dest/.git" ]]; then
      _die "$dest existe mais n’est pas un dépôt git"
    fi
    mkdir -p "$(dirname "$dest")"
    if [[ -w "$(dirname "$dest")" ]]; then
      git clone --branch main "$url" "$dest" || git clone "$url" "$dest"
    else
      sudo git clone --branch main "$url" "$dest" || sudo git clone "$url" "$dest"
      sudo chown -R "$(id -u):$(id -g)" "$dest"
    fi
  fi
}

_deploy_sep() {
  _log "Déploiement SEP (mode ${SEP_MODE})"
  cd "$FP_DIR"
  chmod +x forensic.sh scripts/*.sh 2>/dev/null || true
  if [[ ! -f .env ]]; then
    bash scripts/generate-secrets.sh || true
  fi
  # sysctl OpenSearch
  if [[ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]]; then
    _log "vm.max_map_count → 262144"
    if [[ "$(id -u)" -eq 0 ]]; then
      sysctl -w vm.max_map_count=262144
      echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-opensearch.conf
    else
      sudo sysctl -w vm.max_map_count=262144
      echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf >/dev/null
    fi
  fi
  ./forensic.sh deploy "$SEP_MODE"
}

_deploy_ollama_local() {
  _log "Déploiement Ollama Cybercorp (local / même hôte)"
  _clone_or_pull "$OC_REPO" "$OC_DIR" "ollama-cybercorp"
  cd "$OC_DIR"
  chmod +x scripts/*.sh
  MODE=local \
    SKIP_PULL="$SKIP_PULL" \
    SKIP_REGISTER=1 \
    SEP_ENV="$FP_DIR/.env" \
    ./scripts/deploy.sh
  # Join + register après SEP up
  ./scripts/join-sep-network.sh || true
  SEP_ENV="$FP_DIR/.env" SEP_CP_URL="${SEP_CP_URL:-http://127.0.0.1:8901}" \
    ./scripts/register-sep-provider.sh
}

_deploy_ollama_remote() {
  _log "Déploiement Ollama Cybercorp (VM dédiée / remote)"
  _clone_or_pull "$OC_REPO" "$OC_DIR" "ollama-cybercorp"
  cd "$OC_DIR"
  chmod +x scripts/*.sh
  MODE=remote \
    SKIP_PULL="$SKIP_PULL" \
    SKIP_REGISTER=1 \
    OC_PUBLIC_HOST="${OC_PUBLIC_HOST:-}" \
    ./scripts/deploy.sh
  # Affiche credentials pour MODE=link sur l’autre VM
  # shellcheck disable=SC1091
  set -a; source .env; set +a
  cat <<EOF

╔════════════════════════════════════════════════════════════╗
║  VM Ollama prête — sur la VM SEP lancez :                  ║
║                                                            ║
║  MODE=link \\                                               ║
║    OLLAMA_BASE_URL=http://${OC_PUBLIC_HOST}:${OC_GATEWAY_PORT:-11435}/v1 \\
║    OC_API_KEY=${OC_API_KEY} \\
║    ./scripts/deploy-ei-stack.sh                            ║
║                                                            ║
║  Firewall : autoriser TCP ${OC_GATEWAY_PORT:-11435} depuis la VM SEP ║
╚════════════════════════════════════════════════════════════╝
EOF
}

_link_remote() {
  [[ -n "${OLLAMA_BASE_URL:-}" ]] || _die "OLLAMA_BASE_URL requis (ex. http://10.0.0.5:11435/v1)"
  [[ -n "${OC_API_KEY:-}" ]] || _die "OC_API_KEY requis"
  _clone_or_pull "$OC_REPO" "$OC_DIR" "ollama-cybercorp"
  cd "$OC_DIR"
  # Écrit temporairement la clé pour le script register
  if [[ ! -f .env ]]; then
    cp .env.example .env
  fi
  # shellcheck disable=SC1091
  source "$OC_DIR/scripts/lib-env.sh"
  _oc_set_env OC_API_KEY "$OC_API_KEY" "$OC_DIR/.env"
  BASE_URL="$OLLAMA_BASE_URL" \
    OC_API_KEY="$OC_API_KEY" \
    SEP_ENV="$FP_DIR/.env" \
    SEP_CP_URL="${SEP_CP_URL:-http://127.0.0.1:8901}" \
    ./scripts/register-sep-provider.sh
  _log "Lien SEP ↔ Ollama distant OK"
}

_print_done_single() {
  local host
  host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  cat <<EOF

╔════════════════════════════════════════════════════════════╗
║  Stack EI déployée (1 VM)                                  ║
║                                                            ║
║  SEP     : https://${host:-<IP>}/sekoia                    ║
║  Provider: Ollama Cybercorp (http://oc-gateway:8080/v1)    ║
║                                                            ║
║  UI → Extended Intelligence → Triage / Forensic            ║
╚════════════════════════════════════════════════════════════╝
EOF
}

main() {
  _log "deploy-ei-stack MODE=${MODE} SEP_MODE=${SEP_MODE}"
  _ensure_pkgs
  _ensure_docker

  case "$MODE" in
    single|one|1vm|all)
      _clone_or_pull "$FP_REPO" "$FP_DIR" "forensic-plateform-max-v1"
      _deploy_sep
      _deploy_ollama_local
      _print_done_single
      ;;
    sep|forensic|platform)
      _clone_or_pull "$FP_REPO" "$FP_DIR" "forensic-plateform-max-v1"
      _deploy_sep
      _log "SEP prêt. Sur la VM Ollama : MODE=ollama ./scripts/deploy-ei-stack.sh"
      _log "Puis ici : MODE=link OLLAMA_BASE_URL=… OC_API_KEY=… ./scripts/deploy-ei-stack.sh"
      ;;
    ollama|oc|ai)
      _deploy_ollama_remote
      ;;
    link|connect|register)
      _link_remote
      ;;
    *)
      _die "MODE invalide: $MODE (single|sep|ollama|link)"
      ;;
  esac
}

main "$@"
