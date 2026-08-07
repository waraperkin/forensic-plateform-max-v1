#!/usr/bin/env bash
# Bootstrap machine vierge → SEP + Ollama (Extended Intelligence).
# Peut être téléchargé puis exécuté, ou lancé depuis le dépôt.
#
# 1 VM :
#   curl -fsSL https://raw.githubusercontent.com/waraperkin/forensic-plateform-max-v1/main/scripts/bootstrap-ei.sh \
#     | sudo bash -s -- single
#
# 2 VM — SEP :
#   curl … | sudo bash -s -- sep
#
# 2 VM — Ollama :
#   curl -fsSL https://raw.githubusercontent.com/waraperkin/ollama-cybercorp/main/scripts/bootstrap-vm.sh \
#     | sudo bash
#
# Args : single|sep|ollama|link   (défaut single)
set -euo pipefail

MODE="${1:-${MODE:-single}}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt}"
FP_DIR="${FP_DIR:-${INSTALL_ROOT}/forensic-plateform-max-v1}"
FP_REPO="${FP_REPO:-https://github.com/waraperkin/forensic-plateform-max-v1.git}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] Préférez root/sudo pour une VM propre (Docker, sysctl, /opt)."
  echo "    Relance : sudo MODE=${MODE} $0 $*"
fi

export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq git curl ca-certificates openssl python3 jq 2>/dev/null || true
fi

if [[ ! -d "$FP_DIR/.git" ]]; then
  mkdir -p "$INSTALL_ROOT"
  git clone --branch main "$FP_REPO" "$FP_DIR" || git clone "$FP_REPO" "$FP_DIR"
fi

chmod +x "$FP_DIR/scripts/"*.sh "$FP_DIR/forensic.sh" 2>/dev/null || true
export MODE INSTALL_ROOT FP_DIR
exec "$FP_DIR/scripts/deploy-ei-stack.sh"
