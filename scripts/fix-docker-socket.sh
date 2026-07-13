#!/usr/bin/env sh
# Corrige les permissions du socket Docker (groupe docker, accès rw).
# À exécuter une fois en root : sudo ./scripts/fix-docker-socket.sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "Exécuter avec sudo: sudo $0" >&2
  exit 1
fi
chown root:docker /var/run/docker.sock
chmod 660 /var/run/docker.sock
# Ajouter l'utilisateur courant au groupe docker si appelé via sudo
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  usermod -aG docker "$SUDO_USER" 2>/dev/null || true
  echo "Utilisateur $SUDO_USER ajouté au groupe docker (reconnexion session requise)."
fi
ls -la /var/run/docker.sock
echo "OK — tester : docker ps"
