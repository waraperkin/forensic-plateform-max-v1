#!/usr/bin/env bash
# Génère server.config.yaml + client.config.yaml pour le déploiement Docker forensic-minimal.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VROOT="$(cd "$ROOT/.." && pwd)"
_preserve_https_port="${FP_HTTPS_PORT:-}"
_preserve_public_host="${PUBLIC_HOST:-}"
if [ -f "$VROOT/config/local-ports.env" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$VROOT/config/local-ports.env"
  set +a
  [ -n "$_preserve_https_port" ] && FP_HTTPS_PORT="$_preserve_https_port"
  [ -n "$_preserve_public_host" ] && PUBLIC_HOST="$_preserve_public_host"
fi
BIN="${VR_BIN:-/tmp/velociraptor}"
if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
elif [ -f "$ROOT/../scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/../scripts/lib/host-ip.sh"
  fp_load_env_public_host 2>/dev/null || true
fi
PUBLIC_HOST="${PUBLIC_HOST:-$(fp_url_identity 2>/dev/null || fp_detect_public_ip 2>/dev/null || echo "localhost")}"
PUBLIC_HOST=$(fp_normalize_host "$PUBLIC_HOST" 2>/dev/null || echo "$PUBLIC_HOST")
VR_PUBLIC_ORIGIN="${VR_PUBLIC_ORIGIN:-$(fp_public_https_origin 2>/dev/null || echo "https://${PUBLIC_HOST}")}"
DATA_DIR="/data"

VR_TAG="${VR_VERSION:-v0.76.6}"
VR_GEN_IMAGE="${FP_VR_GEN_IMAGE:-forensic-velociraptor-gen:latest}"

_vr_bin_ready() {
  [[ -x "$BIN" ]] && "$BIN" version >/dev/null 2>&1
}

_vr_ensure_bin() {
  if _vr_bin_ready; then
    return 0
  fi
  echo "Téléchargement du binaire Velociraptor…" >&2
  curl -sL "https://github.com/Velocidex/velociraptor/releases/download/${VR_TAG}/velociraptor-${VR_TAG}-linux-amd64" \
    -o "$BIN"
  chmod +x "$BIN"
  _vr_bin_ready
}

_vr_ensure_docker_gen() {
  if docker image inspect "$VR_GEN_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  echo "Construction image Docker génération Velociraptor ($VR_GEN_IMAGE)…" >&2
  docker build -t "$VR_GEN_IMAGE" -f - "$ROOT" <<DOCKERFILE
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \\
  && curl -sL "https://github.com/Velocidex/velociraptor/releases/download/${VR_TAG}/velociraptor-${VR_TAG}-linux-amd64" \\
    -o /usr/local/bin/velociraptor && chmod +x /usr/local/bin/velociraptor \\
  && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/local/bin/velociraptor"]
DOCKERFILE
}

_vr_workdir() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$ROOT"
  elif pwd -W >/dev/null 2>&1; then
    (cd "$ROOT" && pwd -W)
  else
    echo "$ROOT"
  fi
}

_vr_use_docker() {
  ! _vr_ensure_bin
}

_vr_map_args() {
  local out=()
  for arg in "$@"; do
    if [[ "$arg" == "$ROOT/"* ]]; then
      out+=("/work/${arg#$ROOT/}")
    elif [[ "$arg" == "$ROOT" ]]; then
      out+=("/work")
    else
      out+=("$arg")
    fi
  done
  printf '%s\n' "${out[@]}"
}

_vr_run() {
  if _vr_ensure_bin; then
    "$BIN" "$@"
    return
  fi
  echo "Binaire Linux non exécutable sur cet hôte — fallback Docker ($VR_GEN_IMAGE)…" >&2
  _vr_ensure_docker_gen
  local host_root mapped=()
  host_root="$(_vr_workdir)"
  while IFS= read -r line; do mapped+=("$line"); done < <(_vr_map_args "$@")
  MSYS_NO_PATHCONV=1 docker run --rm -v "${host_root}:/work" -w //work "$VR_GEN_IMAGE" "${mapped[@]}"
}

mkdir -p "$ROOT/config" "$ROOT/clients" "$ROOT/data"

# Écriture atomique : ne JAMAIS tronquer une config valide existante si la
# génération échoue (binaire + fallback Docker indisponibles, réseau coupé…).
_vr_run config generate > "$ROOT/config/server.config.yaml.tmp"
if [ ! -s "$ROOT/config/server.config.yaml.tmp" ]; then
  echo "ERREUR: génération config Velociraptor vide (binaire + Docker indisponibles)" >&2
  rm -f "$ROOT/config/server.config.yaml.tmp"
  exit 1
fi
mv -f "$ROOT/config/server.config.yaml.tmp" "$ROOT/config/server.config.yaml"

python3 - "$ROOT/config/server.config.yaml" "$VR_PUBLIC_ORIGIN" "$DATA_DIR" <<'PY'
import sys
import yaml

path, origin, data_dir = sys.argv[1:4]
origin = origin.replace("\r", "").replace("\n", "").strip().rstrip("/")
host = origin.split("://", 1)[-1]
with open(path, encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}

cfg.setdefault("Client", {})["server_urls"] = [
    f"{origin}/velociraptor/",
]
# Port 8001 direct (agents) — optionnel ; désactivé par défaut derrière nginx seul (AWS)
if __import__("os").environ.get("FP_VR_DIRECT_FRONTEND", "").lower() in ("1", "true", "yes"):
    cfg["Client"]["server_urls"].insert(0, f"{origin.replace(':443', '')}:8001/")
cfg["GUI"]["bind_address"] = "0.0.0.0"
cfg["GUI"]["bind_port"] = 8000
cfg["GUI"]["use_plain_http"] = True
cfg["Frontend"]["bind_address"] = "0.0.0.0"
cfg["Frontend"]["bind_port"] = 8001
cfg["Frontend"]["hostname"] = "127.0.0.1" if __import__("os").environ.get("FP_VR_NGINX_ONLY", "1") == "1" else host.split(":")[0]
if __import__("os").environ.get("FP_VR_NGINX_ONLY", "1") == "1":
    cfg["Frontend"]["use_plain_http"] = True
cfg["API"]["bind_address"] = "0.0.0.0"
cfg["API"]["bind_port"] = 8002
# public_url — VR 0.76+ avec base_path /velociraptor (redirect relatif → /velociraptor/app/index.html)
cfg.setdefault("GUI", {})["public_url"] = f"{origin}/velociraptor/app/index.html"
trusted_host = host
trusted = [trusted_host]
if ":" in trusted_host:
    trusted.append(trusted_host.split(":", 1)[0])
else:
    trusted.append(trusted_host)
cfg.setdefault("GUI", {})["trusted_origins"] = list(dict.fromkeys(trusted))
cfg.setdefault("GUI", {})["base_path"] = "/velociraptor"
cfg.setdefault("Frontend", {})["base_path"] = "/velociraptor"
cfg.setdefault("Datastore", {})
cfg["Datastore"]["location"] = data_dir
cfg["Datastore"]["filestore_directory"] = data_dir

with open(path, "w", encoding="utf-8") as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)

print(f"Config écrite: {path}")
PY

_vr_run --config "$ROOT/config/server.config.yaml" config client > "$ROOT/clients/client.config.yaml.tmp"
if [ -s "$ROOT/clients/client.config.yaml.tmp" ]; then
  mv -f "$ROOT/clients/client.config.yaml.tmp" "$ROOT/clients/client.config.yaml"
else
  rm -f "$ROOT/clients/client.config.yaml.tmp"
  echo "WARN: client.config.yaml non généré (config serveur indisponible)" >&2
fi
echo "api.config.yaml: générer via scripts/helk_velociraptor_master_setup.sh après démarrage du serveur"

echo "Configuration Velociraptor prête dans $ROOT/config/"
