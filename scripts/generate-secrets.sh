#!/usr/bin/env bash
# generate-secrets.sh — Renseigne les secrets vides du .env local.
#
# - Ne touche JAMAIS aux valeurs déjà présentes.
# - Le .env reste local (ignoré par git) — aucun secret n'est commité.
# - Usage : bash scripts/generate-secrets.sh [chemin/.env]
set -euo pipefail

ENV_FILE="${1:-.env}"
if [ ! -f "$ENV_FILE" ]; then
  if [ -f .env.example ]; then
    cp .env.example "$ENV_FILE"
    echo "[generate-secrets] $ENV_FILE créé depuis .env.example"
  else
    echo "[generate-secrets] ERREUR: .env.example introuvable" >&2
    exit 1
  fi
fi

rand_hex()  { openssl rand -hex "${1:-24}"; }
rand_b64()  { openssl rand -base64 "${1:-24}" | tr -d '\n'; }
fernet_key() {
  # Clé Fernet = 32 octets aléatoires en base64 urlsafe
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
  else
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'
  fi
}

# fill_secret VAR GENERATOR — remplit VAR si vide dans $ENV_FILE
fill_secret() {
  local var="$1" gen="$2" cur
  cur=$(grep -E "^${var}=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)
  if [ -n "$cur" ]; then
    return 0
  fi
  local val
  val=$($gen)
  if grep -qE "^${var}=" "$ENV_FILE"; then
    # Remplacement de la ligne vide (portable GNU/BSD sed via fichier tmp)
    local tmp; tmp=$(mktemp)
    awk -v v="$var" -v val="$val" 'BEGIN{FS=OFS="="} $1==v {$2=val} {print}' "$ENV_FILE" > "$tmp"
    mv "$tmp" "$ENV_FILE"
  else
    echo "${var}=${val}" >> "$ENV_FILE"
  fi
  echo "[generate-secrets] $var généré"
}

fill_secret CERT_PORTAL_SECRET   "rand_hex 32"
fill_secret IT_PORTAL_SECRET     "rand_hex 32"
fill_secret PORTAL_SESSION_SECRET "rand_hex 32"
fill_secret PORTAL_ADMIN_PASSWORD "rand_b64 18"
fill_secret INTERNAL_API_TOKEN   "rand_hex 32"
fill_secret SEKOIA_SECRETS_KEY   fernet_key

# Garde-fou : une SEKOIA_SECRETS_KEY héritée d'une ancienne version (format non
# Fernet) casse le store chiffré du control-plane ("SEKOIA_SECRETS_KEY invalide").
# On valide le format (base64 urlsafe → 32 octets) et on régénère si invalide.
_fernet_valid() {
  local k="$1"
  [ -n "$k" ] || return 1
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import base64,sys; k=sys.argv[1].encode(); sys.exit(0 if len(k)==44 and len(base64.urlsafe_b64decode(k))==32 else 1)" "$k" 2>/dev/null
  else
    # Fallback sans python : 44 car. base64 urlsafe terminé par '='
    [[ ${#k} -eq 44 && "$k" =~ ^[A-Za-z0-9_-]{43}=$ ]]
  fi
}
_cur_sk=$(grep -E "^SEKOIA_SECRETS_KEY=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)
if ! _fernet_valid "$_cur_sk"; then
  _new_sk=$(fernet_key)
  _tmp=$(mktemp)
  awk -v val="$_new_sk" 'BEGIN{FS=OFS="="} $1=="SEKOIA_SECRETS_KEY" {$2=val} {print}' "$ENV_FILE" > "$_tmp"
  mv "$_tmp" "$ENV_FILE"
  echo "[generate-secrets] SEKOIA_SECRETS_KEY invalide (format Fernet attendu) — régénérée"
fi

fill_secret REDIS_PASSWORD       "rand_b64 24"
fill_secret POSTGRES_PASSWORD    "rand_b64 24"
fill_secret MYSQL_ROOT_PASSWORD  "rand_b64 24"
fill_secret MYSQL_PASSWORD       "rand_b64 24"
fill_secret MINIO_ROOT_PASSWORD  "rand_b64 24"
fill_secret GRAFANA_ADMIN_PASSWORD "rand_b64 18"
fill_secret THEHIVE_SECRET       "rand_hex 32"

# Garde-fou : TheHive 5.3 exige un login email ("expected valid email address").
# Un THEHIVE_ADMIN_LOGIN hérité sans '@' (ex. "admin") casse le provisionnement
# de l'admin .env et le login portail (audit V02) → migration automatique.
_cur_th=$(grep -E "^THEHIVE_ADMIN_LOGIN=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)
if [ -n "$_cur_th" ] && [[ "$_cur_th" != *@* ]]; then
  _new_th="admin@forensic.local"
  _tmp=$(mktemp)
  awk -v val="$_new_th" 'BEGIN{FS=OFS="="} $1=="THEHIVE_ADMIN_LOGIN" {$2=val} {print}' "$ENV_FILE" > "$_tmp"
  mv "$_tmp" "$ENV_FILE"
  echo "[generate-secrets] THEHIVE_ADMIN_LOGIN non-email ('$_cur_th') — migré vers $_new_th"
fi
fill_secret CORTEX_SECRET        "rand_hex 32"
fill_secret MISP_ENCRYPTION_KEY  "rand_hex 32"
fill_secret OPENCTI_ENCRYPTION_KEY "rand_hex 32"
fill_secret TIMESKETCH_SECRET_KEY "rand_hex 32"
fill_secret TIMESKETCH_PASSWORD  "rand_b64 18"

chmod 600 "$ENV_FILE" 2>/dev/null || true
echo "[generate-secrets] Terminé — $ENV_FILE (chmod 600). Aucune valeur existante modifiée."
