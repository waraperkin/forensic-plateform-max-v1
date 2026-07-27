#!/usr/bin/env bash
# ==============================================================
#  api-auth-check.sh — Vérification deny-by-default des API
#  Correctif audit P-01 : tout endpoint sensible doit renvoyer
#  401 sans cookie de session fp_portal_session.
#
#  Usage :
#     ./tests/security/api-auth-check.sh [BASE_URL]
#  Ex.  : ./tests/security/api-auth-check.sh https://soc.local
#         (défaut : http://localhost)
# ==============================================================
set -u

BASE="${1:-http://localhost}"
BASE="${BASE%/}"
CURL="curl -sk -o /dev/null -w %{http_code} --max-time 10"

fail=0

check() { # check <méthode> <chemin> <codes_attendus(csv)> <libellé>
  local method="$1" path="$2" want="$3" label="$4"
  local code
  code=$($CURL -X "$method" "$BASE$path")
  if [[ ",$want," == *",$code,"* ]]; then
    printf 'OK   %-5s %-45s -> %s (%s)\n' "$method" "$path" "$code" "$label"
  else
    printf 'FAIL %-5s %-45s -> %s (attendu: %s) (%s)\n' "$method" "$path" "$code" "$want" "$label"
    fail=$((fail + 1))
  fi
}

echo "== Endpoints SENSIBLES : 401 exigé sans session =="
check GET  /cert/api/stats                 401 "stats plateforme"
check GET  /cert/api/stats/parsing         401 "stats parsing"
check GET  /cert/api/uploads               401 "liste uploads"
check GET  /cert/api/it-uploads            401 "uploads IT"
check GET  /cert/api/tokens                401 "tokens IT"
check GET  /cert/api/cases                 401 "cases"
check GET  /cert/api/credentials           401 "credentials"
check GET  /cert/api/master/intakes        401 "intakes Sekoia"
check GET  /cert/api/master/ingest_volume  401 "volumes ingest"
check GET  /cert/api/threat/sekoia/assets  401 "proxy threat Sekoia"
check GET  /cert/api/reports               401 "rapports forensic"
check GET  /cert/api/helk/status           401 "statut HELK"
check GET  /cert/api/velociraptor/clients  401 "clients Velociraptor"
check POST /cert/api/upload                401 "upload CERT"
check POST /cert/api/purge                 401 "purge données"
check POST /cert/api/tokens/generate       401 "génération token"
check POST /cert/api/reports/generate      401 "génération rapport"
check POST /it/api/upload                  401 "upload IT sans token"
check GET  /it/api/token/operations        400,401 "opérations token IT"

echo
echo "== Endpoints PUBLICS : doivent rester joignables =="
check GET  /cert/api/health                200 "health CERT"
check GET  /cert/api/it/health             200,502,503 "health IT via CERT"
check GET  /cert/api/config                200 "config upload"
check GET  /it/api/health                  200 "health IT"

echo
if [[ $fail -eq 0 ]]; then
  echo "RÉSULTAT : tous les contrôles passent."
else
  echo "RÉSULTAT : $fail contrôle(s) en échec — voir ci-dessus."
fi
exit $fail
