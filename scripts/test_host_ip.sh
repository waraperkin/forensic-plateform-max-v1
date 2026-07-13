#!/usr/bin/env bash
# Tests unitaires — détection IP publique (sans Docker).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib/host-ip.sh"

pass=0
fail=0

assert_eq() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
    pass=$((pass + 1))
  else
    echo "FAIL: $label (got='$got' want='$want')" >&2
    fail=$((fail + 1))
  fi
}

assert_ipv4() {
  local label="$1" got="$2"
  if _fp_is_ipv4 "$got"; then
    echo "PASS: $label"
    pass=$((pass + 1))
  else
    echo "FAIL: $label (not ipv4: '$got')" >&2
    fail=$((fail + 1))
  fi
}

# Override explicite (IP routable type EC2 — pas une IP documentation RFC 5737)
PUBLIC_HOST=203.0.113.10 FP_PUBLIC_HOST= out="$(fp_detect_public_host)"
assert_eq "PUBLIC_HOST explicite" "$out" "203.0.113.10"

# Placeholder ignoré → FP_PUBLIC_HOST
PUBLIC_HOST=192.0.2.9 FP_PUBLIC_HOST=203.0.113.11 out="$(fp_detect_public_host)"
assert_eq "FP_PUBLIC_HOST quand placeholder" "$out" "203.0.113.11"

# Routable depuis hostname -I (mock via fonction interne)
out="$(_fp_pick_routable_ipv4_from_hostname || true)"
if [ -n "$out" ]; then
  assert_ipv4 "hostname -I routable" "$out"
else
  echo "SKIP: hostname -I routable (aucune IP non-docker)"
fi

# Détection finale retourne une IPv4
PUBLIC_HOST= FP_PUBLIC_HOST= out="$(fp_detect_public_host || true)"
assert_ipv4 "fp_detect_public_host" "$out"

# Normalisation URL
assert_eq "fp_normalize_host strip https" "$(fp_normalize_host 'https://ec2.example.com/path')" "ec2.example.com"
assert_eq "fp_misp_public_base_url (IP)" "$(PUBLIC_HOST=203.0.113.10 PUBLIC_HOSTNAME= fp_misp_public_base_url)" "https://203.0.113.10/misp"
assert_eq "fp_url_identity IP mode" "$(PUBLIC_HOST=203.0.113.10 PUBLIC_HOSTNAME= fp_url_identity)" "203.0.113.10"

echo ""
echo "Résultat: $pass pass, $fail fail"
[ "$fail" -eq 0 ]
