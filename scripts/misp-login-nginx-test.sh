#!/bin/bash
set -eu
PASS=$(grep '^MISP_ADMIN_PASSWORD=' /tmp/.env 2>/dev/null | cut -d= -f2- || echo "c5TI5EPFHpeuYie2m6MIjZ8zXiCbXIJq")
EMAIL="admin@forensic.local"
BASE="${MISP_NGINX_URL:-https://host.docker.internal:8443/misp}"
rm -f /tmp/mc2 /tmp/login2.html /tmp/post2.html
curl -sk -c /tmp/mc2 -b /tmp/mc2 "$BASE/users/login" -o /tmp/login2.html
TOKEN=$(grep -oP 'name="data\[_Token\]\[key\]"[^>]*value="\K[^"]+' /tmp/login2.html)
FIELDS=$(grep -oP 'name="data\[_Token\]\[fields\]"[^>]*value="\K[^"]*' /tmp/login2.html)
CODE=$(curl -sk -c /tmp/mc2 -b /tmp/mc2 \
  -H "Referer: $BASE/users/login" \
  -X POST "$BASE/users/login" \
  --data-urlencode "_method=POST" \
  --data-urlencode "data[_Token][key]=$TOKEN" \
  --data-urlencode "data[_Token][fields]=$FIELDS" \
  --data-urlencode "data[_Token][unlocked]=" \
  --data-urlencode "data[User][email]=$EMAIL" \
  --data-urlencode "data[User][password]=$PASS" \
  -w "%{http_code}" -o /tmp/post2.html)
echo "via-nginx POST HTTP $CODE"
curl -sk -b /tmp/mc2 "$BASE/events/index" -w "\nEVENTS:%{http_code}\n" -o /dev/null
