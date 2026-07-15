#!/bin/bash
set -eu
PASS="${MISP_ADMIN_PASSWORD:-c5TI5EPFHpeuYie2m6MIjZ8zXiCbXIJq}"
EMAIL="${MISP_ADMIN_EMAIL:-admin@forensic.local}"
rm -f /tmp/mc /tmp/login.html /tmp/post.html
curl -sk -c /tmp/mc -b /tmp/mc \
  -H "Host: localhost:8443" -H "X-Forwarded-Proto: https" \
  "http://127.0.0.1/misp/users/login" -o /tmp/login.html
TOKEN=$(grep -oP 'name="data\[_Token\]\[key\]"[^>]*value="\K[^"]+' /tmp/login.html || true)
FIELDS=$(grep -oP 'name="data\[_Token\]\[fields\]"[^>]*value="\K[^"]*' /tmp/login.html || true)
echo "token=${TOKEN:0:8}... fields=$FIELDS"
CODE=$(curl -sk -c /tmp/mc -b /tmp/mc \
  -H "Host: localhost:8443" -H "X-Forwarded-Proto: https" \
  -H "Referer: https://localhost:8443/misp/users/login" \
  -X POST "http://127.0.0.1/misp/users/login" \
  --data-urlencode "_method=POST" \
  --data-urlencode "data[_Token][key]=$TOKEN" \
  --data-urlencode "data[_Token][fields]=$FIELDS" \
  --data-urlencode "data[_Token][unlocked]=" \
  --data-urlencode "data[User][email]=$EMAIL" \
  --data-urlencode "data[User][password]=$PASS" \
  -w "%{http_code}" -o /tmp/post.html)
echo "POST HTTP $CODE"
grep -ioE 'invalid|error|blackhole|events' /tmp/post.html | head -5 || true
curl -sk -b /tmp/mc -H "Host: localhost:8443" -H "X-Forwarded-Proto: https" \
  "http://127.0.0.1/misp/events/index" -w "\nEVENTS:%{http_code} %{url_effective}\n" -o /dev/null
