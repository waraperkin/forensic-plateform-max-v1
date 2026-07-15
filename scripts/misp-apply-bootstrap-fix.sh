#!/bin/sh
# No-op — les patches bootstrap.php corrompaient MISP (PHP visible dans le navigateur).
# MISP.baseurl suffit derrière nginx /misp/.
echo "[misp-bootstrap-fix] skip (MISP.baseurl via cake admin uniquement)"
exit 0
