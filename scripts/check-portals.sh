#!/bin/bash
# Vérifie l'état réel des portails et l'absence de helmet dans les images
echo "=== Vérification des portails ==="
echo ""
echo "1. Headers HTTP du portail IT (doit PAS avoir Cross-Origin-Embedder-Policy):"
curl -si http://localhost/it/api/health 2>/dev/null | grep -iE "cross-origin|content-security|x-frame|HTTP/"
echo ""
echo "2. Test de l'endpoint health:"
curl -s http://localhost/it/api/health | python3 -m json.tool 2>/dev/null || echo "KO"
echo ""
echo "3. Version server.js dans le container:"
docker exec forensic-it-portal head -5 /app/server.js 2>/dev/null || echo "Container non accessible"
echo ""
echo "4. Grep helmet dans le container:"
docker exec forensic-it-portal grep -c "helmet" /app/server.js 2>/dev/null && \
  echo "PROBLEME: helmet trouvé dans le container!" || \
  echo "OK: pas de helmet dans le container"
echo ""
echo "5. Timesketch HTTP:"
curl -si --max-time 5 http://localhost:5000/login 2>/dev/null | head -3 || echo "Timesketch KO"
