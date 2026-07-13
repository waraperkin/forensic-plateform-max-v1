#!/usr/bin/env bash
# Guide recatégorisation Palo Alto + allowlist IP pour équipe réseau.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_align_env_public_ip 2>/dev/null || true
fi

IP=$(fp_url_identity 2>/dev/null || echo "YOUR_PUBLIC_IP")
IP=$(fp_normalize_host "$IP" 2>/dev/null || echo "$IP")
ORG="${FP_SITE_ORG_NAME:-Cybercorp Forensic Platform}"

cat <<EOF

═══════════════════════════════════════════════════════════════
  Palo Alto — accès lab Forensic (IP ${IP})
═══════════════════════════════════════════════════════════════

1) ACCÈS PAR IP (recommandé lab)
   URL : https://${IP}/
   MISP : https://${IP}/misp/
   HELK : https://${IP}/helk/kibana/
   VR   : https://${IP}/velociraptor/

2) POURQUOI « Uncategorized » / « Unknown » ?
   Palo Alto (PAN-DB) catégorise surtout les DOMAINES, pas les IP nues.
   Une IP AWS sans historique reste souvent « not-resolved » / « unknown ».

3) CE QUE LE SERVEUR FAIT (déjà en place après post-start-align)
   • https://${IP}/site-info.html  — page publique descriptive (SOC/DFIR)
   • https://${IP}/robots.txt
   • https://${IP}/.well-known/security.txt
   • En-têtes X-Forensic-Platform pour identification

4) DEMANDE IT / PALO ALTO (le plus fiable pour une IP)

   A) Custom URL Category (immédiat, admin firewall)
      Objects → Custom Objects → URL Category → créer « forensic-lab »
      Ajouter : ${IP}
      Policy → URL Filtering → allow « forensic-lab » pour le groupe SOC

   B) Recatégorisation PAN-DB (plusieurs jours)
      https://urlfiltering.paloaltonetworks.com/
      URL : https://${IP}/site-info.html
      Catégorie suggérée : Computer and Internet Security
      Justification : ${ORG} — lab SOC/DFIR interne autorisé

   C) Security Policy temporaire
      Autoriser destination ${IP} TCP/443 pour profil « SOC-Analysts »

5) RÉGÉNÉRER (normalement automatique via ./forensic.sh -full-start)
   bash scripts/print-paloalto-allowlist-guide.sh

EOF
