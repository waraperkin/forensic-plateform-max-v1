#!/usr/bin/env bash
# Pages et métadonnées publiques pour identification du site (crawlers / Palo Alto URL Filtering).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATIC="$ROOT/config/nginx/static"
ORG="${FP_SITE_ORG_NAME:-Cybercorp Forensic Platform}"
DESC="${FP_SITE_DESCRIPTION:-Private SOC and digital forensics training laboratory. SIEM, threat intelligence, incident response, and security operations center tools for authorized cybersecurity professionals.}"
CONTACT="${FP_SITE_CONTACT_EMAIL:-security@forensic.local}"

if [ -f "$ROOT/scripts/lib/host-ip.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/scripts/lib/host-ip.sh"
  fp_align_env_public_ip 2>/dev/null || true
fi

IP=$(fp_url_identity 2>/dev/null || echo "localhost")
IP=$(fp_normalize_host "$IP" 2>/dev/null || echo "$IP")
BASE="https://${IP}"

mkdir -p "$STATIC/.well-known"

cat > "$STATIC/robots.txt" <<EOF
# Forensic Minimal Platform — allow categorization crawlers
User-agent: *
Allow: /
Allow: /site-info.html
Allow: /.well-known/security.txt
Sitemap: ${BASE}/site-info.html
EOF

cat > "$STATIC/.well-known/security.txt" <<EOF
Contact: mailto:${CONTACT}
Preferred-Languages: fr, en
Canonical: ${BASE}/
Policy: ${BASE}/site-info.html
Acknowledgments: ${ORG} — authorized internal SOC/DFIR lab only
EOF

cat > "$STATIC/site-info.html" <<EOF
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="${DESC}">
<meta name="keywords" content="cybersecurity, SOC, SIEM, digital forensics, incident response, threat intelligence, security operations center, computer security, DFIR, forensic analysis, security training, enterprise security, information security">
<meta name="author" content="${ORG}">
<meta name="classification" content="Business, Computer Security, Education, Information Technology">
<meta name="category" content="Computer and Internet Security">
<meta name="robots" content="index,follow">
<title>${ORG} — SOC / DFIR Laboratory</title>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "WebApplication",
  "name": "${ORG}",
  "description": "${DESC}",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "Web",
  "url": "${BASE}/",
  "audience": { "@type": "Audience", "audienceType": "Cybersecurity professionals" },
  "keywords": "SOC, SIEM, DFIR, threat intelligence, incident response, digital forensics"
}
</script>
<style>
body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.6;color:#1a1a2e;background:#f8fafc}
h1{color:#0f3460} .tag{display:inline-block;background:#e8f4fc;color:#0f3460;padding:.2rem .6rem;border-radius:4px;margin:.2rem;font-size:.85rem}
footer{margin-top:2rem;font-size:.9rem;color:#555}
</style>
</head>
<body>
<h1>${ORG}</h1>
<p><strong>Plateforme interne SOC / DFIR</strong> — laboratoire de formation et d'analyse pour professionnels de la cybersécurité autorisés.</p>
<p>${DESC}</p>
<h2>Services</h2>
<p>
<span class="tag">SIEM</span>
<span class="tag">Threat Intelligence</span>
<span class="tag">Digital Forensics</span>
<span class="tag">Incident Response</span>
<span class="tag">Security Operations Center</span>
<span class="tag">Log Analysis</span>
<span class="tag">Malware Analysis</span>
</p>
<h2>Accès</h2>
<p>Point d'entrée : <a href="${BASE}/">${BASE}/</a> (réseau autorisé uniquement).</p>
<h2>Contact sécurité</h2>
<p><a href="mailto:${CONTACT}">${CONTACT}</a></p>
<footer>
<p>Classification suggérée : Computer and Internet Security · Business and Economy · Training.</p>
<p>© ${ORG} — usage interne / lab autorisé.</p>
</footer>
</body>
</html>
EOF

echo "[setup-site-identity] Static files → $STATIC (base ${BASE})"
