# Certificats TLS CYBERCORP

## Arborescence

```
nginx/certs/
├── ca/
│   ├── ca.crt          # Autorité de certification racine (à faire confiance)
│   └── ca.key          # Clé privée CA (ne pas exposer)
└── server/
    ├── server.crt      # Certificat serveur (SAN: 192.0.2.9)
    ├── server.key      # Clé privée serveur
    └── server.csr      # Demande de signature
```

## Génération

```bash
bash scripts/generate_tls_all.sh
# ou séparément :
bash scripts/generate_ca.sh
bash scripts/generate_server_cert.sh
```

## Confiance client (navigateur / curl)

```bash
# Linux — magasin système (recommandé, nécessite sudo)
sudo bash scripts/install_ca_system.sh

# NSS utilisateur (Chromium)
bash scripts/trust_ca_chromium.sh
# Puis redémarrer Cursor
```

## Déploiement full-auto

```bash
# Avec mot de passe sudo (optionnel)
SUDO_PASSWORD='***' bash scripts/apply_tls_full.sh

# Ou interactif
bash scripts/apply_tls_full.sh
```

## Validation

```bash
curl -v https://192.0.2.9/login.html
# Attendu : SSL certificate verify ok
```

Nginx utilise ces certificats via `docker-compose.yml` :
`./nginx/certs:/etc/nginx/certs`
