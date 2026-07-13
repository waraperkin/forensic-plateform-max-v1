#!/bin/bash
set -euo pipefail
# PostgreSQL : créer les bases secondaires si absentes (syntaxe PostgreSQL valide)
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
SELECT 'CREATE DATABASE timesketch' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'timesketch')\gexec
SELECT 'CREATE DATABASE opencti' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'opencti')\gexec
EOSQL
echo "PostgreSQL: databases timesketch + opencti OK"
