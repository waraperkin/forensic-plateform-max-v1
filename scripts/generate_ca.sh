#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p nginx/certs/ca

openssl genrsa -out nginx/certs/ca/ca.key 4096

openssl req -x509 -new -nodes \
  -key nginx/certs/ca/ca.key \
  -sha256 -days 3650 \
  -subj "/C=FR/ST=IDF/L=Paris/O=CyberCorp/OU=SOC/CN=CyberCorp-Root-CA" \
  -out nginx/certs/ca/ca.crt

echo "CA générée : nginx/certs/ca/ca.crt"
