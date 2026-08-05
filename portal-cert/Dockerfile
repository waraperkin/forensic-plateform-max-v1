FROM node:20-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY portal-cert/package.json ./
RUN npm install --only=production --no-fund --no-audit
COPY portal-cert/server.js ./
COPY lib/ingest-queue.js ./lib/ingest-queue.js
COPY lib/helk-connector.js ./lib/helk-connector.js
COPY lib/velociraptor-connector.js ./lib/velociraptor-connector.js
COPY lib/global-health.js ./lib/global-health.js
COPY lib/service-registry.js ./lib/service-registry.js
COPY lib/cors-policy.js ./lib/cors-policy.js
COPY lib/platform-secrets.js ./lib/platform-secrets.js
COPY lib/credentials-harvest.js ./lib/credentials-harvest.js
COPY lib/bridge-response.js ./lib/bridge-response.js
COPY lib/ui-error-log.js ./lib/ui-error-log.js
COPY lib/upload-limits.js ./lib/upload-limits.js
COPY portal-cert/lib/master-routes.js ./lib/master-routes.js
COPY portal-cert/lib/os-intakes-scan.js ./lib/os-intakes-scan.js
COPY portal-cert/routes/master-intakes.js ./routes/master-intakes.js
COPY portal-cert/routes/master-ingest-errors.js ./routes/master-ingest-errors.js
COPY portal-cert/routes/master-ingest-meta.js ./routes/master-ingest-meta.js
COPY portal-cert/routes/cti-routes.js ./routes/cti-routes.js
COPY portal-cert/routes/incident-routes.js ./routes/incident-routes.js
COPY portal-cert/routes/playbook-routes.js ./routes/playbook-routes.js
COPY portal-cert/routes/alert-intake-routes.js ./routes/alert-intake-routes.js
COPY portal-cert/routes/incident-core-routes.js ./routes/incident-core-routes.js
COPY portal-cert/routes/ioc-enrich-routes.js ./routes/ioc-enrich-routes.js
COPY portal-cert/routes/case-routes.js ./routes/case-routes.js
# Tout module require() par server.js DOIT figurer ici : un COPY oublie fait
# crasher le portail au demarrage (precedent identique cote control-plane, cf.
# commit e02b3c8 et volumetry.py).
COPY portal-cert/routes/similarity-routes.js ./routes/similarity-routes.js
COPY portal-cert/routes/psoar-hub-routes.js ./routes/psoar-hub-routes.js
COPY portal-cert/lib/psoar-storage.js ./lib/psoar-storage.js
COPY portal-cert/routes/helk-routes.js ./routes/helk-routes.js
COPY portal-cert/routes/velociraptor-routes.js ./routes/velociraptor-routes.js
COPY portal-cert/routes/forensic-report-routes.js ./routes/forensic-report-routes.js
COPY portal-cert/lib/forensic-report-engine.js ./lib/forensic-report-engine.js
COPY portal-cert/lib/forensic-report-llm.js ./lib/forensic-report-llm.js
COPY portal-cert/routes/global-health-routes.js ./routes/global-health-routes.js
COPY portal-cert/routes/service-routes.js ./routes/service-routes.js
COPY portal-cert/lib/auth-store.js ./lib/auth-store.js
COPY portal-cert/lib/auth-session.js ./lib/auth-session.js
COPY portal-cert/lib/auth-routes.js ./lib/auth-routes.js
COPY portal-cert/lib/auth-mount.js ./lib/auth-mount.js
COPY portal-cert/lib/credentials-sync.js ./lib/credentials-sync.js
COPY portal-cert/lib/platform-overview.js ./lib/platform-overview.js
COPY portal-cert/lib/audit-log.js ./lib/audit-log.js
COPY portal-cert/lib/threat-platforms-routes.js ./lib/threat-platforms-routes.js
COPY portal-cert/lib/threat-v2-proxy.js ./lib/threat-v2-proxy.js
COPY portal-shared/ ./public/shared/
COPY scripts/minify-portal-assets.sh /tmp/minify-portal-assets.sh
RUN sh /tmp/minify-portal-assets.sh 2>/dev/null || true
COPY portal-cert/public/ ./public/
RUN mkdir -p /tmp/uploads /shared-uploads /app/ssl
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=5 \
  CMD curl -sf http://localhost:3000/api/health || exit 1
CMD ["node", "server.js"]
