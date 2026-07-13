FROM node:20-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY portal-it/package.json ./
RUN npm install --only=production --no-fund --no-audit
COPY portal-it/server.js ./
COPY lib/ingest-queue.js ./lib/ingest-queue.js
COPY lib/helk-connector.js ./lib/helk-connector.js
COPY lib/velociraptor-connector.js ./lib/velociraptor-connector.js
COPY lib/cors-policy.js ./lib/cors-policy.js
COPY lib/service-registry.js ./lib/service-registry.js
COPY lib/platform-secrets.js ./lib/platform-secrets.js
COPY lib/upload-limits.js ./lib/upload-limits.js
COPY lib/ui-error-log.js ./lib/ui-error-log.js
COPY portal-cert/routes/master-intakes.js ./routes/master-intakes.js
COPY portal-cert/routes/master-ingest-errors.js ./routes/master-ingest-errors.js
COPY portal-shared/ ./public/shared/
COPY portal-it/public/ ./public/
RUN mkdir -p /tmp/uploads /shared-uploads
EXPOSE 3001
HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=5 \
  CMD curl -sf http://localhost:3001/api/health || exit 1
CMD ["node", "server.js"]
