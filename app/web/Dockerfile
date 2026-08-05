FROM node:22-alpine

# Runtime TLS tooling: OpenSSL validates/imports PFX and Python runs certctl.
RUN apk add --no-cache openssl python3 su-exec

# Non-root user
RUN addgroup -S fortiflow && adduser -S fortiflow -G fortiflow

WORKDIR /app

# Dependencies first (layer caching)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Application source
COPY . .

# Répertoires persistables
# - /sessions-cache : cache sessions
# - /app/workspaces : historique des workspaces
# - /app/uploads    : fichiers temporaires
RUN mkdir -p /sessions-cache /app/workspaces /app/uploads \
    && chown -R fortiflow:fortiflow /app /sessions-cache \
    && chmod +x /app/entrypoint.sh /app/scripts/fortiflow-certctl \
    && ln -s /app/scripts/fortiflow-certctl /usr/local/bin/fortiflow-certctl

EXPOSE 3737

# Entrypoint root → corrige les permissions des volumes → drop vers fortiflow
CMD ["/app/entrypoint.sh"]
