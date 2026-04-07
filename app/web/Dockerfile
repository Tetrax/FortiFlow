FROM node:20-alpine

# su-exec pour drop de privilèges dans l'entrypoint
RUN apk add --no-cache su-exec

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
    && chmod +x /app/entrypoint.sh

EXPOSE 3737

# Entrypoint root → corrige les permissions des volumes → drop vers fortiflow
CMD ["/app/entrypoint.sh"]
