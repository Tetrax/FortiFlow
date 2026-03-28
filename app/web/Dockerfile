FROM node:20-alpine

# Non-root user
RUN addgroup -S fortiflow && adduser -S fortiflow -G fortiflow

WORKDIR /app

# Dependencies first (layer caching)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Application source
COPY . .

# Répertoires persistables
# - /sessions-cache : cache sessions (store.js remonte de 2 niveaux depuis lib/)
# - /app/workspaces : historique des workspaces
# - /app/uploads    : fichiers temporaires (nettoyés automatiquement)
RUN mkdir -p /sessions-cache /app/workspaces /app/uploads \
    && chown -R fortiflow:fortiflow /app /sessions-cache

USER fortiflow

EXPOSE 3737

CMD ["node", "server.js"]
