#!/bin/sh
# Garantit que les répertoires montés en volume sont accessibles par l'user fortiflow
# (quand Docker crée automatiquement les dossiers hôtes, ils sont owned root)
chown -R fortiflow:fortiflow /sessions-cache /app/workspaces /app/uploads 2>/dev/null || true
exec su-exec fortiflow node server.js
