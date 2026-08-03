'use strict';

// ─── Décisions de flux FortiOS ──────────────────────────────────────────────
// Ensemble canonique unique — toute modification ici impacte le parsing,
// l'analyse et la certification de déploiement.

const ALLOW_ACTIONS = new Set([
  'accept', 'allow', 'allowed', 'pass', 'start', 'close', 'timeout',
  'client-rst', 'server-rst', 'ip-conn',
]);

const DENY_ACTIONS = new Set([
  'deny', 'denied', 'drop', 'dropped', 'block', 'blocked',
  'reject', 'rejected', 'violation',
]);

// Actions terminales de session FortiOS — indiquent la fin d'une session
// acceptée et portent les compteurs définitifs (bytes, packets, service).
const TERMINAL_SESSION_ACTIONS = new Set(['close', 'timeout', 'client-rst', 'server-rst']);

module.exports = {
  ALLOW_ACTIONS,
  DENY_ACTIONS,
  TERMINAL_SESSION_ACTIONS,
};
