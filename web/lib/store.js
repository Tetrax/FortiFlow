'use strict';

const crypto       = require('crypto');
const { EventEmitter } = require('events');

const sessions = new Map();

function createSession() {
  const id = crypto.randomBytes(16).toString('hex');
  sessions.set(id, {
    id,
    createdAt: Date.now(),
    status:    'parsing',
    data:      null,
    error:     null,
    emitter:   new EventEmitter(),
    progress:  { lines: 0, linesPerSec: 0, eta: null },
  });
  return id;
}

function getSession(id) {
  return sessions.get(id) || null;
}

function setSessionData(id, data) {
  const s = sessions.get(id);
  if (s) { s.data = data; s.status = 'ready'; }
}

function setSessionError(id, error) {
  const s = sessions.get(id);
  if (s) { s.error = error; s.status = 'error'; }
}

function deleteSession(id) {
  const s = sessions.get(id);
  if (s) {
    s.emitter.removeAllListeners();
    sessions.delete(id);
  }
}

// Purge sessions older than 2 hours
setInterval(() => {
  const cutoff = Date.now() - 2 * 60 * 60 * 1000;
  for (const [id, s] of sessions) {
    if (s.createdAt < cutoff) {
      s.emitter.removeAllListeners();
      sessions.delete(id);
    }
  }
}, 30 * 60 * 1000);

module.exports = { createSession, getSession, setSessionData, setSessionError, deleteSession };
