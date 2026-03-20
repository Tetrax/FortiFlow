'use strict';

const crypto       = require('crypto');
const { EventEmitter } = require('events');

const sessions = new Map();

// ─── Limits ──────────────────────────────────────────────────────────────────
const MAX_SESSIONS   = 10;          // max concurrent sessions
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;  // 2 hours
const PURGE_INTERVAL = 10 * 60 * 1000;      // check every 10 min (was 30)

function evictOldest() {
  if (sessions.size < MAX_SESSIONS) return;
  // Find oldest session and delete it
  let oldestId = null, oldestTime = Infinity;
  for (const [id, s] of sessions) {
    if (s.createdAt < oldestTime) { oldestTime = s.createdAt; oldestId = id; }
  }
  if (oldestId) deleteSession(oldestId);
}

function createSession() {
  evictOldest();
  const id = crypto.randomBytes(16).toString('hex');
  sessions.set(id, {
    id,
    createdAt:   Date.now(),
    lastAccess:  Date.now(),
    status:      'parsing',
    data:        null,
    error:       null,
    emitter:     new EventEmitter(),
    progress:    { lines: 0, linesPerSec: 0, eta: null },
  });
  return id;
}

function getSession(id) {
  const s = sessions.get(id) || null;
  if (s) s.lastAccess = Date.now();
  return s;
}

function setSessionData(id, data) {
  const s = sessions.get(id);
  if (s) { s.data = data; s.status = 'ready'; s.lastAccess = Date.now(); }
}

function setSessionError(id, error) {
  const s = sessions.get(id);
  if (s) { s.error = error; s.status = 'error'; }
}

function deleteSession(id) {
  const s = sessions.get(id);
  if (s) {
    s.emitter.removeAllListeners();
    s.data = null;
    s.fortiConfig = null;
    sessions.delete(id);
  }
}

// ─── Memory stats (for monitoring) ───────────────────────────────────────────

function getStats() {
  return {
    sessions: sessions.size,
    maxSessions: MAX_SESSIONS,
    memoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  };
}

// ─── Periodic purge — sessions expired by TTL ────────────────────────────────
setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, s] of sessions) {
    if (s.lastAccess < cutoff) {
      s.emitter.removeAllListeners();
      s.data = null;
      s.fortiConfig = null;
      sessions.delete(id);
    }
  }
}, PURGE_INTERVAL);

module.exports = { createSession, getSession, setSessionData, setSessionError, deleteSession, getStats };
