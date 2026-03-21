'use strict';

const crypto       = require('crypto');
const { EventEmitter } = require('events');
const fs           = require('fs');
const path         = require('path');

const sessions = new Map();

// ─── Disk cache ───────────────────────────────────────────────────────────────
const CACHE_DIR = path.join(__dirname, '../../sessions-cache');
fs.mkdirSync(CACHE_DIR, { recursive: true });

function _cachePath(id) { return path.join(CACHE_DIR, `${id}.json`); }

function _save(id) {
  const s = sessions.get(id);
  if (!s || s.status !== 'ready') return;
  try {
    const payload = JSON.stringify({
      id, createdAt: s.createdAt, lastAccess: s.lastAccess, status: s.status,
      data:        s.data        || null,
      fortiConfig: s.fortiConfig || null,
    });
    const tmp = _cachePath(id) + '.tmp';
    fs.writeFile(tmp, payload, 'utf8', (err) => {
      if (err) return;
      fs.rename(tmp, _cachePath(id), () => {});
    });
  } catch { /* ignore write errors */ }
}

function _loadAll() {
  try {
    const files = fs.readdirSync(CACHE_DIR).filter(f => f.endsWith('.json'));
    const cutoff = Date.now() - SESSION_TTL_MS;
    for (const f of files) {
      try {
        const raw = fs.readFileSync(path.join(CACHE_DIR, f), 'utf8');
        const payload = JSON.parse(raw);
        if (!payload.id || payload.lastAccess < cutoff) {
          fs.unlink(path.join(CACHE_DIR, f), () => {});
          continue;
        }
        sessions.set(payload.id, {
          id:          payload.id,
          createdAt:   payload.createdAt,
          lastAccess:  payload.lastAccess,
          status:      payload.status,
          data:        payload.data,
          fortiConfig: payload.fortiConfig,
          error:       null,
          emitter:     new EventEmitter(),
          progress:    { lines: 0, linesPerSec: 0, eta: null },
        });
      } catch { /* skip corrupt files */ }
    }
  } catch { /* ignore if dir unreadable */ }
}

// ─── Limits ──────────────────────────────────────────────────────────────────
const MAX_SESSIONS   = 10;
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;  // 2 hours
const PURGE_INTERVAL = 10 * 60 * 1000;

function evictOldest() {
  if (sessions.size < MAX_SESSIONS) return;
  let oldestId = null, oldestTime = Infinity;
  for (const [id, s] of sessions) {
    if (s.lastAccess < oldestTime) { oldestTime = s.lastAccess; oldestId = id; }
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
  if (s) { s.data = data; s.status = 'ready'; s.lastAccess = Date.now(); _save(id); }
}

function setFortiConfig(id, fortiConfig) {
  const s = sessions.get(id);
  if (s) { s.fortiConfig = fortiConfig; _save(id); }
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
  try { fs.unlink(_cachePath(id), () => {}); } catch { /* ignore */ }
}

// ─── Memory stats ─────────────────────────────────────────────────────────────
function getStats() {
  return {
    sessions: sessions.size,
    maxSessions: MAX_SESSIONS,
    memoryMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
  };
}

// ─── Periodic purge ───────────────────────────────────────────────────────────
setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, s] of sessions) {
    if (s.lastAccess < cutoff) {
      s.emitter.removeAllListeners();
      s.data = null;
      s.fortiConfig = null;
      sessions.delete(id);
      try { fs.unlink(_cachePath(id), () => {}); } catch { /* ignore */ }
    }
  }
}, PURGE_INTERVAL);

// ─── Load persisted sessions on startup ───────────────────────────────────────
_loadAll();

module.exports = { createSession, getSession, setSessionData, setFortiConfig, setSessionError, deleteSession, getStats };
