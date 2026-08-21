'use strict';

const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createSession,
  deleteSession,
  getSession,
  getSessionCachePath,
  setNetworkDecisions,
  setSessionData,
} = require('../lib/store');

test('network decisions persist in the session cache and survive ordinary session reads', async () => {
  const sessionId = createSession();
  const decisions = {
    'P-00001||source': {
      schemaVersion: 1,
      decisionId: 'NUD-test',
      policyId: 'P-00001',
      side: 'source',
      status: 'accepted',
    },
  };
  try {
    setSessionData(sessionId, { flows: [] }, { persist: false });
    setNetworkDecisions(sessionId, decisions);
    assert.deepEqual(getSession(sessionId).networkDecisions, decisions);

    const cachePath = getSessionCachePath(sessionId);
    const deadline = Date.now() + 3000;
    while (!fs.existsSync(cachePath) && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(fs.existsSync(cachePath), true);
    const payload = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
    assert.deepEqual(payload.networkDecisions, decisions);
  } finally {
    deleteSession(sessionId);
  }
});
