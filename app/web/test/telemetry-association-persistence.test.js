'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const store = require('../lib/store');

function cleanup(id) {
  store.deleteSession(id);
}

test('la session conserve une association confirmée et son contexte dans le cache serveur', () => {
  assert.equal(typeof store.setTelemetryAssociation, 'function');
  assert.equal(typeof store.setTelemetryContextId, 'function');
  const id = store.createSession({ telemetryContextId: 'telemetry-1' });
  try {
    store.setSessionData(id, { flows: [], stats: {}, meta: {} });
    store.setTelemetryAssociation(id, {
      telemetryDeviceName: 'FW-COM',
      configHostname: 'FW-AVR-01',
      telemetryContextId: 'telemetry-1',
      configContextId: 'config-1',
      confirmedByUser: true,
      confirmedAt: '2026-08-23T12:00:00.000Z',
    });
    const session = store.getSession(id);
    assert.equal(session.telemetryContextId, 'telemetry-1');
    assert.equal(session.telemetryAssociation.confirmedByUser, true);
    assert.equal(session.telemetryAssociation.telemetryDeviceName, 'FW-COM');
  } finally {
    cleanup(id);
  }
});

test('le cache disque recharge l’association et son contexte après un redémarrage', async () => {
  const id = store.createSession({ telemetryContextId: `telemetry-cache-${Date.now()}` });
  const association = {
    telemetryDeviceName: 'FW-COM',
    configHostname: 'FW-AVR-01',
    telemetryContextId: store.getSession(id).telemetryContextId,
    configContextId: 'config-cache-1',
    confirmedByUser: true,
    confirmedAt: '2026-08-23T12:00:00.000Z',
  };
  try {
    store.setSessionData(id, { flows: [], stats: {}, meta: {} });
    store.setTelemetryAssociation(id, association);
    await new Promise(resolve => setTimeout(resolve, 100));
    const probe = spawnSync(process.execPath, ['-e', `
      const store = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'store'))});
      const s = store.getSession(${JSON.stringify(id)});
      if (!s || s.telemetryContextId !== ${JSON.stringify(association.telemetryContextId)} || s.telemetryAssociation?.configContextId !== 'config-cache-1') process.exit(2);
    `], { encoding: 'utf8', cwd: path.join(__dirname, '..') });
    assert.equal(probe.status, 0, probe.stderr || probe.stdout);
  } finally {
    cleanup(id);
  }
});
