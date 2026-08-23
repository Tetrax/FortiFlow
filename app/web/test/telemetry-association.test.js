'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

let association = {};
try { association = require('../lib/telemetry-association'); } catch {}

function config(overrides = {}) {
  return {
    identity: {
      hostname: 'FW-AVR-01',
      devid: 'FGT-AVR-01',
      selectedVdom: 'root',
      vdomList: ['root'],
      ...overrides.identity,
    },
    selectedVdom: 'root',
    interfaces: {
      lan: { name: 'lan', cidr: '10.250.16.0/23' },
      servers: { name: 'servers', cidr: '10.251.16.0/24' },
    },
    ...overrides,
  };
}

function flow(overrides = {}) {
  return {
    devname: 'FW-AVR-01',
    devid: 'FGT-AVR-01',
    vdom: 'root',
    srcip: '10.250.16.10',
    srcintf: 'lan',
    dstip: '10.251.16.20',
    dstintf: 'servers',
    ...overrides,
  };
}

test('un nom identique télémétrie/configuration est associé automatiquement', () => {
  assert.equal(typeof association.evaluateTelemetryConfigAssociation, 'function');
  const result = association.evaluateTelemetryConfigAssociation(
    [flow()],
    config(),
    { telemetryContextId: 'telemetry-1', configContextId: 'config-1' },
  );
  assert.equal(result.status, 'matched');
  assert.equal(result.requiresConfirmation, false);
  assert.equal(result.telemetryDeviceName, 'FW-AVR-01');
  assert.equal(result.configHostname, 'FW-AVR-01');
});

test('un nom différent exige une confirmation explicite sans devenir une erreur 422', () => {
  const result = association.evaluateTelemetryConfigAssociation(
    [flow({ devname: 'FW-AVR' })],
    config(),
    { telemetryContextId: 'telemetry-1', configContextId: 'config-1' },
  );
  assert.equal(result.status, 'confirmation_required');
  assert.equal(result.code, 'CONFIG_TELEMETRY_ASSOCIATION_REQUIRED');
  assert.equal(result.requiresConfirmation, true);
  assert.equal(result.telemetryDeviceName, 'FW-AVR');
  assert.equal(result.configHostname, 'FW-AVR-01');
  assert.deepEqual(result.validation.errors, []);
});

test('un nom différent sans identifiant technique fort exige quand même la confirmation utilisateur', () => {
  const result = association.evaluateTelemetryConfigAssociation(
    [flow({ devname: 'FW-AVR', devid: '' })],
    { identity: { hostname: 'FW-AVR-01' }, interfaces: {}, zones: {} },
    { telemetryContextId: 'telemetry-1', configContextId: 'config-minimal' },
  );
  assert.equal(result.status, 'confirmation_required');
  assert.equal(result.code, 'CONFIG_TELEMETRY_ASSOCIATION_REQUIRED');
  assert.equal(result.telemetryDeviceName, 'FW-AVR');
  assert.equal(result.configHostname, 'FW-AVR-01');
});

test('une confirmation utilisateur rend la configuration utilisable dans le même contexte exact', () => {
  assert.equal(typeof association.createConfirmedTelemetryAssociation, 'function');
  assert.equal(typeof association.isTelemetryAssociationUsable, 'function');
  const context = { telemetryContextId: 'telemetry-1', configContextId: 'config-1' };
  const confirmed = association.createConfirmedTelemetryAssociation({
    telemetryDeviceName: 'FW-COM',
    configHostname: 'FW-AVR-01',
    ...context,
    confirmedAt: '2026-08-23T12:00:00.000Z',
  });
  assert.equal(confirmed.confirmedByUser, true);
  assert.equal(association.isTelemetryAssociationUsable(confirmed, context), true);
  const result = association.evaluateTelemetryConfigAssociation(
    [flow({ devname: 'FW-COM' })],
    config(),
    context,
    confirmed,
  );
  assert.equal(result.status, 'matched');
  assert.equal(result.confirmedByUser, true);
});

test('un refus désassocie la configuration et toute variation de contexte invalide la confirmation', () => {
  assert.equal(typeof association.refuseTelemetryConfigAssociation, 'function');
  const confirmed = association.createConfirmedTelemetryAssociation({
    telemetryDeviceName: 'FW-COM',
    configHostname: 'FW-AVR-01',
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
    confirmedAt: '2026-08-23T12:00:00.000Z',
  });
  const reloaded = JSON.parse(JSON.stringify(confirmed));
  assert.equal(association.isTelemetryAssociationUsable(reloaded, {
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
  }), true);
  assert.equal(association.isTelemetryAssociationUsable(confirmed, {
    telemetryContextId: 'telemetry-2',
    configContextId: 'config-1',
  }), false);
  assert.equal(association.isTelemetryAssociationUsable(confirmed, {
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-2',
  }), false);
  assert.equal(association.isTelemetryAssociationUsable(confirmed, {
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
    telemetryDeviceName: 'FW-COM-OTHER',
    configHostname: 'FW-AVR-01',
  }), false);
  const selected = association.createSelectedTelemetryAssociation({
    telemetryDeviceName: 'FW-AVR-01',
    configHostname: 'FW-AVR-01',
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
  });
  assert.equal(association.isTelemetryAssociationUsable(selected, {
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
    telemetryDeviceName: 'FW-AVR-01',
    configHostname: 'FW-OTHER',
  }), false);
  assert.deepEqual(
    association.refuseTelemetryConfigAssociation(confirmed),
    { status: 'unassociated', code: 'CONFIG_TELEMETRY_ASSOCIATION_REFUSED', association: null },
  );
});

test('plusieurs équipements télémétrie imposent une sélection exacte avant toute association', () => {
  const flows = [
    flow({ devname: 'FW-A', devid: 'FGT-A', srcip: '10.250.16.10' }),
    flow({ devname: 'FW-B', devid: 'FGT-B', srcip: '10.250.16.11' }),
  ];
  const multi = association.evaluateTelemetryConfigAssociation(
    flows,
    config({ identity: { hostname: 'FW-B', devid: null } }),
    { telemetryContextId: 'telemetry-1', configContextId: 'config-1' },
  );
  assert.equal(multi.status, 'selection_required');
  assert.equal(multi.code, 'CONFIG_TELEMETRY_DEVICE_SELECTION_REQUIRED');
  assert.deepEqual(multi.telemetryDeviceNames, ['FW-A', 'FW-B']);
  const selected = association.evaluateTelemetryConfigAssociation(
    flows,
    config({ identity: { hostname: 'FW-B', devid: 'FGT-B' } }),
    { telemetryContextId: 'telemetry-1', configContextId: 'config-1', telemetryDeviceName: 'FW-B' },
  );
  assert.equal(selected.status, 'matched');
  assert.equal(selected.telemetryDeviceName, 'FW-B');
});

test('une sélection utilisateur exacte peut être persistée sans confirmation de nom', () => {
  assert.equal(typeof association.createSelectedTelemetryAssociation, 'function');
  const selected = association.createSelectedTelemetryAssociation({
    telemetryDeviceName: 'FW-B',
    configHostname: 'FW-B',
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
  });
  assert.equal(selected.selectedByUser, true);
  assert.equal(selected.confirmedByUser, false);
  assert.equal(association.isTelemetryAssociationUsable(selected, {
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
    telemetryDeviceName: 'FW-B',
    configHostname: 'FW-B',
  }), true);
});

test('l’association ne fait aucun rapprochement flou entre deux noms proches', () => {
  const result = association.evaluateTelemetryConfigAssociation(
    [flow({ devname: 'FW-AVR-01-PROD' })],
    config(),
    { telemetryContextId: 'telemetry-1', configContextId: 'config-1' },
  );
  assert.equal(result.status, 'confirmation_required');
  assert.equal(result.telemetryDeviceName, 'FW-AVR-01-PROD');
  assert.equal(result.configHostname, 'FW-AVR-01');
});

test('une confirmation ne contourne jamais une contradiction serial ou réseau', () => {
  const confirmed = association.createConfirmedTelemetryAssociation({
    telemetryDeviceName: 'FW-COM',
    configHostname: 'FW-AVR-01',
    telemetryContextId: 'telemetry-1',
    configContextId: 'config-1',
    confirmedAt: '2026-08-23T12:00:00.000Z',
  });
  const result = association.evaluateTelemetryConfigAssociation(
    [flow({ devname: 'FW-COM', devid: 'FGT-WRONG' })],
    config(),
    { telemetryContextId: 'telemetry-1', configContextId: 'config-1' },
    confirmed,
  );
  assert.equal(result.status, 'contradiction');
  assert.equal(result.code, 'CONFIG_TELEMETRY_MISMATCH');
  assert.equal(result.validation.errors.length > 0, true);
});
