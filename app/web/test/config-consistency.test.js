'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// Keep the first RED behavioral: an absent implementation is an assertion failure,
// not a module-loading/setup failure.
let consistency = {};
try { consistency = require('../lib/config-consistency'); } catch {}
const { parseFortiConfig } = require('../lib/forticonfig');

const MISMATCH_MESSAGE = 'La télémétrie et la configuration FortiGate ne correspondent pas.';

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

function assertMismatch(result) {
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => error.code === 'CONFIG_TELEMETRY_MISMATCH'));
  assert.ok(result.errors.some(error => error.message === MISMATCH_MESSAGE));
  assert.equal(result.message, MISMATCH_MESSAGE);
}

test('cohérent pour le même équipement, VDOM et réseaux d’interfaces', () => {
  assert.equal(typeof consistency.validateConfigTelemetryConsistency, 'function');
  const result = consistency.validateConfigTelemetryConsistency([flow()], config());
  assert.equal(result.ok, true);
  assert.deepEqual(result.telemetryIdentity.devnames, ['FW-AVR-01']);
  assert.deepEqual(result.telemetryIdentity.devids, ['FGT-AVR-01']);
  assert.deepEqual(result.telemetryIdentity.vdoms, ['root']);
  assert.equal(result.interfaceChecks.every(check => check.ok), true);
});

test('refuse le repro FW-COM face à FW-AVR-01 avant toute analyse', () => {
  const result = consistency.validateConfigTelemetryConsistency([
    flow({ devname: 'FW-COM', srcip: '10.252.16.10' }),
  ], config());
  assertMismatch(result);
});

test('autorise conditionnellement une identité hostname inconnue si les interfaces sont cohérentes', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ devname: '', devid: '' })],
    config({ identity: { hostname: null, devid: null } }),
  );
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some(warning => warning.code === 'TELEMETRY_IDENTITY_UNKNOWN'));
  assert.equal(result.errors.length, 0);
});

test('refuse un réseau observé hors du réseau déclaré pour la même interface', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ srcip: '10.252.16.10' })],
    config(),
  );
  assertMismatch(result);
  assert.ok(result.interfaceChecks.some(check => check.interface === 'lan' && check.ok === false));
});

test('accepte explicitement les serials HA autorisés avec une sélection technique', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ devid: 'HA-A' }), flow({ devid: 'HA-B' })],
    config({
      identity: {
        hostname: 'FW-AVR-01',
        devid: null,
        ha: { enabled: true, selectedDeviceId: 'HA-A', memberDeviceIds: ['HA-A', 'HA-B'] },
      },
    }),
  );
  assert.equal(result.ok, true);
  assert.equal(result.telemetryIdentity.devids.length, 2);
});

test('refuse plusieurs VDOM lorsque la sélection technique est absente', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ vdom: 'root' }), flow({ vdom: 'tenant-b' })],
    config({
      identity: {
        hostname: 'FW-AVR-01',
        devid: 'FGT-AVR-01',
        selectedVdom: null,
        vdomList: ['root', 'tenant-b'],
        vdomSelectionRequired: true,
      },
      selectedVdom: null,
    }),
  );
  assertMismatch(result);
});

test('parse et expose le hostname FortiGate sans inventer un serial', () => {
  const parsed = parseFortiConfig(`
config system global
    set hostname "FW-AVR-01"
end
`);
  assert.equal(parsed.identity.hostname, 'FW-AVR-01');
  assert.equal(parsed.hostname, 'FW-AVR-01');
  assert.equal(parsed.identity.devid, null);
});
