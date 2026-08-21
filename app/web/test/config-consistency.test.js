'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');

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

test('agrège les diagnostics interface sans matérialiser un contrôle par flow', () => {
  const repeated = Array.from({ length: 5000 }, () => flow());
  const result = consistency.validateConfigTelemetryConsistency(repeated, config());
  assert.equal(result.ok, true);
  assert.ok(result.interfaceChecks.length <= 4);
  assert.equal(result.interfaceChecks.reduce((sum, check) => sum + check.flowCount, 0), 10000);
});

test('sélectionne automatiquement le VDOM unique prouvé par la télémétrie', () => {
  assert.equal(typeof consistency.selectTelemetryVdom, 'function');
  assert.equal(
    consistency.selectTelemetryVdom([flow({ vdom: 'root' })], ['root', 'tenant-b']),
    'root',
  );
  assert.equal(
    consistency.selectTelemetryVdom([flow({ vdom: 'root' }), flow({ vdom: 'tenant-b' })], ['root', 'tenant-b']),
    null,
  );
  assert.equal(consistency.selectTelemetryVdom([flow({ vdom: 'missing' })], ['root']), null);
});

test('refuse un VDOM demandé qui n’existe pas dans la configuration', () => {
  const multiVdom = `
config vdom
    edit "root"
    next
    edit "tenant-b"
    next
end
`;
  assert.throws(() => parseFortiConfig(multiVdom, 'not-real'), /VDOM.*not-real.*introuvable/i);
});

test('une valeur vdomSelectionRequired=false ne peut pas masquer une sélection multi-VDOM absente', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ vdom: 'root' })],
    config({
      identity: {
        hostname: 'FW-AVR-01',
        devid: 'FGT-AVR-01',
        selectedVdom: null,
        vdomList: ['root', 'tenant-b'],
        vdomSelectionRequired: false,
      },
      selectedVdom: null,
    }),
  );
  assertMismatch(result);
});

test('refuse une capture sans aucune preuve positive de config ou de réseau', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ devname: '', devid: '', vdom: '' })],
    config({
      identity: { hostname: null, devid: null, selectedVdom: null },
      selectedVdom: null,
      interfaces: { lan: { name: 'lan' }, servers: { name: 'servers' } },
    }),
  );
  assertMismatch(result);
});

test('ne masque pas les flux dont l’identité est incomplète lorsque d’autres sont complets', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow(), flow({ devname: '', devid: '', vdom: '' })],
    config(),
  );
  assert.equal(result.ok, true);
  assert.equal(result.telemetryIdentity.incompleteFlows, 1);
  assert.ok(result.warnings.some(warning => warning.code === 'TELEMETRY_IDENTITY_INCOMPLETE'));
});

test('refuse le membre HA observé lorsque le membre technique sélectionné est différent', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ devid: 'HA-B' })],
    config({
      identity: {
        hostname: 'FW-AVR-01',
        devid: null,
        ha: { enabled: true, selectedDeviceId: 'HA-A', memberDeviceIds: ['HA-A', 'HA-B'] },
      },
    }),
  );
  assertMismatch(result);
});

test('refuse un contexte HA ambigu lorsque aucun membre technique n’est sélectionné', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ devid: 'HA-B' })],
    config({
      identity: {
        hostname: 'FW-AVR-01',
        devid: null,
        ha: { enabled: true, memberDeviceIds: ['HA-A', 'HA-B'] },
      },
    }),
  );
  assertMismatch(result);
});

test('accepte les réseaux IPv4 publics lorsqu’ils contiennent les IP observées', () => {
  const result = consistency.validateConfigTelemetryConsistency(
    [flow({ srcip: '198.51.100.10', dstip: '203.0.113.20' })],
    config({
      interfaces: {
        lan: { name: 'lan', cidr: '198.51.100.0/24' },
        servers: { name: 'servers', cidr: '203.0.113.0/24' },
      },
    }),
  );
  assert.equal(result.ok, true);
  assert.equal(result.interfaceChecks.every(check => check.ok), true);
});

test('reste borné sous un budget mémoire réduit avec beaucoup de flows identiques', () => {
  const modulePath = require.resolve('../lib/config-consistency');
  const probe = `
    const { validateConfigTelemetryConsistency } = require(${JSON.stringify(modulePath)});
    const flow = { devname: 'FW', devid: 'FGT', vdom: 'root', srcip: '10.0.0.10', dstip: '10.0.1.20', srcintf: 'lan', dstintf: 'servers' };
    const flows = Array(1200000).fill(flow);
    const config = { identity: { hostname: 'FW', devid: 'FGT', selectedVdom: 'root' }, selectedVdom: 'root', interfaces: { lan: { cidr: '10.0.0.0/24' }, servers: { cidr: '10.0.1.0/24' } }, zones: {} };
    const result = validateConfigTelemetryConsistency(flows, config);
    if (!result.ok || result.interfaceChecks.length !== 2) process.exit(2);
  `;
  const child = spawnSync(process.execPath, ['--max-old-space-size=40', '-e', probe], { encoding: 'utf8', timeout: 30000 });
  assert.equal(child.status, 0, child.stderr || child.stdout);
});
