'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  filterTrafficScope,
  parseTrafficScopeQuery,
  trafficScopeKey,
} = require('../lib/traffic-scope');
const { parseFortiConfig } = require('../lib/forticonfig');

function flow(source, destination, sourceInterface, destinationInterface, count = 1, extra = {}) {
  return {
    srcip: source,
    dstip: destination,
    srcintf: sourceInterface,
    dstintf: destinationInterface,
    count,
    ...extra,
  };
}

test('all traffic scope retains every input flow and session', () => {
  const flows = [
    flow('10.0.0.10', '10.0.1.10', 'port1', 'port2', 3),
    flow('10.0.0.20', '203.0.113.10', 'port1', 'port3', 2),
  ];

  const result = filterTrafficScope(flows, { schemaVersion: 1, mode: 'all' }, {});

  assert.deepEqual(result.flows, flows);
  assert.deepEqual(result.summary, {
    inputFlows: 2,
    inputSessions: 5,
    retainedFlows: 2,
    retainedSessions: 5,
    excludedFlows: 0,
    excludedSessions: 0,
  });
  assert.equal(result.scope.mode, 'all');
  assert.equal(result.scope.schemaVersion, 1);
  assert.equal(trafficScopeKey(result.scope), trafficScopeKey({ mode: 'all', schemaVersion: 1 }));
});

test('lan-lan retains only traffic between configured non-DMZ internal interfaces', () => {
  const fortiConfig = {
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false, cidr: '10.0.0.0/24' },
      servers: { name: 'servers', role: 'lan', isWan: false, cidr: '10.0.1.0/24' },
      edge: { name: 'edge', role: 'wan', isWan: true },
      isolated: { name: 'isolated', role: 'dmz', isWan: false, cidr: '10.0.2.0/24' },
    },
    zones: {},
  };
  const retained = flow('10.0.0.10', '10.0.1.10', 'users', 'servers', 4);
  const result = filterTrafficScope([
    retained,
    flow('10.0.0.10', '203.0.113.10', 'users', 'edge', 3),
    flow('10.0.2.10', '10.0.1.10', 'isolated', 'servers', 2),
    flow('', '', 'missing-a', 'missing-b', 1),
  ], { mode: 'lan-lan' }, fortiConfig);

  assert.deepEqual(result.flows, [retained]);
  assert.deepEqual(result.summary, {
    inputFlows: 4,
    inputSessions: 10,
    retainedFlows: 1,
    retainedSessions: 4,
    excludedFlows: 3,
    excludedSessions: 6,
  });
});

test('lan-internet retains technical LAN egress to a WAN interface', () => {
  const fortiConfig = {
    interfaces: {
      inside: { name: 'inside', role: 'lan', isWan: false },
      outside: { name: 'outside', role: 'wan', isWan: true },
    },
    zones: {},
  };
  const retained = flow('10.0.0.10', '198.51.100.10', 'inside', 'outside', 7);
  const result = filterTrafficScope([
    retained,
    flow('10.0.0.10', '10.0.1.10', 'inside', 'inside', 2),
    flow('198.51.100.10', '10.0.0.10', 'outside', 'inside', 1),
  ], { mode: 'lan-internet' }, fortiConfig);

  assert.deepEqual(result.flows, [retained]);
  assert.equal(result.summary.retainedSessions, 7);
});

test('internet-lan retains technical WAN ingress to a LAN interface', () => {
  const fortiConfig = {
    interfaces: {
      portA: { name: 'portA', role: 'wan', isWan: true },
      portB: { name: 'portB', role: 'lan', isWan: false },
    },
    zones: {},
  };
  const retained = flow('198.51.100.10', '10.0.0.10', 'portA', 'portB', 5);
  const result = filterTrafficScope([
    retained,
    flow('10.0.0.10', '198.51.100.10', 'portB', 'portA', 3),
  ], { mode: 'internet-lan' }, fortiConfig);

  assert.deepEqual(result.flows, [retained]);
  assert.equal(result.summary.excludedSessions, 3);
});

test('lan-dmz uses the FortiGate role and never the interface name', () => {
  const fortiConfig = {
    interfaces: {
      alpha: { name: 'alpha', role: 'lan', isWan: false },
      beta: { name: 'beta', role: 'dmz', isWan: false },
      dmz_by_name_only: { name: 'dmz_by_name_only', role: 'lan', isWan: false },
    },
    zones: {},
  };
  const retained = flow('10.0.0.10', '10.0.2.10', 'alpha', 'beta', 6);
  const result = filterTrafficScope([
    retained,
    flow('10.0.0.10', '10.0.3.10', 'alpha', 'dmz_by_name_only', 4),
  ], { mode: 'lan-dmz' }, fortiConfig);

  assert.deepEqual(result.flows, [retained]);
});

test('dmz-lan accepts an explicit DMZ interface override before FortiGate roles', () => {
  const fortiConfig = {
    interfaces: {
      source_port: { name: 'source_port', role: 'lan', isWan: false },
      target_port: { name: 'target_port', role: 'lan', isWan: false },
    },
    zones: {},
  };
  const retained = flow('10.0.2.10', '10.0.0.10', 'source_port', 'target_port', 2);
  const result = filterTrafficScope([retained], {
    mode: 'dmz-lan',
    dmz: { interfaceNames: ['source_port'] },
  }, fortiConfig);

  assert.deepEqual(result.flows, [retained]);
});

test('custom can explicitly retain unknown endpoints excluded from directional presets', () => {
  const fortiConfig = {
    interfaces: { target: { name: 'target', role: 'lan', isWan: false } },
    zones: {},
  };
  const unknown = flow('', '10.0.0.10', 'unconfigured', 'target', 3);
  const result = filterTrafficScope([
    unknown,
    flow('10.0.0.20', '10.0.0.10', 'target', 'target', 2),
  ], {
    mode: 'custom',
    custom: {
      srcClasses: ['unknown'],
      dstClasses: ['lan'],
      dstInterfaces: ['target'],
    },
  }, fortiConfig);

  assert.deepEqual(result.flows, [unknown]);
});

test('configured internal networks classify public addressing as LAN without naming heuristics', () => {
  const fortiConfig = {
    interfaces: {
      first: { name: 'first', role: 'lan', isWan: false, cidr: '192.0.2.0/24' },
      second: { name: 'second', role: 'lan', isWan: false, cidr: '198.51.100.0/24' },
    },
    zones: {},
  };
  const retained = flow('192.0.2.10', '198.51.100.10', '', '', 1);

  const result = filterTrafficScope([retained], { mode: 'lan-lan' }, fortiConfig);

  assert.deepEqual(result.flows, [retained]);
});

test('FortiGate parsing preserves interface roles required by Traffic Scope', () => {
  const config = parseFortiConfig(`
config system interface
    edit "first"
        set ip 10.0.0.1 255.255.255.0
        set role dmz
    next
    edit "second"
        set ip 10.0.1.1 255.255.255.0
        set role lan
    next
end
`);

  assert.equal(config.interfaces.first.role, 'dmz');
  assert.equal(config.interfaces.second.role, 'lan');
});

test('API query parsing accepts presets and structured custom scopes', () => {
  assert.equal(parseTrafficScopeQuery({ traffic_scope: 'lan-lan' }).mode, 'lan-lan');
  const custom = parseTrafficScopeQuery({
    traffic_scope: JSON.stringify({
      schemaVersion: 1,
      mode: 'custom',
      custom: { srcClasses: ['unknown'], dstInterfaces: ['port2'] },
    }),
  });
  assert.deepEqual(custom.custom.srcClasses, ['unknown']);
  assert.deepEqual(custom.custom.dstInterfaces, ['port2']);
});

test('custom Traffic Scope rejects empty or unknown technical criteria', () => {
  assert.throws(
    () => parseTrafficScopeQuery({ traffic_scope: JSON.stringify({ mode: 'custom' }) }),
    /sans critère/,
  );
  assert.throws(
    () => parseTrafficScopeQuery({
      traffic_scope: JSON.stringify({ mode: 'custom', custom: { srcClasses: ['trusted-users'] } }),
    }),
    /classe technique invalide/,
  );
});

test('malformed IPv4 endpoints remain unknown instead of becoming Internet', () => {
  const malformed = flow('999.999.999.999', '10.0.0.10', '', 'inside', 1);
  const result = filterTrafficScope([malformed], {
    mode: 'custom',
    custom: { srcClasses: ['unknown'], dstClasses: ['lan'] },
  }, {
    interfaces: { inside: { name: 'inside', role: 'lan', isWan: false } },
    zones: {},
  });

  assert.deepEqual(result.flows, [malformed]);
});

test('an explicit DMZ zone override classifies its technical member interfaces', () => {
  const retained = flow('10.0.2.10', '10.0.0.10', 'member-a', 'inside', 1);
  const result = filterTrafficScope([retained], {
    mode: 'dmz-lan',
    dmz: { zoneNames: ['zone-a'] },
  }, {
    interfaces: {
      'member-a': { name: 'member-a', role: 'lan', isWan: false },
      inside: { name: 'inside', role: 'lan', isWan: false },
    },
    zones: { 'zone-a': { name: 'zone-a', members: ['member-a'], isWan: false } },
  });

  assert.deepEqual(result.flows, [retained]);
});
