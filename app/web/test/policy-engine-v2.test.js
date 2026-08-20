'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');

const analyzer = require('../lib/analyzer');
const { applySafeSourceAggregation, evaluatePolicies } = require('../lib/policy-engine-v2');
const {
  analyzePolicies,
  preflightValidation,
  generateConfig,
  sameServiceLabelScope,
} = require('../lib/forticonfig');
const { parseStream } = require('../lib/parser');

test('Policy Engine V2 exposes a pure deterministic build entry point', () => {
  assert.equal(typeof analyzer.buildPolicyEngineV2, 'function');
});

test('service scope comparison ignores duplicate labels but still detects real drift', () => {
  const requested = [
    { label: 'MMS' },
    { label: 'MMS' },
    { label: 'DNS' },
    { label: 'DNS' },
    { label: 'LDAP' },
  ];
  const recalculated = [
    { label: 'MMS' },
    { label: 'DNS' },
    { label: 'LDAP' },
  ];

  assert.equal(sameServiceLabelScope(requested, recalculated), true);
  assert.equal(sameServiceLabelScope(requested, [...recalculated, { label: 'SMB' }]), false);
  assert.equal(sameServiceLabelScope(requested, recalculated.filter(service => service.label !== 'LDAP')), false);
});

function flow(source, destination, proto, port, service, extra = {}) {
  return {
    srcip: source,
    dstip: destination,
    proto: String(proto),
    dstport: String(port),
    service,
    action: 'accept',
    decision: 'allow',
    deploymentEligible: true,
    srcintf: 'users',
    dstintf: 'servers',
    devid: 'FGT-A',
    vdom: 'root',
    count: 1,
    sentBytes: 100,
    rcvdBytes: 200,
    ...extra,
  };
}

test('recommended mode extracts common destination services and residual policies without expansion', () => {
  const source = '192.0.2.10';
  const dstA = '198.51.100.10';
  const dstB = '198.51.100.20';
  const flows = [
    flow(source, dstA, 17, 53, 'DNS'),
    flow(source, dstA, 6, 443, 'HTTPS'),
    flow(source, dstA, 6, 389, 'LDAP'),
    flow(source, dstB, 17, 53, 'DNS'),
    flow(source, dstB, 6, 443, 'HTTPS'),
    flow(source, dstB, 6, 445, 'SMB'),
  ];

  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended' });

  assert.equal(result.policies.length, 3);
  assert.deepEqual(
    result.policies.map(policy => ({
      sources: policy.sources,
      destinations: policy.destinations,
      serviceKeys: policy.serviceKeys,
    })),
    [
      { sources: [source], destinations: [dstA], serviceKeys: ['TCP:389'] },
      { sources: [source], destinations: [dstA, dstB], serviceKeys: ['TCP:443', 'UDP:53'] },
      { sources: [source], destinations: [dstB], serviceKeys: ['TCP:445'] },
    ],
  );
  assert.deepEqual(result.metrics, {
    observedRequiredTuples: 6,
    coveredRequiredTuples: 6,
    missingRequiredTuples: 0,
    allowedTuples: 6,
    unexpectedAllowedTuples: 0,
    coverageRatio: 1,
    expansionRatio: 0,
    blockedRequiredTuples: 0,
    deployableRequiredTuples: 6,
  });
  assert.deepEqual(result.policies.map(policy => policy.metrics), [
    { observedTuples: 1, allowedTuples: 1, unexpectedAllowedTuples: 0, expansionRatio: 0 },
    { observedTuples: 4, allowedTuples: 4, unexpectedAllowedTuples: 0, expansionRatio: 0 },
    { observedTuples: 1, allowedTuples: 1, unexpectedAllowedTuples: 0, expansionRatio: 0 },
  ]);
  assert.deepEqual(result.affinityViews, [{
    id: 'AV-00001',
    policyIds: ['P-00001', 'P-00002', 'P-00003'],
    sources: [source],
    destinations: [dstA, dstB],
    serviceKeys: ['TCP:389', 'TCP:443', 'TCP:445', 'UDP:53'],
    commonServiceKeys: ['TCP:443', 'UDP:53'],
    residualServiceKeysByDestination: {
      [dstA]: ['TCP:389'],
      [dstB]: ['TCP:445'],
    },
    matrix: {
      'TCP:389': { [dstA]: true, [dstB]: false },
      'TCP:443': { [dstA]: true, [dstB]: true },
      'TCP:445': { [dstA]: false, [dstB]: true },
      'UDP:53': { [dstA]: true, [dstB]: true },
    },
  }]);
});

test('identical destination signatures collapse into one exact policy', () => {
  const flows = [
    flow('192.0.2.10', '198.51.100.10', 17, 53, 'DNS'),
    flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS'),
    flow('192.0.2.10', '198.51.100.20', 17, 53, 'DNS'),
    flow('192.0.2.10', '198.51.100.20', 6, 443, 'HTTPS'),
  ];
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended' });
  assert.equal(result.policies.length, 1);
  assert.deepEqual(result.policies[0].destinations, ['198.51.100.10', '198.51.100.20']);
  assert.deepEqual(result.policies[0].serviceKeys, ['TCP:443', 'UDP:53']);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
});

test('services with no common destination behavior remain separate', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 6, 389, 'LDAP'),
    flow('192.0.2.10', '198.51.100.20', 6, 445, 'SMB'),
  ], { profile: 'recommended' });
  assert.equal(result.policies.length, 2);
  assert.ok(result.policies.every(policy => policy.destinations.length === 1));
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
});

test('partially similar sources keep source-service affinity', () => {
  const destination = '198.51.100.10';
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', destination, 17, 53, 'DNS'),
    flow('192.0.2.10', destination, 6, 443, 'HTTPS'),
    flow('192.0.2.20', destination, 17, 53, 'DNS'),
    flow('192.0.2.20', destination, 6, 445, 'SMB'),
  ], { profile: 'recommended' });
  assert.equal(result.policies.length, 3);
  assert.equal(result.metrics.missingRequiredTuples, 0);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
  const dns = result.policies.find(policy => policy.serviceKeys.includes('UDP:53'));
  assert.deepEqual(dns.sources, ['192.0.2.10', '192.0.2.20']);
  assert.deepEqual(dns.destinations, [destination]);
});

test('safe source aggregation merges only policies with identical technical scope', () => {
  const flows = [
    flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS'),
    flow('192.0.2.20', '198.51.100.10', 6, 443, 'HTTPS'),
  ];
  const strict = analyzer.buildPolicyEngineV2(flows, { profile: 'strict' });

  const merged = applySafeSourceAggregation(strict.policies, strict.atoms);
  const metrics = evaluatePolicies(strict.atoms, merged);

  assert.equal(strict.policies.length, 2);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].sources, ['192.0.2.10', '192.0.2.20']);
  assert.equal(metrics.coverageRatio, 1);
  assert.equal(metrics.missingRequiredTuples, 0);
  assert.equal(metrics.unexpectedAllowedTuples, 0);
  assert.equal(metrics.expansionRatio, 0);
});

test('safe source aggregation never merges same-label TCP and UDP services', () => {
  const strict = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 6, 53, 'DNS'),
    flow('192.0.2.20', '198.51.100.10', 17, 53, 'DNS'),
  ], { profile: 'strict' });

  const merged = applySafeSourceAggregation(strict.policies, strict.atoms);
  const metrics = evaluatePolicies(strict.atoms, merged);

  assert.equal(merged.length, 2);
  assert.deepEqual(merged.map(policy => policy.serviceKeys), [['TCP:53'], ['UDP:53']]);
  assert.equal(metrics.missingRequiredTuples, 0);
  assert.equal(metrics.unexpectedAllowedTuples, 0);
  assert.equal(metrics.expansionRatio, 0);
});

test('recommended reuses an existing source CIDR only on exact full membership', () => {
  const flows = [0, 1, 2, 3].map(host =>
    flow(`192.0.2.${host}`, '198.51.100.10', 6, 443, 'HTTPS')
  );
  const config = {
    addresses: {
      'AVR-LAN-STATIONS-192.0.2.0/30': { name: 'AVR-LAN-STATIONS-192.0.2.0/30', cidr: '192.0.2.0/30' },
      SERVER: { name: 'SERVER', cidr: '198.51.100.10/32' },
    },
    addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: {
      users: { name: 'users', cidr: '192.0.2.0/24' },
      servers: { name: 'servers', cidr: '198.51.100.0/24' },
    },
  };

  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });

  assert.equal(result.policies.length, 1);
  assert.equal(result.policies[0].srcSubnet, '192.0.2.0/30');
  assert.equal(result.policies[0]._use32Src, false);
  assert.deepEqual(result.policies[0].sourceObjectReuse, {
    name: 'AVR-LAN-STATIONS-192.0.2.0/30',
    cidr: '192.0.2.0/30',
    addressCount: 4,
  });
  assert.equal(result.optimization.before.policyCount, 1);
  assert.equal(result.optimization.after.policyCount, 1);
  assert.equal(result.optimization.sourceObjectsReused, 1);
  assert.equal(result.optimization.after.missingRequiredTuples, 0);
  assert.equal(result.optimization.after.unexpectedAllowedTuples, 0);
  assert.equal(result.optimization.after.expansionRatio, 0);

  const analyzed = analyzePolicies(result.policies, config, null);
  assert.equal(analyzed[0].analysis.srcAddr.found, true);
  assert.equal(analyzed[0].analysis.srcAddr.name, 'AVR-LAN-STATIONS-192.0.2.0/30');
  const cli = generateConfig(analyzed, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    serviceGroups: config.serviceGroups,
    zones: config.zones,
  });
  assert.match(cli, /set srcaddr "AVR-LAN-STATIONS-192\.0\.2\.0\/30"/);
  assert.doesNotMatch(cli, /edit "AVR-LAN-STATIONS-192\.0\.2\.0\/30"/);
});

test('recommended refuses sparse reuse of an existing source CIDR', () => {
  const flows = [0, 1, 2].map(host =>
    flow(`192.0.2.${host}`, '198.51.100.10', 6, 443, 'HTTPS')
  );
  const result = analyzer.buildPolicyEngineV2(flows, {
    profile: 'recommended',
    fortiConfig: {
      addresses: {
        BROAD: { name: 'BROAD', cidr: '192.0.2.0/30' },
      },
    },
  });

  assert.equal(result.policies[0].sourceObjectReuse, undefined);
  assert.equal(result.policies[0]._use32Src, true);
  assert.equal(result.optimization.sourceObjectsReused, 0);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
  assert.equal(result.metrics.expansionRatio, 0);
});

test('recommended mode exactly preserves every non-empty 2x2x2 permission graph', () => {
  const sources = ['192.0.2.10', '192.0.2.20'];
  const destinations = ['198.51.100.10', '198.51.100.20'];
  const services = [
    { proto: 6, port: 443, name: 'HTTPS' },
    { proto: 17, port: 53, name: 'DNS' },
  ];
  const universe = sources.flatMap(source =>
    destinations.flatMap(destination =>
      services.map(service => ({ source, destination, ...service }))
    )
  );
  for (let mask = 1; mask < (1 << universe.length); mask++) {
    const selected = universe.filter((_tuple, index) => mask & (1 << index));
    const result = analyzer.buildPolicyEngineV2(selected.map(tuple =>
      flow(tuple.source, tuple.destination, tuple.proto, tuple.port, tuple.name)
    ), { profile: 'recommended' });
    assert.equal(result.metrics.observedRequiredTuples, selected.length, `mask=${mask}`);
    assert.equal(result.metrics.coveredRequiredTuples, selected.length, `mask=${mask}`);
    assert.equal(result.metrics.missingRequiredTuples, 0, `mask=${mask}`);
    assert.equal(result.metrics.unexpectedAllowedTuples, 0, `mask=${mask}`);
  }
});

test('input order does not change atoms, policies, names or metrics', () => {
  const flows = [
    flow('192.0.2.20', '198.51.100.20', 6, 445, 'SMB'),
    flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS'),
    flow('192.0.2.20', '198.51.100.10', 17, 53, 'DNS'),
    flow('192.0.2.10', '198.51.100.20', 17, 53, 'DNS'),
  ];
  const forward = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended' });
  const reverse = analyzer.buildPolicyEngineV2([...flows].reverse(), { profile: 'recommended' });
  assert.deepEqual(reverse, forward);
});

test('affinity views stay bounded for 1000 sparse destination-service policies', { timeout: 5000 }, () => {
  const flows = Array.from({ length: 1000 }, (_unused, index) =>
    flow(
      '10.0.0.10',
      `10.${1 + Math.floor(index / 65536)}.${Math.floor(index / 256) % 256}.${index % 256}`,
      6,
      1000 + index,
      `SVC-${index}`,
    )
  );

  const started = process.hrtime.bigint();
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended' });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  assert.equal(result.policies.length, 1000);
  assert.equal(result.affinityViews.length, 1);
  assert.equal(result.affinityViews[0].matrix['TCP:1000']['10.1.0.0'], true);
  assert.equal(result.affinityViews[0].matrix['TCP:1000']['10.1.0.1'], false);
  assert.ok(elapsedMs < 2000, `affinity build took ${Math.round(elapsedMs)} ms`);
});

test('different FortiGate scopes and interface pairs are never merged', () => {
  const base = flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS');
  const result = analyzer.buildPolicyEngineV2([
    base,
    { ...base, vdom: 'tenant-b' },
    { ...base, dstintf: 'dmz' },
  ], { profile: 'recommended' });
  assert.equal(result.atoms.length, 3);
  assert.equal(result.policies.length, 3);
  assert.equal(result.metrics.observedRequiredTuples, 3);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
});

test('preflight rejects a V2 policy that collapses two observed interface pairs', () => {
  const flows = [
    flow('10.0.0.10', '10.0.1.10', 6, 443, 'HTTPS', { srcintf: 'users-a', dstintf: 'servers-a' }),
    flow('10.0.0.10', '10.0.1.10', 6, 443, 'HTTPS', { srcintf: 'users-b', dstintf: 'servers-b' }),
  ];
  const config = {
    addresses: {}, addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: { 'users-a': {}, 'users-b': {}, 'servers-a': {}, 'servers-b': {} },
  };
  const engine = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const analyzed = analyzePolicies(engine.policies, config, null);
  const collapsed = {
    ...analyzed[0],
    srcintf: ['users-a', 'users-b'],
    dstintf: ['servers-a', 'servers-b'],
  };

  const preflight = preflightValidation([collapsed], config, flows, engine.atoms);

  assert.equal(preflight.ok, false);
  assert.equal(preflight.selectionMetrics.missingRequiredTuples, 1);
  assert.ok(preflight.issues.some(issue => issue.code === 'POLICY_ENGINE_MISSING_REQUIRED_TUPLES'));
});

test('strict mode emits one exact policy per canonical tuple', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS'),
    flow('192.0.2.10', '198.51.100.10', 17, 53, 'DNS'),
    flow('192.0.2.10', '198.51.100.10', 17, 53, 'DNS', { count: 5 }),
  ], { profile: 'strict' });
  assert.equal(result.atoms.length, 2);
  assert.equal(result.policies.length, 2);
  assert.equal(result.metrics.coverageRatio, 1);
  assert.equal(result.metrics.expansionRatio, 0);
});

test('dynamic and rare ports remain exact and protocol-specific', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 6, 52121, 'DCE-RPC'),
    flow('192.0.2.10', '198.51.100.10', 6, 52134, 'DCE-RPC'),
    flow('192.0.2.10', '198.51.100.10', 17, 52121, 'DCE-RPC'),
  ], { profile: 'recommended' });
  assert.deepEqual(result.atoms.map(atom => atom.service.key), ['TCP:52121', 'TCP:52134', 'UDP:52121']);
  assert.equal(result.policies.some(policy => policy.serviceKeys.includes('TCP:49152-65535')), false);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
});

test('missing temporal evidence propagates an unknown confidence instead of certification', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS'),
  ], { profile: 'recommended' });
  assert.equal(result.policies[0].confidence, 'unknown');
});

test('synthetic mode aggregates a dense known subnet and measures every additional tuple', () => {
  const destination = '198.51.100.10';
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.0', destination, 6, 443, 'HTTPS'),
    flow('192.0.2.1', destination, 6, 443, 'HTTPS'),
    flow('192.0.2.2', destination, 6, 443, 'HTTPS'),
  ], {
    profile: 'synthetic',
    networks: [{ cidr: '192.0.2.0/30', name: 'CLIENTS-DENSE' }],
    networkAggregation: { minDensity: 0.75, minHosts: 3, minPrefix: 24 },
  });

  assert.equal(result.policies.length, 1);
  assert.equal(result.policies[0].srcSubnet, '192.0.2.0/30');
  assert.equal(result.policies[0]._use32Src, false);
  assert.deepEqual(result.policies[0].networkAggregation.source, {
    cidr: '192.0.2.0/30',
    objectName: 'CLIENTS-DENSE',
    observedHosts: 3,
    possibleHosts: 4,
    density: 0.75,
    additionalHosts: 1,
  });
  assert.equal(result.metrics.observedRequiredTuples, 3);
  assert.equal(result.metrics.coveredRequiredTuples, 3);
  assert.equal(result.metrics.missingRequiredTuples, 0);
  assert.equal(result.metrics.allowedTuples, 4);
  assert.equal(result.metrics.unexpectedAllowedTuples, 1);
  assert.equal(result.metrics.expansionRatio, 1 / 3);
});

test('re-analysis may deduplicate presentation labels without widening the technical service scope', () => {
  const flows = [
    flow('10.0.0.10', '10.0.1.10', 17, 3479, 'MMS'),
    flow('10.0.0.10', '10.0.1.10', 17, 3481, 'MMS'),
    flow('10.0.0.10', '10.0.1.10', 6, 53, 'DNS'),
    flow('10.0.0.10', '10.0.1.10', 17, 53, 'DNS'),
  ];
  const config = {
    addresses: {}, addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
  };
  const engine = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const analyzed = analyzePolicies(engine.policies, config, null);

  assert.deepEqual(engine.policies[0].analysis.services.map(service => service.label).sort(), ['DNS', 'DNS', 'MMS', 'MMS']);
  assert.deepEqual(analyzed[0].analysis.services.map(service => service.label).sort(), ['DNS', 'MMS']);
  assert.equal(sameServiceLabelScope(engine.policies[0].analysis.services, analyzed[0].analysis.services), true);
  assert.deepEqual(analyzed[0].analysis.services.find(service => service.label === 'MMS').udpPorts, [3479, 3481]);
  assert.equal(preflightValidation(analyzed, config, flows, engine.atoms).ok, true);
});

test('service normalization prefers exact existing objects and classifies predefined, rare and dynamic ports', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS'),
    flow('192.0.2.10', '198.51.100.10', 6, 8443, 'APP-HTTPS', { count: 20, days: ['2026-08-01', '2026-08-02'] }),
    flow('192.0.2.10', '198.51.100.10', 6, 12345, '', { count: 1 }),
    flow('192.0.2.10', '198.51.100.10', 6, 52121, 'DCE-RPC'),
  ], {
    profile: 'recommended',
    fortiConfig: {
      customServices: {
        'APP-HTTPS-EXACT': { name: 'APP-HTTPS-EXACT', proto: 'TCP/UDP/SCTP', tcpPorts: [8443], udpPorts: [] },
        'APP-HTTPS-WIDE': { name: 'APP-HTTPS-WIDE', proto: 'TCP/UDP/SCTP', tcpPorts: [8443, 9443], udpPorts: [] },
      },
    },
  });

  const byKey = Object.fromEntries(result.serviceInventory.map(service => [service.key, service]));
  assert.equal(byKey['TCP:443'].classification, 'predefined');
  assert.equal(byKey['TCP:443'].selectedObject, 'HTTPS');
  assert.equal(byKey['TCP:8443'].classification, 'existing');
  assert.equal(byKey['TCP:8443'].selectedObject, 'APP-HTTPS-EXACT');
  assert.equal(byKey['TCP:12345'].classification, 'rare');
  assert.equal(byKey['TCP:52121'].classification, 'dynamic');
  assert.equal(byKey['TCP:52121'].generalizedRange, null);
});

test('safe optimizer finds local service intersections even when global service signatures differ', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 17, 53, 'DNS'),
    flow('192.0.2.10', '198.51.100.10', 6, 443, 'HTTPS'),
    flow('192.0.2.10', '198.51.100.10', 6, 389, 'LDAP'),
    flow('192.0.2.10', '198.51.100.20', 17, 53, 'DNS'),
    flow('192.0.2.10', '198.51.100.20', 6, 443, 'HTTPS'),
    flow('192.0.2.10', '198.51.100.20', 6, 445, 'SMB'),
    flow('192.0.2.30', '198.51.100.30', 17, 53, 'DNS'),
  ], { profile: 'recommended' });

  assert.equal(result.policies.length, 4);
  assert.ok(result.policies.some(policy =>
    policy.sources.length === 1
    && policy.sources[0] === '192.0.2.10'
    && policy.destinations.length === 2
    && policy.serviceKeys.join(',') === 'TCP:443,UDP:53'
  ));
  assert.equal(result.metrics.missingRequiredTuples, 0);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
});

test('V2 policies can be reconciled against a workspace-restored FortiGate service inventory', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('192.0.2.10', '198.51.100.10', 6, 8443, ''),
  ], { profile: 'recommended' });
  const fortiConfig = {
    addresses: {},
    interfaces: {},
    zones: {},
    customServices: {
      'APP-HTTPS': {
        name: 'APP-HTTPS',
        proto: 'TCP/UDP/SCTP',
        tcpPorts: [8443],
        udpPorts: [],
        _tcpSet: {},
        _udpSet: {},
      },
    },
  };

  const analyzed = analyzePolicies(result.policies, fortiConfig, null);
  assert.equal(analyzed.length, 1);
  assert.equal(analyzed[0].analysis.services[0].found, true);
  assert.equal(analyzed[0].analysis.services[0].name, 'APP-HTTPS');
});

test('preflight certifies grouped V2 rectangles from exact technical tuples', () => {
  const flows = [
    flow('10.0.0.10', '10.0.1.10', 17, 53, 'DNS'),
    flow('10.0.0.10', '10.0.1.10', 6, 443, 'HTTPS'),
    flow('10.0.0.10', '10.0.1.10', 6, 389, 'LDAP'),
    flow('10.0.0.10', '10.0.1.20', 17, 53, 'DNS'),
    flow('10.0.0.10', '10.0.1.20', 6, 443, 'HTTPS'),
    flow('10.0.0.10', '10.0.1.20', 6, 445, 'SMB'),
  ];
  const config = {
    addresses: {},
    addressGroups: {},
    customServices: {},
    serviceGroups: {},
    interfaces: { users: {}, servers: {} },
    zones: {},
  };
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const analyzed = analyzePolicies(result.policies, config, null);
  const preflight = preflightValidation(analyzed, config, flows);

  assert.equal(preflight.ok, true);
  assert.equal(preflight.certification.level, 'exact');
});

test('preflight rejects a selected V2 subset that omits a deployable required tuple', () => {
  const flows = [
    flow('10.0.0.10', '10.0.1.10', 6, 443, 'HTTPS'),
    flow('10.0.0.20', '10.0.1.20', 6, 22, 'SSH'),
  ];
  const config = {
    addresses: {}, addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
  };
  const engine = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const analyzed = analyzePolicies(engine.policies, config, null);

  const preflight = preflightValidation([analyzed[0]], config, flows, engine.atoms);

  assert.equal(preflight.ok, false);
  assert.equal(preflight.selectionMetrics.coverageRatio, 0.5);
  assert.equal(preflight.selectionMetrics.missingRequiredTuples, 1);
  assert.ok(preflight.issues.some(issue => issue.code === 'POLICY_ENGINE_MISSING_REQUIRED_TUPLES'));
});

test('preflight rejects the same service label when protocol or port differs', () => {
  const policy = {
    srcintf: 'users', dstintf: 'servers',
    srcSubnet: '10.0.0.10/32', dstTarget: '10.0.1.10/32',
    srcHosts: ['10.0.0.10'], dstHosts: ['10.0.1.10'],
    services: ['APP'],
    serviceTuples: [{ proto: '6', port: '443', service: 'APP' }],
    _use32Src: true, _use32Dst: true,
    _segmentationPlan: { source: 'host', destination: 'host', services: 'separate' },
    action: 'accept', log: 'all',
    scope: { devid: 'FGT-A', vdom: 'root' },
    analysis: {
      srcIface: 'users', dstIface: 'servers',
      services: [{ label: 'APP', name: 'APP', found: true }],
    },
  };
  const config = { addresses: {}, addressGroups: {}, interfaces: { users: {}, servers: {} }, zones: {} };
  const mismatched = [flow('10.0.0.10', '10.0.1.10', 6, 8443, 'APP')];

  const result = preflightValidation([policy], config, mismatched);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some(issue => /non observé/.test(issue.msg)));
});

test('V2 preserves an explicit internal classification for public-address LANs', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('203.0.113.10', '198.51.100.10', 6, 443, 'HTTPS', {
      srcType: 'private',
      dstType: 'private',
    }),
  ], { profile: 'recommended' });
  assert.equal(result.policies[0].dstType, 'private');
});

test('V2 exact path reaches FortiGate CLI generation without ALL fallbacks', () => {
  const flows = [
    flow('10.0.0.10', '10.0.1.10', 6, 443, 'HTTPS'),
    flow('10.0.0.20', '10.0.1.10', 6, 443, 'HTTPS'),
  ];
  const config = {
    addresses: {}, addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
  };
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const analyzed = analyzePolicies(result.policies, config, null);
  const preflight = preflightValidation(analyzed, config, flows);
  assert.equal(preflight.ok, true);

  const cli = generateConfig(analyzed, {
    addresses: config.addresses,
    addressGroups: config.addressGroups,
    serviceGroups: config.serviceGroups,
    zones: config.zones,
    namingPrefix: 'FFV2',
  });
  assert.match(cli, /config firewall policy/);
  assert.doesNotMatch(cli, /set srcaddr "all"/);
  assert.doesNotMatch(cli, /set service "ALL"/);
});

test('legacy consolidation never crosses observed interface pairs', () => {
  const base = {
    srcSubnet: '10.0.0.0/24', dstTarget: '10.0.1.0/24', dstType: 'private',
    services: ['HTTPS'], ports: [443], protos: ['TCP'],
    serviceTuples: [{ proto: '6', port: '443', service: 'HTTPS' }],
    serviceDesc: 'HTTPS', sessions: 1, sentBytes: 1, rcvdBytes: 1,
    scope: { devid: 'FGT-A', vdom: 'root' }, noRcvdSrcHosts: [],
  };
  const result = analyzer.consolidatePolicies([
    { ...base, flowSrcintf: 'lan', dstintf: 'servers' },
    { ...base, flowSrcintf: 'dmz', dstintf: 'servers' },
  ]);
  assert.equal(result.length, 2);
});

test('V2 reports every flow excluded before canonical policy generation', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('10.0.0.10', '10.0.1.10', 6, 443, 'HTTPS', { count: 2 }),
    flow('10.0.0.10', '10.0.1.20', 6, 443, 'HTTPS', {
      count: 3,
      deploymentEligible: false,
      evidenceIssues: ['nat_observed'],
    }),
    flow('10.0.0.10', '10.0.1.30', 6, 443, 'HTTPS', {
      count: 4,
      action: 'deny',
      decision: 'deny',
    }),
  ], { profile: 'recommended' });

  assert.deepEqual(result.inputSummary, {
    inputFlows: 3,
    inputSessions: 9,
    includedFlows: 1,
    includedSessions: 2,
    excludedFlows: 2,
    excludedSessions: 7,
    exclusionReasons: {
      deployment_ineligible: 3,
      not_allowed: 4,
    },
  });
});

test('expert profile exposes the effective safe optimizer parameters', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('10.0.0.10', '10.0.1.10', 6, 443, 'HTTPS'),
  ], { profile: 'expert' });
  assert.deepEqual(result.expertParameters, {
    groupingStrategy: 'deterministic-safe-rectangles',
    serviceIdentity: 'protocol-destination-port',
    allowImplicitExpansion: false,
    networkAggregation: false,
  });
  assert.equal(result.metrics.expansionRatio, 0);
});

test('ICMP type and code remain distinct and reuse an exact FortiGate object', () => {
  const config = {
    addresses: {}, addressGroups: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
    customServices: {
      'PING-EXACT': {
        name: 'PING-EXACT', proto: 'ICMP', tcpPorts: [], udpPorts: [],
        icmptype: 8, icmpcode: 0,
      },
    },
  };
  const flows = [flow('10.0.0.10', '10.0.1.10', 1, 0, 'ICMP/8/0')];
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  assert.equal(result.atoms[0].service.key, 'ICMP:8:0');
  assert.equal(result.serviceInventory[0].classification, 'existing');
  assert.equal(result.serviceInventory[0].selectedObject, 'PING-EXACT');
  assert.equal(result.blockers.length, 0);
  const analyzed = analyzePolicies(result.policies, config, null);
  assert.equal(preflightValidation(analyzed, config, flows).ok, true);
});

test('TCP or UDP without a numeric destination port is blocked and counted separately', () => {
  const result = analyzer.buildPolicyEngineV2([
    flow('10.0.0.10', '10.0.1.10', 6, '80-90', 'APP-RANGE'),
  ], { profile: 'recommended' });
  assert.equal(result.serviceInventory[0].classification, 'unresolved-port');
  assert.equal(result.serviceInventory[0].deploymentBlocked, true);
  assert.deepEqual(result.blockers, [{
    code: 'MISSING_DSTPORT',
    serviceKey: 'TCP',
    affectedTuples: 1,
    message: 'Le port destination observé est absent ou illisible ; aucune permission FortiGate exacte ne peut être calculée.',
  }]);
  assert.equal(result.metrics.blockedRequiredTuples, 1);
});

test('synthetic never reuses an existing network object broader than the measured CIDR', () => {
  const flows = [0, 1, 2].map(host =>
    flow(`10.0.0.${host}`, '10.0.1.10', 6, 443, 'HTTPS')
  );
  const config = {
    addresses: { BROAD: { name: 'BROAD', cidr: '10.0.0.0/29' } },
    addressGroups: {}, customServices: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
  };
  const result = analyzer.buildPolicyEngineV2(flows, {
    profile: 'synthetic',
    fortiConfig: config,
    networks: [{ cidr: '10.0.0.0/30', name: 'MEASURED' }],
    networkAggregation: { minDensity: 0.75, minHosts: 3, minPrefix: 24 },
  });
  const analyzed = analyzePolicies(result.policies, config, null);
  assert.equal(result.policies[0].srcSubnet, '10.0.0.0/30');
  assert.equal(analyzed[0].analysis.srcAddr.found, false);
  assert.notEqual(analyzed[0].analysis.srcAddr.name, 'BROAD');
});

test('a named ICMP service is reusable when the selected FortiGate config defines the same protocol object', () => {
  const config = {
    addresses: {}, addressGroups: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
    customServices: {
      PING: { name: 'PING', proto: 'ICMP', tcpPorts: [], udpPorts: [], icmptype: 8, icmpcode: null },
    },
  };
  const flows = [flow('10.0.0.10', '10.0.1.10', 1, '', 'PING')];
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  assert.equal(result.atoms[0].service.key, 'ICMP:NAME:PING');
  assert.equal(result.serviceInventory[0].classification, 'existing');
  assert.equal(result.serviceInventory[0].selectedObject, 'PING');
  assert.equal(result.blockers.length, 0);
  const analyzed = analyzePolicies(result.policies, config, null);
  assert.equal(preflightValidation(analyzed, config, flows).ok, true);
});

test('named ICMP is blocked when observed type/code conflicts with the same-named FortiGate object', () => {
  const config = {
    addresses: {}, addressGroups: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
    customServices: {
      PING: { name: 'PING', proto: 'ICMP', tcpPorts: [], udpPorts: [], icmptype: 3, icmpcode: 1 },
    },
  };
  const flows = [flow('10.0.0.10', '10.0.1.10', 1, '', 'PING', { icmpType: 8, icmpCode: 0 })];
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  const analyzed = analyzePolicies(result.policies, config, null);
  const preflight = preflightValidation(analyzed, config, flows, result.atoms);

  assert.equal(result.atoms[0].service.key, 'ICMP:8:0');
  assert.equal(result.blockers.length, 1);
  assert.equal(analyzed[0].analysis.services[0].found, false);
  assert.equal(preflight.ok, false);
});

test('different named ICMP services never collapse when type and code are absent', () => {
  const config = {
    addresses: {}, addressGroups: {}, serviceGroups: {}, zones: {},
    interfaces: { users: {}, servers: {} },
    customServices: {
      PING: { name: 'PING', proto: 'ICMP', tcpPorts: [], udpPorts: [], icmptype: 8, icmpcode: null },
    },
  };
  const flows = [
    flow('10.0.0.10', '10.0.1.10', 1, '', 'PING'),
    flow('10.0.0.10', '10.0.1.10', 1, '', 'GOOGLE-ICMP'),
  ];
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended', fortiConfig: config });
  assert.deepEqual(result.atoms.map(atom => atom.service.key), ['ICMP:NAME:GOOGLE-ICMP', 'ICMP:NAME:PING']);
  assert.equal(result.metrics.observedRequiredTuples, 2);
  assert.equal(result.metrics.missingRequiredTuples, 0);
  assert.equal(result.metrics.unexpectedAllowedTuples, 0);
  assert.equal(result.metrics.blockedRequiredTuples, 1);
  assert.deepEqual(result.blockers.map(blocker => blocker.serviceKey), ['ICMP:NAME:GOOGLE-ICMP']);
});

test('parser preserves ICMP type/code and keeps different portless ICMP service identities separate', async () => {
  const common = 'date=2026-08-20 time=10:00:00 type=traffic subtype=forward devname=FGT-A devid=FGT-A vd=root srcip=10.0.0.10 dstip=10.0.1.10 proto=1 action=accept srcintf=users dstintf=servers policyid=1 sentbyte=1 rcvdbyte=1';
  const parsed = await parseStream(Readable.from([[
    `${common} service=PING icmptype=8 icmpcode=0`,
    `${common} service=GOOGLE-ICMP`,
  ].join('\n')]));
  const flows = [...parsed.flowMap.values()].sort((a, b) => a.service.localeCompare(b.service));
  assert.equal(flows.length, 2);
  assert.deepEqual(flows.map(item => ({ service: item.service, icmpType: item.icmpType, icmpCode: item.icmpCode })), [
    { service: 'GOOGLE-ICMP', icmpType: null, icmpCode: null },
    { service: 'PING', icmpType: 8, icmpCode: 0 },
  ]);
  const result = analyzer.buildPolicyEngineV2(flows, { profile: 'recommended' });
  assert.deepEqual(result.atoms.map(atom => atom.service.key), ['ICMP:8:0', 'ICMP:NAME:GOOGLE-ICMP']);
});
