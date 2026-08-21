'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildPolicyEngineV2 } = require('../lib/policy-engine-v2');
const {
  buildPolicyRepresentationCandidates,
} = require('../lib/network-representation-integration');

function flow(source, destination, extra = {}) {
  return {
    srcip: source,
    dstip: destination,
    proto: '6',
    dstport: '443',
    service: 'HTTPS',
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

function fixture() {
  const fortiConfig = {
    addresses: {
      SOURCE_NET: { name: 'SOURCE_NET', cidr: '192.0.2.0/31' },
      DESTINATION_HOST: { name: 'DESTINATION_HOST', cidr: '198.51.100.10/32' },
    },
    addressGroups: {},
    interfaces: {
      users: { name: 'users', role: 'lan', isWan: false },
      servers: { name: 'servers', role: 'lan', isWan: false },
    },
    zones: {},
    customServices: {},
  };
  const engine = buildPolicyEngineV2([
    flow('192.0.2.0', '198.51.100.10'),
    flow('192.0.2.1', '198.51.100.10'),
  ], { profile: 'recommended', fortiConfig, trafficScope: { mode: 'all' } });
  return { fortiConfig, engine, policy: engine.policies[0] };
}

test('integration exposes source and destination candidates without mutating policy or engine metrics', () => {
  const { fortiConfig, engine, policy } = fixture();
  const policyBefore = structuredClone(policy);
  const metricsBefore = structuredClone(engine.metrics);

  const response = buildPolicyRepresentationCandidates(engine, fortiConfig, policy.id);

  assert.deepEqual(policy, policyBefore);
  assert.deepEqual(engine.metrics, metricsBefore);
  assert.equal(response.policyId, policy.id);
  assert.equal(response.trafficScopeKey, engine.trafficScope.key);
  assert.ok(response.source.candidates.length > 0);
  assert.ok(response.destination.candidates.length > 0);
  for (const side of [response.source, response.destination]) {
    assert.ok(side.resolverInputHash);
    assert.equal(Object.hasOwn(side, 'decision'), false);
    assert.equal(Object.hasOwn(side, 'finalMetrics'), false);
    for (const candidate of side.candidates) {
      assert.ok(candidate.previewMetrics);
      assert.ok(Array.isArray(candidate.reasonCodes));
      assert.deepEqual(Object.keys(candidate.safetyState).sort(), ['autoApplicable', 'eligibility']);
      assert.equal(Object.hasOwn(candidate, 'representedIps'), false);
    }
  }
  assert.deepEqual(engine.metrics, {
    observedRequiredTuples: 2,
    coveredRequiredTuples: 2,
    missingRequiredTuples: 0,
    allowedTuples: 2,
    unexpectedAllowedTuples: 0,
    coverageRatio: 1,
    expansionRatio: 0,
    blockedRequiredTuples: 0,
    deployableRequiredTuples: 2,
  });
});

test('resolver input hashes change when FortiGate configuration or Traffic Scope changes', () => {
  const { fortiConfig, engine, policy } = fixture();
  const baseline = buildPolicyRepresentationCandidates(engine, fortiConfig, policy.id);
  const renamedConfig = structuredClone(fortiConfig);
  renamedConfig.addresses = {
    RENAMED_SOURCE: { name: 'RENAMED_SOURCE', cidr: '192.0.2.0/31' },
    DESTINATION_HOST: { name: 'DESTINATION_HOST', cidr: '198.51.100.10/32' },
  };
  const configChanged = buildPolicyRepresentationCandidates(engine, renamedConfig, policy.id);

  const customScopeEngine = buildPolicyEngineV2([
    flow('192.0.2.0', '198.51.100.10'),
    flow('192.0.2.1', '198.51.100.10'),
  ], {
    profile: 'recommended',
    fortiConfig,
    trafficScope: {
      mode: 'custom',
      custom: { srcClasses: ['lan'], dstClasses: ['lan'] },
    },
  });
  const scopeChanged = buildPolicyRepresentationCandidates(
    customScopeEngine,
    fortiConfig,
    customScopeEngine.policies[0].id,
  );

  assert.notEqual(baseline.source.resolverInputHash, configChanged.source.resolverInputHash);
  assert.notEqual(baseline.destination.resolverInputHash, configChanged.destination.resolverInputHash);
  assert.notEqual(baseline.source.resolverInputHash, scopeChanged.source.resolverInputHash);
  assert.notEqual(baseline.destination.resolverInputHash, scopeChanged.destination.resolverInputHash);
  assert.notEqual(baseline.trafficScopeKey, scopeChanged.trafficScopeKey);
});

test('integration projection is deterministic and rejects a non-exact V2 policy', () => {
  const { fortiConfig, engine, policy } = fixture();
  assert.deepEqual(
    buildPolicyRepresentationCandidates(engine, fortiConfig, policy.id),
    buildPolicyRepresentationCandidates(engine, fortiConfig, policy.id),
  );

  const generalizedEngine = structuredClone(engine);
  generalizedEngine.policies[0]._policyEngineV2.safeExact = false;
  assert.throws(
    () => buildPolicyRepresentationCandidates(
      generalizedEngine,
      fortiConfig,
      generalizedEngine.policies[0].id,
    ),
    /policy V2 exacte/,
  );
});
